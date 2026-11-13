import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
    Connection,
    Keypair,
    NonceAccount,
    PublicKey,
    SystemProgram,
    SYSVAR_CLOCK_PUBKEY,
    Transaction,
    TransactionInstruction,
    sendAndConfirmTransaction,
} from '@solana/web3.js';
import { spawn, type ChildProcess } from 'node:child_process';
import { access, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PROGRAM_ID } from '../../src/constants.ts';

const enabled = process.env.RUN_DURABLE_NONCE_AGAVE_E2E === '1';
const suite = enabled ? describe : describe.skip;
const RPC_URL = 'http://127.0.0.1:8899';
const TOKEN_PROGRAM_ID = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
const PROGRAM_ADDRESS = new PublicKey(PROGRAM_ID);
const NONCE_ACCOUNT_SIZE = 80;
const SOURCE_TOKEN_AMOUNT = 1_000_000n;
const NONCE_LIFETIME_SECONDS = 3_600n;

let validator: ChildProcess | undefined;
let validatorLogs = '';
let temporaryDirectory: string | undefined;
let connection: Connection | undefined;
let mint: Keypair;
let sourceTokenAccount: Keypair;
let subscriber: Keypair;
let nonceAuthority: Keypair;
let nonceAccount: Keypair;

function appendValidatorLog(chunk: Buffer): void {
    validatorLogs = (validatorLogs + chunk.toString('utf8')).slice(-20_000);
}

async function waitForValidator(child: ChildProcess, rpc: Connection): Promise<void> {
    let startupError: Error | undefined;
    child.on('error', error => {
        startupError = error;
    });

    const deadline = Date.now() + 90_000;
    while (Date.now() < deadline) {
        if (startupError) {
            throw new Error('AGAVE_TEST_VALIDATOR_SPAWN_FAILED: ' + startupError.message);
        }
        if (child.exitCode !== null) {
            throw new Error(
                'AGAVE_TEST_VALIDATOR_EXITED_EARLY: exit=' +
                    String(child.exitCode) +
                    '; logs=' +
                    validatorLogs,
            );
        }

        try {
            if ((await rpc.getHealth()) === 'ok') {
                await rpc.getLatestBlockhash('confirmed');
                return;
            }
        } catch {
            // The RPC listener can open before the genesis bank is ready.
        }

        await new Promise(resolveDelay => setTimeout(resolveDelay, 500));
    }

    throw new Error('AGAVE_TEST_VALIDATOR_START_TIMEOUT: ' + validatorLogs);
}

async function stopValidator(): Promise<void> {
    // This test uses request/response RPC only; there are no websocket subscriptions.
    connection = undefined;

    if (validator && validator.exitCode === null && validator.signalCode === null) {
        const child = validator;
        await new Promise<void>(resolveExit => {
            const killTimer = setTimeout(() => child.kill('SIGKILL'), 10_000);
            child.once('exit', () => {
                clearTimeout(killTimer);
                resolveExit();
            });
            child.kill('SIGTERM');
        });
    }
    validator = undefined;

    if (temporaryDirectory) {
        await rm(temporaryDirectory, { recursive: true, force: true });
        temporaryDirectory = undefined;
    }
}

function readNonceHash(accountData: Buffer): string {
    return NonceAccount.fromAccountData(accountData).nonce;
}

function readClockUnixTimestamp(data: Buffer): bigint {
    if (data.length < 40) {
        throw new Error('CLOCK_SYSVAR_DATA_TOO_SHORT');
    }
    return data.readBigInt64LE(32);
}

async function createSubscriberOwnedMintAndNonAtaSource(
    rpc: Connection,
): Promise<void> {
    const mintRent = await rpc.getMinimumBalanceForRentExemption(82);
    const tokenAccountRent = await rpc.getMinimumBalanceForRentExemption(165);

    const initializeMint2Data = Buffer.alloc(35);
    initializeMint2Data.writeUInt8(20, 0); // InitializeMint2
    initializeMint2Data.writeUInt8(6, 1); // Six decimal places.
    subscriber.publicKey.toBuffer().copy(initializeMint2Data, 2);
    initializeMint2Data.writeUInt8(0, 34); // No freeze authority.

    const initializeAccount3Data = Buffer.alloc(33);
    initializeAccount3Data.writeUInt8(18, 0); // InitializeAccount3
    subscriber.publicKey.toBuffer().copy(initializeAccount3Data, 1);

    const mintToData = Buffer.alloc(9);
    mintToData.writeUInt8(7, 0); // MintTo
    mintToData.writeBigUInt64LE(SOURCE_TOKEN_AMOUNT, 1);

    const transaction = new Transaction().add(
        SystemProgram.createAccount({
            fromPubkey: subscriber.publicKey,
            newAccountPubkey: mint.publicKey,
            lamports: mintRent,
            space: 82,
            programId: TOKEN_PROGRAM_ID,
        }),
        new TransactionInstruction({
            programId: TOKEN_PROGRAM_ID,
            keys: [{ pubkey: mint.publicKey, isSigner: false, isWritable: true }],
            data: initializeMint2Data,
        }),
        SystemProgram.createAccount({
            fromPubkey: subscriber.publicKey,
            newAccountPubkey: sourceTokenAccount.publicKey,
            lamports: tokenAccountRent,
            space: 165,
            programId: TOKEN_PROGRAM_ID,
        }),
        new TransactionInstruction({
            programId: TOKEN_PROGRAM_ID,
            keys: [
                { pubkey: sourceTokenAccount.publicKey, isSigner: false, isWritable: true },
                { pubkey: mint.publicKey, isSigner: false, isWritable: false },
            ],
            data: initializeAccount3Data,
        }),
        new TransactionInstruction({
            programId: TOKEN_PROGRAM_ID,
            keys: [
                { pubkey: mint.publicKey, isSigner: false, isWritable: true },
                { pubkey: sourceTokenAccount.publicKey, isSigner: false, isWritable: true },
                { pubkey: subscriber.publicKey, isSigner: true, isWritable: false },
            ],
            data: mintToData,
        }),
    );

    await sendAndConfirmTransaction(rpc, transaction, [
        subscriber,
        mint,
        sourceTokenAccount,
    ]);
}

function authorityAuthorizeInstruction(
    subscriberAddress: PublicKey,
    registry: PublicKey,
    authority: PublicKey,
    mintAddress: PublicKey,
    sourceAddress: PublicKey,
    notAfterTimestamp: bigint,
): TransactionInstruction {
    const data = Buffer.alloc(25);
    data.writeUInt8(18, 0); // AuthorizeSubscriptionAuthorityVNext
    data.writeBigUInt64LE(0n, 1); // Initial Registry generation.
    data.writeBigUInt64LE(0n, 9); // First authorization nonce.
    data.writeBigInt64LE(notAfterTimestamp, 17);

    return new TransactionInstruction({
        programId: PROGRAM_ADDRESS,
        keys: [
            { pubkey: subscriberAddress, isSigner: true, isWritable: true },
            { pubkey: registry, isSigner: false, isWritable: true },
            { pubkey: authority, isSigner: false, isWritable: true },
            { pubkey: mintAddress, isSigner: false, isWritable: false },
            { pubkey: sourceAddress, isSigner: false, isWritable: true },
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
            { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        ],
        data,
    });
}

function deliberatelyFailingTransfer(
    nonSignerSource: PublicKey,
    destination: PublicKey,
    lamports: bigint,
): TransactionInstruction {
    // SystemInstruction::Transfer = enum variant 2, followed by u64 lamports.
    // The source is funded but deliberately is not a transaction signer.
    const data = Buffer.alloc(12);
    data.writeUInt32LE(2, 0);
    data.writeBigUInt64LE(lamports, 4);

    return new TransactionInstruction({
        programId: SystemProgram.programId,
        keys: [
            { pubkey: nonSignerSource, isSigner: false, isWritable: true },
            { pubkey: destination, isSigner: false, isWritable: true },
        ],
        data,
    });
}

function buildDurableNonceTransaction(
    nonceHash: string,
    authorize: TransactionInstruction,
    failingTransfer: TransactionInstruction,
): Transaction {
    const transaction = new Transaction();
    transaction.feePayer = subscriber.publicKey;
    transaction.recentBlockhash = nonceHash;
    transaction.add(
        SystemProgram.nonceAdvance({
            noncePubkey: nonceAccount.publicKey,
            authorizedPubkey: nonceAuthority.publicKey,
        }),
        authorize,
        failingTransfer,
    );
    transaction.sign(subscriber, nonceAuthority);
    return transaction;
}

function expectSourceTokenAccountUnchanged(data: Buffer): void {
    // SPL Token Account layout: amount is at byte 64, delegate COption at byte 72,
    // and delegated_amount at byte 121. A failed outer transaction must roll
    // back the nested Token Program Approve CPI as well as VNext PDAs.
    expect(data.length).toBe(165);
    expect(data.readBigUInt64LE(64)).toBe(SOURCE_TOKEN_AMOUNT);
    expect(data.readUInt32LE(72)).toBe(0);
    expect(data.readBigUInt64LE(121)).toBe(0n);
}

suite('VNext durable nonce semantics on the real Agave test validator', () => {
    beforeAll(async () => {
        const programPath = process.env.SOLMINT_VNEXT_PROGRAM_SO;
        if (!programPath) {
            throw new Error('SOLMINT_VNEXT_PROGRAM_SO_MUST_POINT_TO_THE_EXACT_BUILT_PROGRAM');
        }
        const absoluteProgramPath = resolve(programPath);
        await access(absoluteProgramPath);

        temporaryDirectory = await mkdtemp(join(tmpdir(), 'solmint-agave-durable-nonce-'));
        mint = Keypair.generate();
        sourceTokenAccount = Keypair.generate();
        subscriber = Keypair.generate();
        nonceAuthority = Keypair.generate();
        nonceAccount = Keypair.generate();

        const ledgerPath = join(temporaryDirectory, 'ledger');
        const child = spawn(
            'solana-test-validator',
            [
                '--reset',
                '--ledger',
                ledgerPath,
                '--rpc-port',
                '8899',
                '--bpf-program',
                PROGRAM_ADDRESS.toBase58(),
                absoluteProgramPath,
            ],
            { stdio: ['ignore', 'pipe', 'pipe'] },
        );
        validator = child;
        child.stdout?.on('data', appendValidatorLog);
        child.stderr?.on('data', appendValidatorLog);

        const rpc = new Connection(RPC_URL, 'confirmed');
        connection = rpc;
        await waitForValidator(child, rpc);

        const [programInfo, tokenProgramInfo] = await Promise.all([
            rpc.getAccountInfo(PROGRAM_ADDRESS, 'confirmed'),
            rpc.getAccountInfo(TOKEN_PROGRAM_ID, 'confirmed'),
        ]);
        expect(programInfo?.executable, 'Exact VNext SBF must be executable').toBe(true);
        expect(tokenProgramInfo?.executable, 'SPL Token Program must be executable').toBe(true);
    }, 120_000);

    afterAll(async () => {
        await stopValidator();
    });

    it(
        'persists nonce advancement while rolling back successful VNext authorization and SPL Token Approve after a later failure',
        async () => {
            const rpc = connection;
            if (!rpc) throw new Error('AGAVE_TEST_VALIDATOR_NOT_STARTED');

            const subscriberAirdrop = await rpc.requestAirdrop(
                subscriber.publicKey,
                5_000_000_000,
            );
            const subscriberAirdropConfirmation = await rpc.confirmTransaction(
                subscriberAirdrop,
                'confirmed',
            );
            expect(subscriberAirdropConfirmation.value.err).toBeNull();

            const nonSignerSource = Keypair.generate();
            const nonSignerAirdrop = await rpc.requestAirdrop(nonSignerSource.publicKey, 100_000_000);
            const nonSignerAirdropConfirmation = await rpc.confirmTransaction(
                nonSignerAirdrop,
                'confirmed',
            );
            expect(nonSignerAirdropConfirmation.value.err).toBeNull();

            await createSubscriberOwnedMintAndNonAtaSource(rpc);

            const nonceRent = await rpc.getMinimumBalanceForRentExemption(NONCE_ACCOUNT_SIZE);
            const nonceCreation = SystemProgram.createNonceAccount({
                fromPubkey: subscriber.publicKey,
                noncePubkey: nonceAccount.publicKey,
                authorizedPubkey: nonceAuthority.publicKey,
                lamports: nonceRent,
            });
            await sendAndConfirmTransaction(rpc, nonceCreation, [subscriber, nonceAccount], {
                commitment: 'confirmed',
            });

            const nonceAccountInfo = await rpc.getAccountInfo(nonceAccount.publicKey, 'confirmed');
            expect(nonceAccountInfo).not.toBeNull();
            const originalNonceHash = readNonceHash(nonceAccountInfo!.data);

            const [registry] = PublicKey.findProgramAddressSync(
                [
                    Buffer.from('authorityConsent', 'utf8'),
                    subscriber.publicKey.toBuffer(),
                    mint.publicKey.toBuffer(),
                    sourceTokenAccount.publicKey.toBuffer(),
                ],
                PROGRAM_ADDRESS,
            );
            const [authority] = PublicKey.findProgramAddressSync(
                [
                    Buffer.from('SubscriptionAuthorityVNext', 'utf8'),
                    subscriber.publicKey.toBuffer(),
                    mint.publicKey.toBuffer(),
                    sourceTokenAccount.publicKey.toBuffer(),
                ],
                PROGRAM_ADDRESS,
            );

            const clockInfo = await rpc.getAccountInfo(SYSVAR_CLOCK_PUBKEY, 'confirmed');
            expect(clockInfo).not.toBeNull();
            const notAfter = readClockUnixTimestamp(clockInfo!.data) + NONCE_LIFETIME_SECONDS;
            const authorize = authorityAuthorizeInstruction(
                subscriber.publicKey,
                registry,
                authority,
                mint.publicKey,
                sourceTokenAccount.publicKey,
                notAfter,
            );

            const failedTransaction = buildDurableNonceTransaction(
                originalNonceHash,
                authorize,
                deliberatelyFailingTransfer(nonSignerSource.publicKey, subscriber.publicKey, 1n),
            );
            const signature = await rpc.sendRawTransaction(failedTransaction.serialize(), {
                skipPreflight: true,
                maxRetries: 0,
            });
            const confirmation = await rpc.confirmTransaction(signature, 'confirmed');
            expect(confirmation.value.err).not.toBeNull();

            const confirmedTransaction = await rpc.getTransaction(signature, {
                commitment: 'confirmed',
                maxSupportedTransactionVersion: 0,
            });
            expect(confirmedTransaction).not.toBeNull();
            expect(confirmedTransaction!.meta?.err).not.toBeNull();
            expect(JSON.stringify(confirmedTransaction!.meta?.err)).toMatch(/MissingRequiredSignature/);

            const executionLogs = confirmedTransaction!.meta?.logMessages ?? [];
            const tokenProgramSuccess = executionLogs.findIndex(line =>
                line.includes('Program ' + TOKEN_PROGRAM_ID.toBase58() + ' success'),
            );
            const authorityProgramSuccess = executionLogs.findIndex(line =>
                line.includes('Program ' + PROGRAM_ADDRESS.toBase58() + ' success'),
            );
            const laterSystemProgramFailure = executionLogs.findIndex(line =>
                line.includes('Program ' + SystemProgram.programId.toBase58() + ' failed'),
            );
            expect(tokenProgramSuccess).toBeGreaterThanOrEqual(0);
            expect(authorityProgramSuccess).toBeGreaterThan(tokenProgramSuccess);
            expect(laterSystemProgramFailure).toBeGreaterThan(authorityProgramSuccess);

            const nonceAfterFailureInfo = await rpc.getAccountInfo(nonceAccount.publicKey, 'confirmed');
            expect(nonceAfterFailureInfo).not.toBeNull();
            const nonceAfterFailure = readNonceHash(nonceAfterFailureInfo!.data);
            expect(nonceAfterFailure).not.toBe(originalNonceHash);

            // The successful authorization and Token Program Approve happen
            // before instruction #2 fails. Both PDAs and the token delegate
            // must be rolled back; only the durable nonce and fee persist.
            expect(await rpc.getAccountInfo(registry, 'confirmed')).toBeNull();
            expect(await rpc.getAccountInfo(authority, 'confirmed')).toBeNull();
            const sourceAfterFailure = await rpc.getAccountInfo(sourceTokenAccount.publicKey, 'confirmed');
            expect(sourceAfterFailure).not.toBeNull();
            expectSourceTokenAccountUnchanged(sourceAfterFailure!.data);

            // Change only a non-financial failure-instruction byte to obtain a
            // different transaction signature while retaining the consumed nonce.
            const staleReplay = buildDurableNonceTransaction(
                originalNonceHash,
                authorize,
                deliberatelyFailingTransfer(nonSignerSource.publicKey, subscriber.publicKey, 2n),
            );

            let staleReplayRejected = false;
            let staleReplayError = '';
            try {
                const replaySignature = await rpc.sendRawTransaction(staleReplay.serialize(), {
                    skipPreflight: false,
                    maxRetries: 0,
                });
                const replayConfirmation = await rpc.confirmTransaction(
                    replaySignature,
                    'confirmed',
                );
                staleReplayRejected = replayConfirmation.value.err !== null;
                if (staleReplayRejected) {
                    const replayTransaction = await rpc.getTransaction(replaySignature, {
                        commitment: 'confirmed',
                        maxSupportedTransactionVersion: 0,
                    });
                    staleReplayError = JSON.stringify(replayTransaction?.meta?.err ?? 'replay failed');
                }
            } catch (error) {
                staleReplayRejected = true;
                staleReplayError = error instanceof Error ? error.message : String(error);
            }

            expect(staleReplayRejected).toBe(true);
            expect(staleReplayError).toMatch(/blockhash|nonce/i);
            const nonceAfterReplayInfo = await rpc.getAccountInfo(nonceAccount.publicKey, 'confirmed');
            expect(nonceAfterReplayInfo).not.toBeNull();
            expect(readNonceHash(nonceAfterReplayInfo!.data)).toBe(nonceAfterFailure);
            expect(await rpc.getAccountInfo(registry, 'confirmed')).toBeNull();
            expect(await rpc.getAccountInfo(authority, 'confirmed')).toBeNull();
            const sourceAfterReplay = await rpc.getAccountInfo(sourceTokenAccount.publicKey, 'confirmed');
            expect(sourceAfterReplay).not.toBeNull();
            expectSourceTokenAccountUnchanged(sourceAfterReplay!.data);
        },
        240_000,
    );
});
