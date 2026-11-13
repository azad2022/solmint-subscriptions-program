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
} from '@solana/web3.js';
import { spawn, type ChildProcess } from 'node:child_process';
import { access, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PROGRAM_ID } from '../../src/constants.ts';

const enabled = process.env.RUN_DURABLE_NONCE_AGAVE_E2E === '1';
const suite = enabled ? describe : describe.skip;
const RPC_URL = 'http://127.0.0.1:8899';
const TOKEN_PROGRAM_ID = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
const PROGRAM_ADDRESS = new PublicKey(PROGRAM_ID);
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
            const health = await rpc.getHealth();
            if (health === 'ok') {
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
    if (connection) {
        try {
            await connection.close();
        } catch {
            // The validator process is still terminated below.
        }
        connection = undefined;
    }

    if (validator && validator.exitCode === null) {
        const child = validator;
        child.kill('SIGTERM');
        await Promise.race([
            new Promise<void>(resolveExit => child.once('exit', () => resolveExit())),
            new Promise<void>(resolveTimeout => setTimeout(resolveTimeout, 10_000)),
        ]);
        if (child.exitCode === null) {
            child.kill('SIGKILL');
            await new Promise<void>(resolveExit => child.once('exit', () => resolveExit()));
        }
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

function authorityRevokeInstruction(
    subscriberAddress: PublicKey,
    registry: PublicKey,
    authority: PublicKey,
    mintAddress: PublicKey,
    sourceAddress: PublicKey,
    notAfterTimestamp: bigint,
): TransactionInstruction {
    const data = Buffer.alloc(25);
    data.writeUInt8(19, 0); // RevokeSubscriptionAuthorityVNext
    data.writeBigUInt64LE(1n, 1); // Pre-empt the one pending generation-zero authorization.
    data.writeBigUInt64LE(0n, 9); // First revoke nonce.
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
    revoke: TransactionInstruction,
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
        revoke,
        failingTransfer,
    );
    transaction.sign(subscriber, nonceAuthority);
    return transaction;
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

        // A minimal initialized SPL Mint account fixture. The Revoke tombstone
        // path validates its owner, exact 82-byte layout and initialized flag,
        // but does not invoke the Token Program because the source account and
        // VNext Authority do not yet exist.
        const mintData = Buffer.alloc(82);
        mintData.writeUInt8(6, 44);
        mintData.writeUInt8(1, 45);
        const mintFixture = {
            pubkey: mint.publicKey.toBase58(),
            account: {
                lamports: 1_000_000_000,
                data: [mintData.toString('base64'), 'base64'],
                owner: TOKEN_PROGRAM_ID.toBase58(),
                executable: false,
                rentEpoch: 0,
            },
            space: 82,
        };
        const mintFixturePath = join(temporaryDirectory, 'initialized-spl-mint.json');
        await writeFile(mintFixturePath, JSON.stringify(mintFixture), 'utf8');

        const ledgerPath = join(temporaryDirectory, 'ledger');
        validator = spawn(
            'solana-test-validator',
            [
                '--reset',
                '--quiet',
                '--ledger',
                ledgerPath,
                '--rpc-port',
                '8899',
                '--bpf-program',
                PROGRAM_ADDRESS.toBase58(),
                absoluteProgramPath,
                '--account',
                mint.publicKey.toBase58(),
                mintFixturePath,
            ],
            { stdio: ['ignore', 'pipe', 'pipe'] },
        );
        validator.stdout?.on('data', appendValidatorLog);
        validator.stderr?.on('data', appendValidatorLog);

        connection = new Connection(RPC_URL, 'confirmed');
        await waitForValidator(validator, connection);
    }, 120_000);

    afterAll(async () => {
        await stopValidator();
    });

    it(
        'persists nonce advancement, rolls back authority state after a later instruction fails, and rejects a fresh-signature replay',
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

            const nonceRent = await rpc.getMinimumBalanceForRentExemption(NonceAccount.fromAccountData.length ?? 80);
            const nonceCreation = SystemProgram.createNonceAccount({
                fromPubkey: subscriber.publicKey,
                noncePubkey: nonceAccount.publicKey,
                authorizedPubkey: nonceAuthority.publicKey,
                lamports: nonceRent,
            });
            await import('@solana/web3.js').then(async ({ sendAndConfirmTransaction }) => {
                await sendAndConfirmTransaction(rpc, nonceCreation, [subscriber, nonceAccount], {
                    commitment: 'confirmed',
                });
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
            const revoke = authorityRevokeInstruction(
                subscriber.publicKey,
                registry,
                authority,
                mint.publicKey,
                sourceTokenAccount.publicKey,
                notAfter,
            );

            const failedTransaction = buildDurableNonceTransaction(
                originalNonceHash,
                revoke,
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

            const executionLogs = confirmedTransaction!.meta?.logMessages ?? [];
            const authorityProgramSuccess = executionLogs.findIndex(line =>
                line.includes('Program ' + PROGRAM_ADDRESS.toBase58() + ' success'),
            );
            const laterSystemProgramFailure = executionLogs.findIndex(line =>
                line.includes('Program ' + SystemProgram.programId.toBase58() + ' failed'),
            );
            expect(authorityProgramSuccess).toBeGreaterThanOrEqual(0);
            expect(laterSystemProgramFailure).toBeGreaterThan(authorityProgramSuccess);

            const nonceAfterFailureInfo = await rpc.getAccountInfo(nonceAccount.publicKey, 'confirmed');
            expect(nonceAfterFailureInfo).not.toBeNull();
            const nonceAfterFailure = readNonceHash(nonceAfterFailureInfo!.data);
            expect(nonceAfterFailure).not.toBe(originalNonceHash);

            // The failed transaction's Authority Registry allocation and
            // lifecycle change must be rolled back by the validator.
            expect(await rpc.getAccountInfo(registry, 'confirmed')).toBeNull();
            expect(await rpc.getAccountInfo(authority, 'confirmed')).toBeNull();

            // Change a non-financial instruction byte to obtain a new transaction
            // signature while retaining the consumed nonce hash. A duplicate
            // signature rejection alone would not prove nonce consumption.
            const staleReplay = buildDurableNonceTransaction(
                originalNonceHash,
                revoke,
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
        },
        240_000,
    );
});
