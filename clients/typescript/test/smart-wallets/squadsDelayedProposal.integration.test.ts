import { AccountRole, type Address, type Instruction } from '@solana/kit';
import {
    Connection,
    Keypair,
    LAMPORTS_PER_SOL,
    PublicKey,
    sendAndConfirmTransaction,
    SystemProgram,
    SYSVAR_CLOCK_PUBKEY,
    Transaction,
    TransactionInstruction,
} from '@solana/web3.js';
import * as squads from '@sqds/multisig';
import { beforeAll, describe, expect, it } from 'vitest';
import { PROGRAM_ID } from '../../src/constants.ts';
import { createSquadsWallet } from './squadsWallet.ts';

const runIntegration = process.env.RUN_SQUADS_DELAYED_PROPOSAL_E2E === '1';
const suite = runIntegration ? describe : describe.skip;
const RPC_URL = process.env.SOLANA_RPC_URL ?? 'http://127.0.0.1:8899';
const TOKEN_PROGRAM_ID = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
const SUBSCRIPTIONS_PROGRAM_ID = new PublicKey(PROGRAM_ID);
const INITIAL_TOKEN_AMOUNT = 1_000_000n;

function toKitInstruction(instruction: TransactionInstruction): Instruction {
    return {
        programAddress: instruction.programId.toBase58() as Address,
        accounts: instruction.keys.map(meta => ({
            address: meta.pubkey.toBase58() as Address,
            role: meta.isSigner
                ? meta.isWritable
                    ? AccountRole.WRITABLE_SIGNER
                    : AccountRole.READONLY_SIGNER
                : meta.isWritable
                  ? AccountRole.WRITABLE
                  : AccountRole.READONLY,
        })),
        data: new Uint8Array(instruction.data),
    };
}

function encodeAuthorityAction(
    discriminator: number,
    expectedGeneration: bigint,
    expectedNonce: bigint,
    notAfterTs: bigint,
): Buffer {
    const data = Buffer.alloc(25);
    data.writeUInt8(discriminator, 0);
    data.writeBigUInt64LE(expectedGeneration, 1);
    data.writeBigUInt64LE(expectedNonce, 9);
    data.writeBigInt64LE(notAfterTs, 17);
    return data;
}

async function airdrop(connection: Connection, address: PublicKey, lamports: number): Promise<void> {
    const signature = await connection.requestAirdrop(address, lamports);
    const confirmation = await connection.confirmTransaction(signature, 'confirmed');
    if (confirmation.value.err) {
        throw new Error(`LOCAL_SURFPOOL_AIRDROP_FAILED: ${JSON.stringify(confirmation.value.err)}`);
    }
}

async function readClockTimestamp(connection: Connection): Promise<bigint> {
    const clock = await connection.getAccountInfo(SYSVAR_CLOCK_PUBKEY, 'confirmed');
    if (!clock || clock.data.length < 40) {
        throw new Error('SURFPOOL_CLOCK_SYSVAR_UNAVAILABLE');
    }
    return clock.data.readBigInt64LE(32);
}

async function advanceClockPast(
    connection: Connection,
    feePayer: Keypair,
    recipient: PublicKey,
    deadline: bigint,
): Promise<bigint> {
    const stopAt = Date.now() + 30_000;
    let current = await readClockTimestamp(connection);

    while (current <= deadline && Date.now() < stopAt) {
        const transaction = new Transaction().add(
            SystemProgram.transfer({
                fromPubkey: feePayer.publicKey,
                toPubkey: recipient,
                lamports: 1,
            }),
        );
        await sendAndConfirmTransaction(connection, transaction, [feePayer]);
        current = await readClockTimestamp(connection);
    }

    if (current <= deadline) {
        throw new Error(
            `SURFPOOL_CLOCK_DID_NOT_ADVANCE_PAST_DEADLINE: current=${current}; deadline=${deadline}`,
        );
    }
    return current;
}

async function createMintAndVaultOwnedSourceAccount(
    connection: Connection,
    feePayer: Keypair,
    vault: PublicKey,
): Promise<{ mint: Keypair; source: Keypair }> {
    const mint = Keypair.generate();
    const source = Keypair.generate();
    const mintRent = await connection.getMinimumBalanceForRentExemption(82);
    const tokenAccountRent = await connection.getMinimumBalanceForRentExemption(165);

    const initializeMintData = Buffer.alloc(35);
    initializeMintData.writeUInt8(20, 0); // InitializeMint2 (no Rent sysvar account)
    initializeMintData.writeUInt8(0, 1); // decimals
    feePayer.publicKey.toBuffer().copy(initializeMintData, 2);
    initializeMintData.writeUInt8(0, 34); // no freeze authority

    const initializeAccount3Data = Buffer.alloc(33);
    initializeAccount3Data.writeUInt8(18, 0); // InitializeAccount3
    vault.toBuffer().copy(initializeAccount3Data, 1);

    const mintToData = Buffer.alloc(9);
    mintToData.writeUInt8(7, 0); // MintTo
    mintToData.writeBigUInt64LE(INITIAL_TOKEN_AMOUNT, 1);

    const transaction = new Transaction().add(
        SystemProgram.createAccount({
            fromPubkey: feePayer.publicKey,
            newAccountPubkey: mint.publicKey,
            lamports: mintRent,
            space: 82,
            programId: TOKEN_PROGRAM_ID,
        }),
        new TransactionInstruction({
            programId: TOKEN_PROGRAM_ID,
            keys: [{ pubkey: mint.publicKey, isSigner: false, isWritable: true }],
            data: initializeMintData,
        }),
        SystemProgram.createAccount({
            fromPubkey: feePayer.publicKey,
            newAccountPubkey: source.publicKey,
            lamports: tokenAccountRent,
            space: 165,
            programId: TOKEN_PROGRAM_ID,
        }),
        new TransactionInstruction({
            programId: TOKEN_PROGRAM_ID,
            keys: [
                { pubkey: source.publicKey, isSigner: false, isWritable: true },
                { pubkey: mint.publicKey, isSigner: false, isWritable: false },
            ],
            data: initializeAccount3Data,
        }),
        new TransactionInstruction({
            programId: TOKEN_PROGRAM_ID,
            keys: [
                { pubkey: mint.publicKey, isSigner: false, isWritable: true },
                { pubkey: source.publicKey, isSigner: false, isWritable: true },
                { pubkey: feePayer.publicKey, isSigner: true, isWritable: false },
            ],
            data: mintToData,
        }),
    );

    await sendAndConfirmTransaction(connection, transaction, [feePayer, mint, source]);
    return { mint, source };
}

suite('Squads v4 delayed proposal against VNext authority registry', () => {
    const connection = new Connection(RPC_URL, 'confirmed');

    beforeAll(async () => {
        const [subscriptionsInfo, squadsInfo, tokenInfo] = await Promise.all([
            connection.getAccountInfo(SUBSCRIPTIONS_PROGRAM_ID, 'confirmed'),
            connection.getAccountInfo(squads.PROGRAM_ID, 'confirmed'),
            connection.getAccountInfo(TOKEN_PROGRAM_ID, 'confirmed'),
        ]);

        expect(subscriptionsInfo?.executable, 'VNext subscriptions program must be deployed in local Surfpool').toBe(true);
        expect(squadsInfo?.executable, 'Squads v4 program must be present in the Surfpool fork').toBe(true);
        expect(tokenInfo?.executable, 'SPL Token program must be available').toBe(true);
    }, 120_000);

    it(
        'executes a revocation before an approved delayed authorization and rejects the stale proposal atomically',
        async () => {
            const feePayer = Keypair.generate();
            const members = [Keypair.generate(), Keypair.generate(), Keypair.generate()];
            await airdrop(connection, feePayer.publicKey, 10 * LAMPORTS_PER_SOL);
            for (const member of members) {
                await airdrop(connection, member.publicKey, LAMPORTS_PER_SOL);
            }

            const wallet = await createSquadsWallet({
                connection,
                feePayer,
                members,
                approvalsRequired: 2,
                vaultIndex: 0,
            });
            const vault = new PublicKey(wallet.address);
            await airdrop(connection, vault, 5 * LAMPORTS_PER_SOL);

            const { mint, source } = await createMintAndVaultOwnedSourceAccount(
                connection,
                feePayer,
                vault,
            );

            // This is intentionally a newly created non-ATA token account owned by
            // the Squads Vault PDA; it is the exact source identity in the VNext registry.
            const [registryPda] = PublicKey.findProgramAddressSync(
                [
                    Buffer.from('authorityConsent'),
                    vault.toBuffer(),
                    mint.publicKey.toBuffer(),
                    source.publicKey.toBuffer(),
                ],
                SUBSCRIPTIONS_PROGRAM_ID,
            );
            const [authorityPda] = PublicKey.findProgramAddressSync(
                [
                    Buffer.from('SubscriptionAuthorityVNext'),
                    vault.toBuffer(),
                    mint.publicKey.toBuffer(),
                    source.publicKey.toBuffer(),
                ],
                SUBSCRIPTIONS_PROGRAM_ID,
            );

            const now = await readClockTimestamp(connection);
            const notAfterTs = now + 3_600n;
            const commonAccounts = [
                { pubkey: vault, isSigner: true, isWritable: true },
                { pubkey: registryPda, isSigner: false, isWritable: true },
                { pubkey: authorityPda, isSigner: false, isWritable: true },
                { pubkey: mint.publicKey, isSigner: false, isWritable: false },
                { pubkey: source.publicKey, isSigner: false, isWritable: true },
                { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
                { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
            ];

            const authorizeInstruction = new TransactionInstruction({
                programId: SUBSCRIPTIONS_PROGRAM_ID,
                keys: commonAccounts,
                data: encodeAuthorityAction(18, 0n, 0n, notAfterTs),
            });
            const revokeInstruction = new TransactionInstruction({
                programId: SUBSCRIPTIONS_PROGRAM_ID,
                keys: commonAccounts,
                data: encodeAuthorityAction(19, 1n, 0n, notAfterTs),
            });

            // Retain an approved generation-0 authorization without executing it.
            const delayedAuthorize = await wallet.stageInstructions([
                toKitInstruction(authorizeInstruction),
            ]);
            await wallet.approveProposal(delayedAuthorize);

            const [delayedAuthorizeProposalPda] = squads.getProposalPda({
                multisigPda: new PublicKey(delayedAuthorize.multisigPda),
                transactionIndex: delayedAuthorize.transactionIndex,
            });
            const approvedBeforeRevocation = await squads.accounts.Proposal.fromAccountAddress(
                connection,
                delayedAuthorizeProposalPda,
            );
            expect(approvedBeforeRevocation.status.__kind).toBe('Approved');

            // A separate approved transaction invalidates the still-pending
            // generation-1 authorization by advancing the Registry to generation 2.
            const revokeProposal = await wallet.stageInstructions([toKitInstruction(revokeInstruction)]);
            await wallet.approveProposal(revokeProposal);
            const revokeSignature = await wallet.executeProposal(revokeProposal);
            const revokeConfirmation = await connection.confirmTransaction(
                revokeSignature,
                'confirmed',
            );
            expect(revokeConfirmation.value.err).toBeNull();

            const [revokeProposalPda] = squads.getProposalPda({
                multisigPda: new PublicKey(revokeProposal.multisigPda),
                transactionIndex: revokeProposal.transactionIndex,
            });
            const executedRevokeProposal = await squads.accounts.Proposal.fromAccountAddress(
                connection,
                revokeProposalPda,
            );
            expect(executedRevokeProposal.status.__kind).toBe('Executed');

            // Skip preflight so the stale inner instruction is submitted to the
            // local validator and its failed transaction metadata/logs are inspectable.
            const staleSignature = await wallet.executeProposal(
                delayedAuthorize,
                members[0],
                { skipPreflight: true },
            );
            const staleConfirmation = await connection.confirmTransaction(
                staleSignature,
                'confirmed',
            );
            expect(staleConfirmation.value.err).not.toBeNull();

            const failedTransaction = await connection.getTransaction(staleSignature, {
                commitment: 'confirmed',
                maxSupportedTransactionVersion: 0,
            });
            expect(failedTransaction?.meta?.err).not.toBeNull();
            expect(JSON.stringify(failedTransaction?.meta?.err)).toContain('141');
            expect((failedTransaction?.meta?.logMessages ?? []).join('\n')).toContain(
                'custom program error: 0x8d',
            );

            // The failed execution must not consume or mutate the approved proposal.
            const stillApproved = await squads.accounts.Proposal.fromAccountAddress(
                connection,
                delayedAuthorizeProposalPda,
            );
            expect(stillApproved.status.__kind).toBe('Approved');
            const [delayedVaultTransactionPda] = squads.getTransactionPda({
                multisigPda: new PublicKey(delayedAuthorize.multisigPda),
                index: delayedAuthorize.transactionIndex,
            });
            expect(await connection.getAccountInfo(delayedVaultTransactionPda, 'confirmed')).not.toBeNull();

            const registryInfo = await connection.getAccountInfo(registryPda, 'confirmed');
            expect(registryInfo).not.toBeNull();
            const registryData = registryInfo!.data;
            expect(registryData.length).toBe(188);
            expect(registryData.readUInt8(2)).toBe(0); // revoked
            expect(registryData.readBigUInt64LE(164)).toBe(2n);
            expect(registryData.readBigUInt64LE(172)).toBe(0n);
            expect(registryData.readBigUInt64LE(180)).toBe(1n);
            expect(new PublicKey(registryData.subarray(132, 164)).equals(vault)).toBe(true);

            const authorityInfo = await connection.getAccountInfo(authorityPda, 'confirmed');
            expect(
                authorityInfo === null ||
                    (authorityInfo.lamports === 0 && authorityInfo.data.length === 0),
            ).toBe(true);

            const tokenAccountInfo = await connection.getAccountInfo(source.publicKey, 'confirmed');
            expect(tokenAccountInfo).not.toBeNull();
            expect(new PublicKey(tokenAccountInfo!.data.subarray(32, 64)).equals(vault)).toBe(true);
            expect(tokenAccountInfo!.data.readBigUInt64LE(64)).toBe(INITIAL_TOKEN_AMOUNT);
            expect(tokenAccountInfo!.data.readUInt32LE(72)).toBe(0); // no delegate
        },
        240_000,
    );

    it(
        'rejects an approved delayed authorization after its on-chain deadline expires',
        async () => {
            const feePayer = Keypair.generate();
            const members = [Keypair.generate(), Keypair.generate(), Keypair.generate()];
            await airdrop(connection, feePayer.publicKey, 10 * LAMPORTS_PER_SOL);
            for (const member of members) {
                await airdrop(connection, member.publicKey, LAMPORTS_PER_SOL);
            }

            const wallet = await createSquadsWallet({
                connection,
                feePayer,
                members,
                approvalsRequired: 2,
                vaultIndex: 0,
            });
            const vault = new PublicKey(wallet.address);
            await airdrop(connection, vault, 5 * LAMPORTS_PER_SOL);

            const { mint, source } = await createMintAndVaultOwnedSourceAccount(
                connection,
                feePayer,
                vault,
            );
            const [registryPda] = PublicKey.findProgramAddressSync(
                [
                    Buffer.from('authorityConsent'),
                    vault.toBuffer(),
                    mint.publicKey.toBuffer(),
                    source.publicKey.toBuffer(),
                ],
                SUBSCRIPTIONS_PROGRAM_ID,
            );
            const [authorityPda] = PublicKey.findProgramAddressSync(
                [
                    Buffer.from('SubscriptionAuthorityVNext'),
                    vault.toBuffer(),
                    mint.publicKey.toBuffer(),
                    source.publicKey.toBuffer(),
                ],
                SUBSCRIPTIONS_PROGRAM_ID,
            );

            const now = await readClockTimestamp(connection);
            const deadline = now + 1n;
            const authorizeInstruction = new TransactionInstruction({
                programId: SUBSCRIPTIONS_PROGRAM_ID,
                keys: [
                    { pubkey: vault, isSigner: true, isWritable: true },
                    { pubkey: registryPda, isSigner: false, isWritable: true },
                    { pubkey: authorityPda, isSigner: false, isWritable: true },
                    { pubkey: mint.publicKey, isSigner: false, isWritable: false },
                    { pubkey: source.publicKey, isSigner: false, isWritable: true },
                    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
                    { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
                ],
                data: encodeAuthorityAction(18, 0n, 0n, deadline),
            });

            const delayedAuthorize = await wallet.stageInstructions([
                toKitInstruction(authorizeInstruction),
            ]);
            await wallet.approveProposal(delayedAuthorize);

            const current = await advanceClockPast(connection, feePayer, members[0].publicKey, deadline);
            expect(current).toBeGreaterThan(deadline);

            const staleSignature = await wallet.executeProposal(
                delayedAuthorize,
                members[0],
                { skipPreflight: true },
            );
            const confirmation = await connection.confirmTransaction(
                staleSignature,
                'confirmed',
            );
            expect(confirmation.value.err).not.toBeNull();

            const failedTransaction = await connection.getTransaction(staleSignature, {
                commitment: 'confirmed',
                maxSupportedTransactionVersion: 0,
            });
            expect(failedTransaction?.meta?.err).not.toBeNull();
            expect(JSON.stringify(failedTransaction?.meta?.err)).toContain('143');
            expect((failedTransaction?.meta?.logMessages ?? []).join('\n')).toContain(
                'custom program error: 0x8f',
            );

            const [proposalPda] = squads.getProposalPda({
                multisigPda: new PublicKey(delayedAuthorize.multisigPda),
                transactionIndex: delayedAuthorize.transactionIndex,
            });
            const stillApproved = await squads.accounts.Proposal.fromAccountAddress(
                connection,
                proposalPda,
            );
            expect(stillApproved.status.__kind).toBe('Approved');

            expect(await connection.getAccountInfo(registryPda, 'confirmed')).toBeNull();
            expect(await connection.getAccountInfo(authorityPda, 'confirmed')).toBeNull();

            const tokenAccountInfo = await connection.getAccountInfo(source.publicKey, 'confirmed');
            expect(tokenAccountInfo).not.toBeNull();
            expect(tokenAccountInfo!.data.readBigUInt64LE(64)).toBe(INITIAL_TOKEN_AMOUNT);
            expect(tokenAccountInfo!.data.readUInt32LE(72)).toBe(0);
        },
        240_000,
    );
});
