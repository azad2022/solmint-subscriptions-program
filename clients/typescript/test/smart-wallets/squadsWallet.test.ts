import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Connection, Keypair } from '@solana/web3.js';
import * as squads from '@sqds/multisig';
import { SquadsSmartWallet, type StagedSquadsProposal } from './squadsWallet.ts';

const rpcMocks = vi.hoisted(() => ({
    vaultTransactionCreate: vi.fn(),
    proposalCreate: vi.fn(),
    proposalApprove: vi.fn(),
    vaultTransactionExecute: vi.fn(),
}));

vi.mock('@sqds/multisig', async importOriginal => {
    const actual = await importOriginal<typeof import('@sqds/multisig')>();
    return {
        ...actual,
        rpc: {
            ...actual.rpc,
            ...rpcMocks,
        },
    };
});

describe('SquadsSmartWallet staged proposal lifecycle', () => {
    const feePayer = Keypair.generate();
    const members = [Keypair.generate(), Keypair.generate(), Keypair.generate()];
    const multisigPda = Keypair.generate().publicKey;
    const blockhash = Keypair.generate().publicKey.toBase58();
    const connection = {
        getLatestBlockhash: vi.fn().mockResolvedValue({ blockhash }),
        confirmTransaction: vi.fn().mockResolvedValue({ value: { err: null } }),
    } as unknown as Connection;

    let multisigRead: ReturnType<typeof vi.spyOn>;
    let wallet: SquadsSmartWallet;

    beforeEach(() => {
        rpcMocks.vaultTransactionCreate.mockResolvedValue('vault-create-signature');
        rpcMocks.proposalCreate.mockResolvedValue('proposal-create-signature');
        rpcMocks.proposalApprove.mockResolvedValue('proposal-approve-signature');
        rpcMocks.vaultTransactionExecute.mockResolvedValue('vault-execute-signature');

        multisigRead = vi
            .spyOn(squads.accounts.Multisig, 'fromAccountAddress')
            .mockResolvedValue({ transactionIndex: 41n } as Awaited<
                ReturnType<typeof squads.accounts.Multisig.fromAccountAddress>
            >);

        wallet = new SquadsSmartWallet({
            connection,
            feePayer,
            members,
            approvalsRequired: 2,
            multisigPda,
            vaultIndex: 4,
            programId: squads.PROGRAM_ID,
        });
    });

    afterEach(() => {
        vi.restoreAllMocks();
        vi.clearAllMocks();
    });

    it('stages a real indexed VaultTransaction and Active Proposal without voting or execution', async () => {
        const staged = await wallet.stageInstructions([]);

        expect(multisigRead).toHaveBeenCalledOnce();
        expect(multisigRead).toHaveBeenCalledWith(connection, multisigPda);
        expect(rpcMocks.vaultTransactionCreate).toHaveBeenCalledOnce();
        expect(rpcMocks.proposalCreate).toHaveBeenCalledOnce();
        expect(rpcMocks.vaultTransactionCreate.mock.invocationCallOrder[0]).toBeLessThan(
            rpcMocks.proposalCreate.mock.invocationCallOrder[0],
        );
        expect(rpcMocks.vaultTransactionCreate.mock.calls[0][0]).toMatchObject({
            transactionIndex: 42n,
            creator: members[0].publicKey,
            rentPayer: feePayer.publicKey,
            signers: [members[0]],
            vaultIndex: 4,
            ephemeralSigners: 0,
            programId: squads.PROGRAM_ID,
        });
        expect(rpcMocks.proposalCreate.mock.calls[0][0]).toMatchObject({
            transactionIndex: 42n,
            creator: members[0],
            multisigPda,
            isDraft: false,
        });
        expect(connection.confirmTransaction).toHaveBeenCalledTimes(2);
        expect(connection.confirmTransaction.mock.calls.map(([signature]) => signature)).toEqual([
            'vault-create-signature',
            'proposal-create-signature',
        ]);
        expect(rpcMocks.proposalApprove).not.toHaveBeenCalled();
        expect(rpcMocks.vaultTransactionExecute).not.toHaveBeenCalled();
        expect(staged).toEqual({
            multisigPda: multisigPda.toBase58(),
            transactionIndex: 42n,
        });
        expect(Object.isFrozen(staged)).toBe(true);
    });

    it('approves and executes only when the caller explicitly invokes those phases', async () => {
        const staged: StagedSquadsProposal = {
            multisigPda: multisigPda.toBase58(),
            transactionIndex: 42n,
        };

        await wallet.approveProposal(staged);
        expect(rpcMocks.proposalApprove).toHaveBeenCalledTimes(2);
        expect(connection.confirmTransaction).toHaveBeenCalledTimes(2);
        expect(rpcMocks.proposalApprove.mock.calls.map(([args]) => args.member)).toEqual(
            members.slice(0, 2),
        );
        expect(rpcMocks.vaultTransactionExecute).not.toHaveBeenCalled();

        const sendOptions = { skipPreflight: true };
        await expect(wallet.executeProposal(staged, members[1], sendOptions)).resolves.toBe('vault-execute-signature');
        expect(rpcMocks.vaultTransactionExecute).toHaveBeenCalledOnce();
        expect(rpcMocks.vaultTransactionExecute.mock.calls[0][0].sendOptions).toEqual(sendOptions);
        expect(rpcMocks.vaultTransactionExecute.mock.calls[0][0]).toMatchObject({
            transactionIndex: 42n,
            member: members[1].publicKey,
            signers: [members[1]],
        });
    });

    it('rejects a proposal handle belonging to another multisig', async () => {
        const otherWallet = new SquadsSmartWallet({
            connection,
            feePayer,
            members,
            approvalsRequired: 2,
            multisigPda: Keypair.generate().publicKey,
            vaultIndex: 0,
            programId: squads.PROGRAM_ID,
        });
        const staged: StagedSquadsProposal = {
            multisigPda: multisigPda.toBase58(),
            transactionIndex: 42n,
        };

        await expect(otherWallet.approveProposal(staged)).rejects.toThrow(
            'SQUADS_PROPOSAL_MULTISIG_MISMATCH',
        );
        await expect(otherWallet.executeProposal(staged)).rejects.toThrow(
            'SQUADS_PROPOSAL_MULTISIG_MISMATCH',
        );
        expect(rpcMocks.proposalApprove).not.toHaveBeenCalled();
        expect(rpcMocks.vaultTransactionExecute).not.toHaveBeenCalled();
    });

    it('rejects duplicate approvers before sending a second vote', async () => {
        const staged: StagedSquadsProposal = {
            multisigPda: multisigPda.toBase58(),
            transactionIndex: 42n,
        };

        await expect(wallet.approveProposal(staged, [members[0], members[0]])).rejects.toThrow(
            'SQUADS_PROPOSAL_DUPLICATE_APPROVER',
        );
        expect(rpcMocks.proposalApprove).toHaveBeenCalledOnce();
        expect(connection.confirmTransaction).toHaveBeenCalledOnce();
    });

    it('does not pass the creator twice when creator is also the fee payer', async () => {
        const samePayerWallet = new SquadsSmartWallet({
            connection,
            feePayer: members[0],
            members,
            approvalsRequired: 2,
            multisigPda,
            vaultIndex: 4,
            programId: squads.PROGRAM_ID,
        });

        await samePayerWallet.stageInstructions([]);

        expect(rpcMocks.vaultTransactionCreate.mock.calls[0][0]).toMatchObject({
            creator: members[0].publicKey,
            rentPayer: members[0].publicKey,
            signers: [],
        });
    });

    it('preserves immediate-send behavior as stage, approve, then execute', async () => {
        await expect(wallet.sendInstructions([])).resolves.toBe('vault-execute-signature');

        expect(rpcMocks.vaultTransactionCreate).toHaveBeenCalledOnce();
        expect(rpcMocks.proposalCreate).toHaveBeenCalledOnce();
        expect(rpcMocks.proposalApprove).toHaveBeenCalledTimes(2);
        expect(rpcMocks.vaultTransactionExecute).toHaveBeenCalledOnce();
        expect(rpcMocks.vaultTransactionCreate.mock.invocationCallOrder[0]).toBeLessThan(
            rpcMocks.proposalCreate.mock.invocationCallOrder[0],
        );
        expect(rpcMocks.proposalCreate.mock.invocationCallOrder[0]).toBeLessThan(
            rpcMocks.proposalApprove.mock.invocationCallOrder[0],
        );
        expect(rpcMocks.proposalApprove.mock.invocationCallOrder[1]).toBeLessThan(
            rpcMocks.vaultTransactionExecute.mock.invocationCallOrder[0],
        );
        expect(connection.confirmTransaction).toHaveBeenCalledTimes(5);
        expect(connection.confirmTransaction.mock.calls[4][0]).toBe('vault-execute-signature');
    });
});
