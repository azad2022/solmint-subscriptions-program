import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Connection, Keypair } from '@solana/web3.js';
import * as squads from '@sqds/multisig';
import { SquadsSmartWallet, type StagedSquadsProposal } from './squadsWallet.ts';

describe('SquadsSmartWallet staged proposal lifecycle', () => {
    const feePayer = Keypair.generate();
    const members = [Keypair.generate(), Keypair.generate(), Keypair.generate()];
    const multisigPda = Keypair.generate().publicKey;
    const blockhash = Keypair.generate().publicKey.toBase58();
    const connection = {
        getLatestBlockhash: vi.fn().mockResolvedValue({ blockhash }),
    } as unknown as Connection;

    let multisigRead: ReturnType<typeof vi.spyOn>;
    let vaultCreate: ReturnType<typeof vi.spyOn>;
    let proposalCreate: ReturnType<typeof vi.spyOn>;
    let proposalApprove: ReturnType<typeof vi.spyOn>;
    let vaultExecute: ReturnType<typeof vi.spyOn>;
    let wallet: SquadsSmartWallet;

    beforeEach(() => {
        multisigRead = vi
            .spyOn(squads.accounts.Multisig, 'fromAccountAddress')
            .mockResolvedValue({ transactionIndex: 41n } as Awaited<
                ReturnType<typeof squads.accounts.Multisig.fromAccountAddress>
            >);
        vaultCreate = vi.spyOn(squads.rpc, 'vaultTransactionCreate').mockResolvedValue(
            'vault-create-signature',
        );
        proposalCreate = vi.spyOn(squads.rpc, 'proposalCreate').mockResolvedValue(
            'proposal-create-signature',
        );
        proposalApprove = vi.spyOn(squads.rpc, 'proposalApprove').mockResolvedValue(
            'proposal-approve-signature',
        );
        vaultExecute = vi.spyOn(squads.rpc, 'vaultTransactionExecute').mockResolvedValue(
            'vault-execute-signature',
        );

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
        expect(vaultCreate).toHaveBeenCalledOnce();
        expect(proposalCreate).toHaveBeenCalledOnce();
        expect(vaultCreate.mock.invocationCallOrder[0]).toBeLessThan(
            proposalCreate.mock.invocationCallOrder[0],
        );
        expect(vaultCreate.mock.calls[0][0]).toMatchObject({
            transactionIndex: 42n,
            creator: members[0].publicKey,
            rentPayer: feePayer.publicKey,
            signers: [members[0]],
            vaultIndex: 4,
            ephemeralSigners: 0,
            programId: squads.PROGRAM_ID,
        });
        expect(proposalCreate.mock.calls[0][0]).toMatchObject({
            transactionIndex: 42n,
            creator: members[0],
            multisigPda,
            isDraft: false,
        });
        expect(proposalApprove).not.toHaveBeenCalled();
        expect(vaultExecute).not.toHaveBeenCalled();
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
        expect(proposalApprove).toHaveBeenCalledTimes(2);
        expect(proposalApprove.mock.calls.map(([args]) => args.member)).toEqual(members.slice(0, 2));
        expect(vaultExecute).not.toHaveBeenCalled();

        await expect(wallet.executeProposal(staged)).resolves.toBe('vault-execute-signature');
        expect(vaultExecute).toHaveBeenCalledOnce();
        expect(vaultExecute.mock.calls[0][0]).toMatchObject({
            transactionIndex: 42n,
            member: members[0].publicKey,
            signers: [members[0]],
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
        expect(proposalApprove).not.toHaveBeenCalled();
        expect(vaultExecute).not.toHaveBeenCalled();
    });

    it('rejects duplicate approvers before sending a second vote', async () => {
        const staged: StagedSquadsProposal = {
            multisigPda: multisigPda.toBase58(),
            transactionIndex: 42n,
        };

        await expect(wallet.approveProposal(staged, [members[0], members[0]])).rejects.toThrow(
            'SQUADS_PROPOSAL_DUPLICATE_APPROVER',
        );
        expect(proposalApprove).toHaveBeenCalledOnce();
    });

    it('preserves the existing immediate-send behavior as stage, approve, then execute', async () => {
        await expect(wallet.sendInstructions([])).resolves.toBe('vault-execute-signature');

        expect(vaultCreate).toHaveBeenCalledOnce();
        expect(proposalCreate).toHaveBeenCalledOnce();
        expect(proposalApprove).toHaveBeenCalledTimes(2);
        expect(vaultExecute).toHaveBeenCalledOnce();
        expect(vaultCreate.mock.invocationCallOrder[0]).toBeLessThan(
            proposalCreate.mock.invocationCallOrder[0],
        );
        expect(proposalCreate.mock.invocationCallOrder[0]).toBeLessThan(
            proposalApprove.mock.invocationCallOrder[0],
        );
        expect(proposalApprove.mock.invocationCallOrder[1]).toBeLessThan(
            vaultExecute.mock.invocationCallOrder[0],
        );
    });
});
