import type { Address, Instruction } from '@solana/kit';
import {
    type Connection,
    Keypair,
    LAMPORTS_PER_SOL,
    PublicKey,
    sendAndConfirmTransaction,
    Transaction,
    TransactionMessage,
} from '@solana/web3.js';
import * as squads from '@sqds/multisig';
import type { SmartWallet } from './SmartWallet.ts';
import { toWeb3Instruction } from './utils.ts';

type SquadsWalletConfig = {
    connection: Connection;
    feePayer: Keypair;
    members: Keypair[];
    approvalsRequired: number;
    vaultIndex?: number;
    programId?: PublicKey;
};

export type StagedSquadsProposal = Readonly<{
    multisigPda: string;
    transactionIndex: bigint;
}>;

/**
 * A Squads proposal is deliberately split into independent phases so callers
 * can retain an approved proposal while other on-chain state changes occur.
 * The target Program must enforce its own generation/revision/deadline checks
 * when Squads eventually invokes the stored instruction.
 */
export class SquadsSmartWallet implements SmartWallet {
    public readonly name = 'squads';
    public readonly address: Address;
    private readonly connection: Connection;
    private readonly feePayer: Keypair;
    private readonly members: Keypair[];
    private readonly approvalsRequired: number;
    private readonly multisigPda: PublicKey;
    private readonly vaultIndex: number;
    private readonly programId: PublicKey;

    constructor(config: {
        connection: Connection;
        feePayer: Keypair;
        members: Keypair[];
        approvalsRequired: number;
        multisigPda: PublicKey;
        vaultIndex: number;
        programId: PublicKey;
    }) {
        this.connection = config.connection;
        this.feePayer = config.feePayer;
        this.members = config.members;
        this.approvalsRequired = config.approvalsRequired;
        this.multisigPda = config.multisigPda;
        this.vaultIndex = config.vaultIndex;
        this.programId = config.programId;

        const [vaultPda] = squads.getVaultPda({
            multisigPda: this.multisigPda,
            index: this.vaultIndex,
            programId: this.programId,
        });
        this.address = vaultPda.toBase58() as Address;
    }

    private assertProposalBelongsToWallet(proposal: StagedSquadsProposal): void {
        if (proposal.multisigPda !== this.multisigPda.toBase58()) {
            throw new Error('SQUADS_PROPOSAL_MULTISIG_MISMATCH');
        }
        if (proposal.transactionIndex < 1n) {
            throw new Error('SQUADS_PROPOSAL_TRANSACTION_INDEX_INVALID');
        }
    }

    private assertConfiguredMember(member: Keypair): void {
        if (!this.members.some(configured => configured.publicKey.equals(member.publicKey))) {
            throw new Error('SQUADS_MEMBER_NOT_CONFIGURED');
        }
    }

    /**
     * Creates the VaultTransaction and Active Proposal, but does not approve
     * or execute either. Transaction index is read from chain, never guessed
     * from process-local state.
     */
    async stageInstructions(instructions: Instruction[]): Promise<StagedSquadsProposal> {
        const creator = this.members[0];
        if (!creator) throw new Error('SQUADS_MULTISIG_HAS_NO_MEMBERS');

        const multisig = await squads.accounts.Multisig.fromAccountAddress(
            this.connection,
            this.multisigPda,
        );
        const transactionIndex = BigInt(multisig.transactionIndex.toString()) + 1n;

        const message = new TransactionMessage({
            payerKey: new PublicKey(this.address),
            recentBlockhash: (await this.connection.getLatestBlockhash()).blockhash,
            instructions: instructions.map(toWeb3Instruction),
        });

        await squads.rpc.vaultTransactionCreate({
            connection: this.connection,
            feePayer: this.feePayer,
            multisigPda: this.multisigPda,
            transactionIndex,
            creator: creator.publicKey,
            rentPayer: this.feePayer.publicKey,
            signers: [creator],
            vaultIndex: this.vaultIndex,
            ephemeralSigners: 0,
            transactionMessage: message,
            programId: this.programId,
        });

        try {
            await squads.rpc.proposalCreate({
                connection: this.connection,
                feePayer: this.feePayer,
                creator,
                multisigPda: this.multisigPda,
                transactionIndex,
                isDraft: false,
                programId: this.programId,
            });
        } catch (error) {
            throw new Error(
                `SQUADS_PROPOSAL_CREATE_FAILED: vault transaction ${transactionIndex} may already exist; reconcile on-chain state before retrying`,
                { cause: error },
            );
        }

        return Object.freeze({
            multisigPda: this.multisigPda.toBase58(),
            transactionIndex,
        });
    }

    /** Adds votes only; execution is a separate explicit operation. */
    async approveProposal(
        proposal: StagedSquadsProposal,
        approvers: Keypair[] = this.members.slice(0, this.approvalsRequired),
    ): Promise<void> {
        this.assertProposalBelongsToWallet(proposal);
        if (approvers.length === 0) throw new Error('SQUADS_PROPOSAL_APPROVERS_REQUIRED');

        const seen = new Set<string>();
        for (const member of approvers) {
            this.assertConfiguredMember(member);
            const address = member.publicKey.toBase58();
            if (seen.has(address)) throw new Error('SQUADS_PROPOSAL_DUPLICATE_APPROVER');
            seen.add(address);

            await squads.rpc.proposalApprove({
                connection: this.connection,
                feePayer: this.feePayer,
                member,
                multisigPda: this.multisigPda,
                transactionIndex: proposal.transactionIndex,
                programId: this.programId,
            });
        }
    }

    /** Executes an already-approved proposal. Program checks remain authoritative. */
    async executeProposal(
        proposal: StagedSquadsProposal,
        executor: Keypair = this.members[0],
    ): Promise<string> {
        this.assertProposalBelongsToWallet(proposal);
        if (!executor) throw new Error('SQUADS_MULTISIG_HAS_NO_EXECUTOR');
        this.assertConfiguredMember(executor);

        return squads.rpc.vaultTransactionExecute({
            connection: this.connection,
            feePayer: this.feePayer,
            multisigPda: this.multisigPda,
            transactionIndex: proposal.transactionIndex,
            member: executor.publicKey,
            signers: [executor],
            programId: this.programId,
        });
    }

    /** Backward-compatible immediate flow; staged APIs are available for delayed proposals. */
    async sendInstructions(instructions: Instruction[]): Promise<string> {
        const proposal = await this.stageInstructions(instructions);
        await this.approveProposal(proposal);
        return this.executeProposal(proposal);
    }
}

async function ensureProgramConfig({
    connection,
    feePayer,
    programId,
}: {
    connection: Connection;
    feePayer: Keypair;
    programId: PublicKey;
}): Promise<{ programConfigPda: PublicKey; treasury: PublicKey }> {
    const [programConfigPda] = squads.getProgramConfigPda({ programId });
    const existing = await connection.getAccountInfo(programConfigPda);
    if (existing) {
        const programConfig = await squads.accounts.ProgramConfig.fromAccountAddress(connection, programConfigPda);
        return { programConfigPda, treasury: programConfig.treasury };
    }

    const initIx = squads.generated.createProgramConfigInitInstruction(
        {
            programConfig: programConfigPda,
            initializer: feePayer.publicKey,
        },
        {
            args: {
                authority: feePayer.publicKey,
                multisigCreationFee: 0n,
                treasury: feePayer.publicKey,
            },
        },
        programId,
    );

    const tx = new Transaction().add(initIx);
    tx.feePayer = feePayer.publicKey;
    tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
    tx.sign(feePayer);
    await sendAndConfirmTransaction(connection, tx, [feePayer]);

    return { programConfigPda, treasury: feePayer.publicKey };
}

export async function createSquadsWallet(config: SquadsWalletConfig): Promise<SquadsSmartWallet> {
    if (config.members.length === 0) throw new Error('SQUADS_MULTISIG_HAS_NO_MEMBERS');
    if (
        !Number.isInteger(config.approvalsRequired) ||
        config.approvalsRequired < 1 ||
        config.approvalsRequired > config.members.length
    ) {
        throw new Error('SQUADS_APPROVAL_THRESHOLD_INVALID');
    }

    const programId = config.programId ?? squads.PROGRAM_ID;
    const vaultIndex = config.vaultIndex ?? 0;
    const approvalsRequired = config.approvalsRequired;

    const { treasury } = await ensureProgramConfig({
        connection: config.connection,
        feePayer: config.feePayer,
        programId,
    });

    const createKey = Keypair.generate();
    const airdropSig = await config.connection.requestAirdrop(createKey.publicKey, LAMPORTS_PER_SOL);
    await config.connection.confirmTransaction(airdropSig, 'confirmed');
    const [multisigPda] = squads.getMultisigPda({
        createKey: createKey.publicKey,
        programId,
    });

    const members = config.members.map(member => ({
        key: member.publicKey,
        permissions: squads.types.Permissions.all(),
    }));

    const creator = config.members[0];
    await squads.rpc.multisigCreateV2({
        connection: config.connection,
        treasury,
        createKey,
        creator,
        multisigPda,
        configAuthority: config.feePayer.publicKey,
        threshold: approvalsRequired,
        members,
        timeLock: 0,
        rentCollector: null,
        programId,
    });

    return new SquadsSmartWallet({
        connection: config.connection,
        feePayer: config.feePayer,
        members: config.members,
        approvalsRequired,
        multisigPda,
        vaultIndex,
        programId,
    });
}
