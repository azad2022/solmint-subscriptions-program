use litesvm::LiteSVM;
use solana_account::Account;
use solana_clock::Clock;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_program_pack::Pack;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use spl_token_2022_interface::state::Account as TokenAccount;

use crate::{
    state::{AuthorityConsentRegistry, VNextSubscriptionAuthority},
    tests::{
        constants::{MINT_DECIMALS, PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID},
        utils::{
            current_ts, fetch_account, init_ata, init_aux_token_account, init_mint, init_wallet,
            initialize_subscription_authority_action, CloseSubscriptionAuthority, CreateDelegation,
            RevokeAbandonedDelegation, RevokeDelegation, RevokeSubscriptionAuthority, TransferDelegation,
        },
    },
    SubscriptionAuthority, AUTHORITY_REGISTRY_ACTIVE,
};

fn to_address(key: &Pubkey) -> pinocchio::Address {
    pinocchio::Address::from(key.to_bytes())
}

fn to_pubkey(address: pinocchio::Address) -> Pubkey {
    Pubkey::new_from_array(address.to_bytes())
}

fn load_immutable_legacy_program() -> LiteSVM {
    let legacy_program = std::env::var("SOLMINT_LEGACY_PROGRAM_SO")
        .expect("CI must supply the exact immutable v0.5.0 Program binary");
    let mut litesvm = LiteSVM::new();
    litesvm.add_program_from_file(PROGRAM_ID.to_bytes(), legacy_program).unwrap();

    let mut clock = litesvm.get_sysvar::<Clock>();
    clock.unix_timestamp = current_ts();
    litesvm.set_sysvar::<Clock>(&clock);
    litesvm
}

/// Installs byte-valid VNext Registry/Authority fixtures and a non-ATA token
/// account whose delegate points at the VNext Authority. The old binary is
/// loaded by the caller and cannot create or interpret these VNext account
/// types. Fixture bytes are created with the exact production state encoders.
fn seed_vnext_non_ata_lineage(
    litesvm: &mut LiteSVM,
    subscriber: &Pubkey,
    mint: &Pubkey,
    source: &Pubkey,
) -> (Pubkey, Pubkey) {
    let subscriber_address = to_address(subscriber);
    let mint_address = to_address(mint);
    let source_address = to_address(source);
    let token_program_address = to_address(&TOKEN_PROGRAM_ID);

    let (registry_address, registry_bump) = AuthorityConsentRegistry::find_pda(
        &subscriber_address,
        &mint_address,
        &source_address,
    );
    let (authority_address, authority_bump) = VNextSubscriptionAuthority::find_pda(
        &subscriber_address,
        &mint_address,
        &source_address,
    );
    let registry = to_pubkey(registry_address);
    let authority = to_pubkey(authority_address);

    let mut registry_data = vec![0u8; AuthorityConsentRegistry::LEN];
    AuthorityConsentRegistry::init(
        &mut registry_data,
        &subscriber_address,
        &mint_address,
        &source_address,
        &token_program_address,
        &subscriber_address,
        registry_bump,
    )
    .unwrap();
    registry_data[2] = AUTHORITY_REGISTRY_ACTIVE;
    registry_data[164..172].copy_from_slice(&1u64.to_le_bytes());
    registry_data[172..180].copy_from_slice(&1u64.to_le_bytes());

    let mut authority_data = vec![0u8; VNextSubscriptionAuthority::LEN];
    VNextSubscriptionAuthority::init(
        &mut authority_data,
        &subscriber_address,
        &mint_address,
        &source_address,
        &registry_address,
        &token_program_address,
        &subscriber_address,
        1,
        authority_bump,
    )
    .unwrap();

    for (address, data) in [(registry, registry_data), (authority, authority_data)] {
        let lamports = litesvm.minimum_balance_for_rent_exemption(data.len());
        litesvm
            .set_account(
                address,
                Account { lamports, data, owner: PROGRAM_ID, executable: false, rent_epoch: 0 },
            )
            .unwrap();
    }

    let mut source_account = litesvm.get_account(source).unwrap();
    let mut source_state = TokenAccount::unpack(&source_account.data).unwrap();
    source_state.delegate = Some(authority).into();
    source_state.delegated_amount = u64::MAX;
    TokenAccount::pack(source_state, &mut source_account.data).unwrap();
    litesvm.set_account(*source, source_account).unwrap();

    (registry, authority)
}

fn send_signed(litesvm: &mut LiteSVM, signer: &Keypair, instruction: Instruction) -> bool {
    let transaction = Transaction::new(
        &[signer],
        Message::new(std::slice::from_ref(&instruction), Some(&signer.pubkey())),
        litesvm.latest_blockhash(),
    );
    let result = litesvm.send_transaction(transaction);
    litesvm.expire_blockhash();
    result.is_ok()
}

fn legacy_create_permission_ix(
    discriminator: u8,
    subscriber: &Pubkey,
    vnext_authority: Pubkey,
    attempted_delegation_account: Pubkey,
    delegatee: &Pubkey,
    payload: &[u8],
) -> Instruction {
    let mut data = vec![discriminator];
    data.extend_from_slice(payload);
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*subscriber, true),
            AccountMeta::new(vnext_authority, false),
            AccountMeta::new(attempted_delegation_account, false),
            AccountMeta::new_readonly(*delegatee, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

fn legacy_transfer_ix(
    discriminator: u8,
    delegation: Pubkey,
    authority: Pubkey,
    source: Pubkey,
    destination: Pubkey,
    mint: Pubkey,
    token_program: Pubkey,
    delegator: &Pubkey,
    caller: &Pubkey,
    amount: u64,
    remaining: Vec<AccountMeta>,
) -> Instruction {
    let event_authority = Pubkey::find_program_address(&[b"event_authority"], &PROGRAM_ID).0;
    let mut accounts = vec![
        AccountMeta::new(delegation, false),
        AccountMeta::new(authority, false),
        AccountMeta::new(source, false),
        AccountMeta::new(destination, false),
        AccountMeta::new_readonly(mint, false),
        AccountMeta::new_readonly(token_program, false),
        AccountMeta::new_readonly(*caller, true),
        AccountMeta::new_readonly(event_authority, false),
        AccountMeta::new_readonly(PROGRAM_ID, false),
    ];
    accounts.extend(remaining);

    let mut data = vec![discriminator];
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(delegator.as_ref());
    data.extend_from_slice(mint.as_ref());
    Instruction { program_id: PROGRAM_ID, accounts, data }
}

fn assert_vnext_lineage_unchanged(
    litesvm: &LiteSVM,
    registry: &Pubkey,
    registry_data: &[u8],
    registry_lamports: u64,
    authority: &Pubkey,
    authority_data: &[u8],
    authority_lamports: u64,
    source: &Pubkey,
    source_data: &[u8],
    source_lamports: u64,
    expected_delegate: Pubkey,
) {
    let registry_after = litesvm.get_account(registry).unwrap();
    assert_eq!(registry_after.data, registry_data, "legacy path mutated VNext Registry bytes");
    assert_eq!(registry_after.lamports, registry_lamports, "legacy path changed VNext Registry lamports");

    let authority_after = litesvm.get_account(authority).unwrap();
    assert_eq!(authority_after.data, authority_data, "legacy path mutated VNext Authority bytes");
    assert_eq!(authority_after.lamports, authority_lamports, "legacy path changed VNext Authority lamports");

    let source_after = litesvm.get_account(source).unwrap();
    assert_eq!(source_after.data, source_data, "legacy path mutated VNext source token bytes");
    assert_eq!(source_after.lamports, source_lamports, "legacy path changed VNext source lamports");
    let source_state = TokenAccount::unpack(&source_after.data).unwrap();
    assert_eq!(source_state.delegate.unwrap(), expected_delegate);
    assert_eq!(source_state.delegated_amount, u64::MAX);
}

/// The immutable v0.5.0 dispatcher must reject every additive VNext
/// instruction discriminator (18..=27) before account processing. This is a
/// binary-compatibility boundary test, not proof of a separate Program ID.
#[test]
#[ignore = "requires SOLMINT_LEGACY_PROGRAM_SO from the immutable v0.5.0 build"]
fn vnext_legacy_program_rejects_all_vnext_instruction_discriminators() {
    let mut litesvm = load_immutable_legacy_program();
    let payer = init_wallet(&mut litesvm, 100_000_000_000);

    for discriminator in 18u8..=27 {
        let ix = Instruction { program_id: PROGRAM_ID, accounts: vec![], data: vec![discriminator] };
        let result = send_signed(&mut litesvm, &payer, ix);
        assert!(!result, "immutable v0.5.0 Program unexpectedly accepted VNext discriminator {discriminator}");
    }

    assert!(litesvm.get_account(&payer.pubkey()).is_some());
}

/// The old Init path rejects an auxiliary token account. This is only a
/// single non-ATA boundary test; the expanded matrix below also installs
/// VNext-shaped state before invoking legacy instructions.
#[test]
#[ignore = "requires SOLMINT_LEGACY_PROGRAM_SO from the immutable v0.5.0 build"]
fn vnext_legacy_program_cannot_delegate_a_non_ata_source() {
    let mut litesvm = load_immutable_legacy_program();
    let subscriber = init_wallet(&mut litesvm, 100_000_000_000);
    let mint = init_mint(&mut litesvm, TOKEN_PROGRAM_ID, MINT_DECIMALS, 1_000_000_000, Some(subscriber.pubkey()), &[]);
    let source = init_aux_token_account(&mut litesvm, mint, subscriber.pubkey(), 1_000_000);

    let subscriber_address = to_address(&subscriber.pubkey());
    let mint_address = to_address(&mint);
    let source_address = to_address(&source);
    let vnext_registry = to_pubkey(
        AuthorityConsentRegistry::find_pda(&subscriber_address, &mint_address, &source_address).0,
    );
    let vnext_authority = to_pubkey(
        VNextSubscriptionAuthority::find_pda(&subscriber_address, &mint_address, &source_address).0,
    );
    let (legacy_authority, _) = Pubkey::find_program_address(
        &[SubscriptionAuthority::SEED, subscriber.pubkey().as_ref(), mint.as_ref()],
        &PROGRAM_ID,
    );

    let init = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(subscriber.pubkey(), true),
            AccountMeta::new(legacy_authority, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(source, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
        ],
        data: vec![0],
    };
    assert!(!send_signed(&mut litesvm, &subscriber, init));

    let source_state = fetch_account::<TokenAccount>(&litesvm, &source);
    assert_eq!(source_state.amount, 1_000_000);
    assert!(source_state.delegate.is_none());
    assert!(litesvm.get_account(&legacy_authority).is_none());
    assert!(litesvm.get_account(&vnext_registry).is_none());
    assert!(litesvm.get_account(&vnext_authority).is_none());
}

/// Exercise the immutable v0.5.0 authority, permission and transfer handlers
/// against a byte-valid VNext Registry/Authority and a non-ATA source, while
/// an ATA for the same subscriber+mint is present. The legacy handlers remain
/// callable for the ATA; attempts to substitute or spend through VNext state
/// must fail atomically and preserve the VNext account/token bytes.
#[test]
#[ignore = "requires SOLMINT_LEGACY_PROGRAM_SO from the immutable v0.5.0 build"]
fn vnext_legacy_program_authority_and_transfer_routes_preserve_non_ata_lineage() {
    let mut litesvm = load_immutable_legacy_program();
    let subscriber = init_wallet(&mut litesvm, 100_000_000_000);
    let delegatee = init_wallet(&mut litesvm, 100_000_000_000);

    let mint = init_mint(
        &mut litesvm,
        TOKEN_PROGRAM_ID,
        MINT_DECIMALS,
        10_000_000,
        Some(subscriber.pubkey()),
        &[],
    );
    let subscriber_ata = init_ata(&mut litesvm, mint, subscriber.pubkey(), 2_000_000);
    let vnext_source = init_aux_token_account(&mut litesvm, mint, subscriber.pubkey(), 2_000_000);
    let delegatee_ata = init_ata(&mut litesvm, mint, delegatee.pubkey(), 0);
    assert_ne!(subscriber_ata, vnext_source, "test must use distinct ATA and non-ATA accounts");

    let (vnext_registry, vnext_authority) =
        seed_vnext_non_ata_lineage(&mut litesvm, &subscriber.pubkey(), &mint, &vnext_source);
    let registry_before = litesvm.get_account(&vnext_registry).unwrap();
    let authority_before = litesvm.get_account(&vnext_authority).unwrap();
    let source_before = litesvm.get_account(&vnext_source).unwrap();

    // The old instruction is still valid for the canonical ATA. This proves
    // legacy dispatch remains active and is not silently disabled by additive VNext selectors.
    let (legacy_init, legacy_authority, _) =
        initialize_subscription_authority_action(&mut litesvm, &subscriber, mint);
    assert!(legacy_init.is_ok(), "the pinned v0.5.0 ATA initialization should remain valid");
    assert_ne!(legacy_authority, vnext_authority);

    let ata_after_init = fetch_account::<TokenAccount>(&litesvm, &subscriber_ata);
    assert_eq!(ata_after_init.delegate.unwrap(), legacy_authority);
    let vnext_source_after_init = fetch_account::<TokenAccount>(&litesvm, &vnext_source);
    assert_eq!(vnext_source_after_init.delegate.unwrap(), vnext_authority);

    let now = litesvm.get_sysvar::<Clock>().unix_timestamp;
    let (fixed_created, fixed_delegation) = CreateDelegation::new(
        &mut litesvm,
        &subscriber,
        mint,
        delegatee.pubkey(),
    )
    .nonce(71)
    .fixed(500_000, now + 86_400);
    assert!(fixed_created.is_ok(), "legacy fixed delegation on ATA should be constructible");

    let (recurring_created, recurring_delegation) = CreateDelegation::new(
        &mut litesvm,
        &subscriber,
        mint,
        delegatee.pubkey(),
    )
    .nonce(72)
    .recurring(500_000, 3_600, now, now + 86_400);
    assert!(recurring_created.is_ok(), "legacy recurring delegation on ATA should be constructible");

    // A legacy permission-creation instruction may not reinterpret a VNext
    // Authority or overwrite the persistent VNext Registry as a delegation PDA.
    let mut fixed_payload = Vec::new();
    fixed_payload.extend_from_slice(&73u64.to_le_bytes());
    fixed_payload.extend_from_slice(&100_000u64.to_le_bytes());
    fixed_payload.extend_from_slice(&(now + 3_600).to_le_bytes());
    fixed_payload.extend_from_slice(&1i64.to_le_bytes());
    let create_fixed_against_vnext = legacy_create_permission_ix(
        1,
        &subscriber.pubkey(),
        vnext_authority,
        vnext_registry,
        &delegatee.pubkey(),
        &fixed_payload,
    );
    assert!(!send_signed(&mut litesvm, &subscriber, create_fixed_against_vnext));

    let mut recurring_payload = Vec::new();
    recurring_payload.extend_from_slice(&74u64.to_le_bytes());
    recurring_payload.extend_from_slice(&100_000u64.to_le_bytes());
    recurring_payload.extend_from_slice(&3_600u64.to_le_bytes());
    recurring_payload.extend_from_slice(&now.to_le_bytes());
    recurring_payload.extend_from_slice(&(now + 86_400).to_le_bytes());
    recurring_payload.extend_from_slice(&1i64.to_le_bytes());
    let create_recurring_against_vnext = legacy_create_permission_ix(
        2,
        &subscriber.pubkey(),
        vnext_authority,
        vnext_registry,
        &delegatee.pubkey(),
        &recurring_payload,
    );
    assert!(!send_signed(&mut litesvm, &subscriber, create_recurring_against_vnext));

    // Legacy close/revoke/recovery paths must not close or reinterpret VNext accounts.
    assert!(CloseSubscriptionAuthority::new(&mut litesvm, &subscriber, mint)
        .pda(vnext_authority)
        .execute()
        .is_err());

    assert!(RevokeSubscriptionAuthority::new(&mut litesvm, &subscriber, mint)
        .ata(subscriber_ata)
        .authority(vnext_authority)
        .execute()
        .is_err());

    assert!(RevokeDelegation::new(
        &mut litesvm,
        &subscriber,
        mint,
        delegatee.pubkey(),
        75,
    )
    .pda(vnext_registry)
    .execute()
    .is_err());

    assert!(RevokeAbandonedDelegation::new(
        &mut litesvm,
        &subscriber,
        subscriber.pubkey(),
        mint,
        delegatee.pubkey(),
    )
    .nonce(76)
    .pda(vnext_registry)
    .authority(vnext_authority)
    .execute()
    .is_err());

    // Supplying the non-ATA VNext source to a valid legacy delegation must not
    // transfer from it. Account substitution of the VNext Authority must also fail.
    assert!(TransferDelegation::new(
        &mut litesvm,
        &delegatee,
        subscriber.pubkey(),
        mint,
        fixed_delegation,
    )
    .amount(10_000)
    .from(vnext_source)
    .to(delegatee_ata)
    .fixed()
    .is_err());

    let substituted_authority_transfer = legacy_transfer_ix(
        4,
        fixed_delegation,
        vnext_authority,
        vnext_source,
        delegatee_ata,
        mint,
        TOKEN_PROGRAM_ID,
        &subscriber.pubkey(),
        &delegatee.pubkey(),
        10_000,
        vec![
            AccountMeta::new(vnext_registry, false),
            AccountMeta::new(vnext_authority, false),
        ],
    );
    assert!(!send_signed(&mut litesvm, &delegatee, substituted_authority_transfer));

    // A mismatched Token Program must not be accepted for the SPL Token mint.
    let wrong_token_program_transfer = legacy_transfer_ix(
        4,
        fixed_delegation,
        legacy_authority,
        subscriber_ata,
        delegatee_ata,
        mint,
        TOKEN_2022_PROGRAM_ID,
        &subscriber.pubkey(),
        &delegatee.pubkey(),
        10_000,
        vec![],
    );
    assert!(!send_signed(&mut litesvm, &delegatee, wrong_token_program_transfer));

    // Both legacy transfer variants can still execute against the legacy ATA.
    // Injecting VNext Registry/Authority as remaining accounts must not mutate them.
    let fixed_with_remaining_accounts = legacy_transfer_ix(
        4,
        fixed_delegation,
        legacy_authority,
        subscriber_ata,
        delegatee_ata,
        mint,
        TOKEN_PROGRAM_ID,
        &subscriber.pubkey(),
        &delegatee.pubkey(),
        10_000,
        vec![
            AccountMeta::new(vnext_registry, false),
            AccountMeta::new(vnext_authority, false),
        ],
    );
    assert!(send_signed(&mut litesvm, &delegatee, fixed_with_remaining_accounts));

    let recurring_with_remaining_accounts = legacy_transfer_ix(
        5,
        recurring_delegation,
        legacy_authority,
        subscriber_ata,
        delegatee_ata,
        mint,
        TOKEN_PROGRAM_ID,
        &subscriber.pubkey(),
        &delegatee.pubkey(),
        10_000,
        vec![
            AccountMeta::new(vnext_registry, false),
            AccountMeta::new(vnext_authority, false),
        ],
    );
    assert!(send_signed(&mut litesvm, &delegatee, recurring_with_remaining_accounts));

    assert_eq!(fetch_account::<TokenAccount>(&litesvm, &subscriber_ata).amount, 1_980_000);
    assert_eq!(fetch_account::<TokenAccount>(&litesvm, &delegatee_ata).amount, 20_000);

    assert_vnext_lineage_unchanged(
        &litesvm,
        &vnext_registry,
        &registry_before.data,
        registry_before.lamports,
        &vnext_authority,
        &authority_before.data,
        authority_before.lamports,
        &vnext_source,
        &source_before.data,
        source_before.lamports,
        vnext_authority,
    );
}
