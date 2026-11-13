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
use spl_token_2022_interface::{extension::ExtensionType, state::Account as TokenAccount};

use crate::{
    instructions::create_plan::{PlanData, PlanTerms},
    state::{
        common::PlanStatus, AuthorityConsentRegistry, PlanRevisionRegistry, SubscriptionLifecycleRegistry, VNextPlan,
        VNextSubscription, VNextSubscriptionAuthority,
    },
    tests::{
        constants::{MINT_DECIMALS, PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID},
        utils::{
            advance_slots, current_ts, fetch_account, init_ata, init_aux_token_account, init_mint, init_wallet,
            initialize_subscription_authority_action, install_transfer_hook_extra_metas, load_transfer_hook_example,
            set_transfer_hook_config, CancelSubscription, CancelSubscriptionNow, CloseSubscriptionAuthority,
            CreateDelegation, CreatePlan, DeletePlan, ResumeSubscription, RevokeAbandonedDelegation,
            RevokeAbandonedSubscription, RevokeDelegation, RevokeSubscription, RevokeSubscriptionAuthority, Subscribe,
            TransferDelegation, TransferSubscription, UpdatePlan, TRANSFER_HOOK_EXAMPLE_PROGRAM_ID,
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
    let legacy_program =
        std::env::var("SOLMINT_LEGACY_PROGRAM_SO").expect("CI must supply the exact immutable v0.5.0 Program binary");
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

    let (registry_address, registry_bump) =
        AuthorityConsentRegistry::find_pda(&subscriber_address, &mint_address, &source_address);
    let (authority_address, authority_bump) =
        VNextSubscriptionAuthority::find_pda(&subscriber_address, &mint_address, &source_address);
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
            .set_account(address, Account { lamports, data, owner: PROGRAM_ID, executable: false, rent_epoch: 0 })
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

fn legacy_subscription_transfer_ix(
    subscription: Pubkey,
    plan: Pubkey,
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
        AccountMeta::new(subscription, false),
        AccountMeta::new_readonly(plan, false),
        AccountMeta::new_readonly(authority, false),
        AccountMeta::new(source, false),
        AccountMeta::new(destination, false),
        AccountMeta::new_readonly(*caller, true),
        AccountMeta::new_readonly(mint, false),
        AccountMeta::new_readonly(token_program, false),
        AccountMeta::new_readonly(event_authority, false),
        AccountMeta::new_readonly(PROGRAM_ID, false),
    ];
    accounts.extend(remaining);

    let mut data = vec![*crate::instructions::transfer_subscription::DISCRIMINATOR];
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

fn set_program_owned_account(litesvm: &mut LiteSVM, address: Pubkey, data: Vec<u8>) {
    let lamports = litesvm.minimum_balance_for_rent_exemption(data.len());
    litesvm
        .set_account(address, Account { lamports, data, owner: PROGRAM_ID, executable: false, rent_epoch: 0 })
        .unwrap();
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
    let vnext_registry =
        to_pubkey(AuthorityConsentRegistry::find_pda(&subscriber_address, &mint_address, &source_address).0);
    let vnext_authority =
        to_pubkey(VNextSubscriptionAuthority::find_pda(&subscriber_address, &mint_address, &source_address).0);
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

    let mint = init_mint(&mut litesvm, TOKEN_PROGRAM_ID, MINT_DECIMALS, 10_000_000, Some(subscriber.pubkey()), &[]);
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
    let (legacy_init, legacy_authority, _) = initialize_subscription_authority_action(&mut litesvm, &subscriber, mint);
    assert!(legacy_init.is_ok(), "the pinned v0.5.0 ATA initialization should remain valid");
    assert_ne!(legacy_authority, vnext_authority);

    let ata_after_init = fetch_account::<TokenAccount>(&litesvm, &subscriber_ata);
    assert_eq!(ata_after_init.delegate.unwrap(), legacy_authority);
    let vnext_source_after_init = fetch_account::<TokenAccount>(&litesvm, &vnext_source);
    assert_eq!(vnext_source_after_init.delegate.unwrap(), vnext_authority);

    let now = litesvm.get_sysvar::<Clock>().unix_timestamp;
    let (fixed_created, fixed_delegation) = CreateDelegation::new(&mut litesvm, &subscriber, mint, delegatee.pubkey())
        .nonce(71)
        .fixed(500_000, now + 86_400);
    assert!(fixed_created.is_ok(), "legacy fixed delegation on ATA should be constructible");

    let (recurring_created, recurring_delegation) =
        CreateDelegation::new(&mut litesvm, &subscriber, mint, delegatee.pubkey()).nonce(72).recurring(
            500_000,
            3_600,
            now,
            now + 86_400,
        );
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
    assert!(CloseSubscriptionAuthority::new(&mut litesvm, &subscriber, mint).pda(vnext_authority).execute().is_err());

    assert!(RevokeSubscriptionAuthority::new(&mut litesvm, &subscriber, mint)
        .ata(subscriber_ata)
        .authority(vnext_authority)
        .execute()
        .is_err());

    assert!(RevokeDelegation::new(&mut litesvm, &subscriber, mint, delegatee.pubkey(), 75,)
        .pda(vnext_registry)
        .execute()
        .is_err());

    assert!(RevokeAbandonedDelegation::new(&mut litesvm, &subscriber, subscriber.pubkey(), mint, delegatee.pubkey(),)
        .nonce(76)
        .pda(vnext_registry)
        .authority(vnext_authority)
        .execute()
        .is_err());

    // Supplying the non-ATA VNext source to a valid legacy delegation must not
    // transfer from it. Account substitution of the VNext Authority must also fail.
    assert!(TransferDelegation::new(&mut litesvm, &delegatee, subscriber.pubkey(), mint, fixed_delegation,)
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
        vec![AccountMeta::new(vnext_registry, false), AccountMeta::new(vnext_authority, false)],
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
        vec![AccountMeta::new(vnext_registry, false), AccountMeta::new(vnext_authority, false)],
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
        vec![AccountMeta::new(vnext_registry, false), AccountMeta::new(vnext_authority, false)],
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

/// The immutable v0.5.0 Plan and Subscription lifecycle handlers must not
/// reinterpret VNext Plan/Subscription accounts or mutate their persistent
/// revision registries. This is a bounded account-boundary test; it does not
/// disable legacy instructions for pre-existing ATA-backed customers.
#[test]
#[ignore = "requires SOLMINT_LEGACY_PROGRAM_SO from the immutable v0.5.0 build"]
fn vnext_legacy_program_plan_and_subscription_routes_preserve_vnext_lineage() {
    let mut litesvm = load_immutable_legacy_program();
    let subscriber = init_wallet(&mut litesvm, 100_000_000_000);
    let merchant = init_wallet(&mut litesvm, 100_000_000_000);
    let mint = init_mint(&mut litesvm, TOKEN_PROGRAM_ID, MINT_DECIMALS, 10_000_000, Some(subscriber.pubkey()), &[]);
    let subscriber_ata = init_ata(&mut litesvm, mint, subscriber.pubkey(), 2_000_000);
    let merchant_ata = init_ata(&mut litesvm, mint, merchant.pubkey(), 0);
    let vnext_source = init_aux_token_account(&mut litesvm, mint, subscriber.pubkey(), 2_000_000);

    let (authority_registry, vnext_authority) =
        seed_vnext_non_ata_lineage(&mut litesvm, &subscriber.pubkey(), &mint, &vnext_source);
    let (legacy_init, legacy_authority, _) = initialize_subscription_authority_action(&mut litesvm, &subscriber, mint);
    assert!(legacy_init.is_ok(), "legacy ATA authority setup must succeed for the control case");

    let now = litesvm.get_sysvar::<Clock>().unix_timestamp;
    let plan_id = 9001u64;
    let merchant_address = to_address(&merchant.pubkey());
    let subscriber_address = to_address(&subscriber.pubkey());
    let mint_address = to_address(&mint);
    let source_address = to_address(&vnext_source);
    let zero_address: pinocchio::Address = [0u8; 32].into();
    let terms = PlanTerms { amount: 100_000, period_hours: 24, created_at: now };
    let plan_data = PlanData {
        plan_id,
        mint: mint_address,
        terms,
        end_ts: 0,
        destinations: [zero_address; 4],
        pullers: [zero_address; 4],
        metadata_uri: [0u8; 128],
    };

    let (vnext_plan_address, vnext_plan_bump) = VNextPlan::find_pda(&merchant_address, plan_id);
    let vnext_plan = to_pubkey(vnext_plan_address);
    let mut vnext_plan_data = vec![0u8; VNextPlan::LEN];
    VNextPlan::init(&mut vnext_plan_data, &merchant_address, vnext_plan_bump, PlanStatus::Active as u8, 1, &plan_data)
        .unwrap();
    set_program_owned_account(&mut litesvm, vnext_plan, vnext_plan_data);

    let (plan_registry_address, plan_registry_bump) =
        PlanRevisionRegistry::find_pda(&merchant_address, &vnext_plan_address);
    let plan_registry = to_pubkey(plan_registry_address);
    let mut plan_registry_data = vec![0u8; PlanRevisionRegistry::LEN];
    PlanRevisionRegistry::init(
        &mut plan_registry_data,
        &vnext_plan_address,
        &merchant_address,
        &merchant_address,
        plan_registry_bump,
    )
    .unwrap();
    PlanRevisionRegistry::load_mut(&mut plan_registry_data).unwrap().advance(0, 0).unwrap();
    set_program_owned_account(&mut litesvm, plan_registry, plan_registry_data);

    let (lifecycle_address, lifecycle_bump) =
        SubscriptionLifecycleRegistry::find_pda(&vnext_plan_address, &subscriber_address, &source_address);
    let lifecycle_registry = to_pubkey(lifecycle_address);
    let mut lifecycle_data = vec![0u8; SubscriptionLifecycleRegistry::LEN];
    SubscriptionLifecycleRegistry::init(
        &mut lifecycle_data,
        &vnext_plan_address,
        &subscriber_address,
        &source_address,
        &subscriber_address,
        lifecycle_bump,
    )
    .unwrap();
    SubscriptionLifecycleRegistry::load_mut(&mut lifecycle_data).unwrap().advance(0, 0).unwrap();
    set_program_owned_account(&mut litesvm, lifecycle_registry, lifecycle_data);

    let (vnext_subscription_address, vnext_subscription_bump) =
        VNextSubscription::find_pda(&vnext_plan_address, &subscriber_address, &source_address);
    let vnext_subscription = to_pubkey(vnext_subscription_address);
    let mut vnext_subscription_data = vec![0u8; VNextSubscription::LEN];
    VNextSubscription::init(
        &mut vnext_subscription_data,
        &vnext_plan_address,
        &subscriber_address,
        &source_address,
        &mint_address,
        &to_address(&TOKEN_PROGRAM_ID),
        &subscriber_address,
        &terms,
        now,
        1,
        1,
        vnext_subscription_bump,
    )
    .unwrap();
    set_program_owned_account(&mut litesvm, vnext_subscription, vnext_subscription_data);

    let (legacy_plan, legacy_plan_bump) = crate::tests::pda::get_plan_pda(&merchant.pubkey(), plan_id);
    assert_ne!(legacy_plan, vnext_plan, "legacy and VNext Plan namespaces must differ");

    let (legacy_plan_result, created_legacy_plan) = CreatePlan::new(&mut litesvm, &merchant, mint)
        .plan_id(plan_id)
        .amount(terms.amount)
        .period_hours(terms.period_hours)
        .execute();
    assert!(legacy_plan_result.is_ok(), "the immutable legacy Plan control case must remain usable");
    assert_eq!(created_legacy_plan, legacy_plan);

    let legacy_plan_account = litesvm.get_account(&legacy_plan).unwrap();
    let legacy_plan_state = crate::Plan::load(&legacy_plan_account.data).unwrap();
    let legacy_plan_mint = legacy_plan_state.data.mint;
    let legacy_plan_amount = legacy_plan_state.data.terms.amount;
    let legacy_plan_period_hours = legacy_plan_state.data.terms.period_hours;
    let legacy_plan_created_at = legacy_plan_state.data.terms.created_at;
    let legacy_authority_account = litesvm.get_account(&legacy_authority).unwrap();
    let legacy_init_id = SubscriptionAuthority::load(&legacy_authority_account.data).unwrap().init_id;

    let (legacy_subscription, _) = crate::tests::pda::get_subscription_pda(&legacy_plan, &subscriber.pubkey());
    assert_ne!(
        legacy_subscription, vnext_subscription,
        "legacy Subscription PDA must not alias the source-bound VNext PDA"
    );

    let legacy_subscribe_control =
        Subscribe::new(&mut litesvm, &subscriber, merchant.pubkey(), legacy_plan, plan_id, legacy_plan_bump, mint)
            .execute();
    assert!(legacy_subscribe_control.is_ok(), "legacy Subscribe control case must remain operational");
    let legacy_subscription_before = litesvm.get_account(&legacy_subscription).unwrap();

    let legacy_plan_before = litesvm.get_account(&legacy_plan).unwrap();
    let plan_before = litesvm.get_account(&vnext_plan).unwrap();
    let plan_registry_before = litesvm.get_account(&plan_registry).unwrap();
    let subscription_before = litesvm.get_account(&vnext_subscription).unwrap();
    let lifecycle_before = litesvm.get_account(&lifecycle_registry).unwrap();
    let authority_registry_before = litesvm.get_account(&authority_registry).unwrap();
    let authority_before = litesvm.get_account(&vnext_authority).unwrap();
    let source_before = litesvm.get_account(&vnext_source).unwrap();
    let subscriber_ata_before = litesvm.get_account(&subscriber_ata).unwrap();
    let merchant_ata_before = litesvm.get_account(&merchant_ata).unwrap();

    let (legacy_create_result, _) = CreatePlan::new(&mut litesvm, &merchant, mint)
        .plan_id(plan_id)
        .amount(100_000)
        .period_hours(24)
        .pda(vnext_plan)
        .execute();
    assert!(legacy_create_result.is_err(), "legacy CreatePlan must not occupy the VNext Plan PDA");

    assert!(
        UpdatePlan::new(&mut litesvm, &merchant, vnext_plan).metadata_uri("legacy mutation").execute().is_err(),
        "legacy UpdatePlan must reject VNext Plan account encoding"
    );
    assert!(
        DeletePlan::new(&mut litesvm, &merchant, vnext_plan).execute().is_err(),
        "legacy DeletePlan must reject VNext Plan account encoding"
    );

    let mut subscribe_data = vec![*crate::instructions::subscribe::DISCRIMINATOR];
    subscribe_data.extend_from_slice(&plan_id.to_le_bytes());
    subscribe_data.push(legacy_plan_bump);
    subscribe_data.extend_from_slice(legacy_plan_mint.as_ref());
    subscribe_data.extend_from_slice(&legacy_plan_amount.to_le_bytes());
    subscribe_data.extend_from_slice(&legacy_plan_period_hours.to_le_bytes());
    subscribe_data.extend_from_slice(&legacy_plan_created_at.to_le_bytes());
    subscribe_data.extend_from_slice(&legacy_init_id.to_le_bytes());
    let event_authority = Pubkey::find_program_address(&[b"event_authority"], &PROGRAM_ID).0;
    let legacy_subscribe = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(subscriber.pubkey(), true),
            AccountMeta::new_readonly(merchant.pubkey(), false),
            AccountMeta::new_readonly(legacy_plan, false),
            AccountMeta::new(vnext_subscription, false),
            AccountMeta::new_readonly(legacy_authority, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(event_authority, false),
            AccountMeta::new_readonly(PROGRAM_ID, false),
        ],
        data: subscribe_data,
    };
    assert!(
        !send_signed(&mut litesvm, &subscriber, legacy_subscribe),
        "legacy Subscribe must reject a VNext Plan/Subscription binding"
    );
    let legacy_subscription_after_bad_subscribe = litesvm.get_account(&legacy_subscription).unwrap();
    assert_eq!(
        legacy_subscription_after_bad_subscribe.data, legacy_subscription_before.data,
        "account substitution during legacy Subscribe changed the real legacy Subscription"
    );
    assert_eq!(
        legacy_subscription_after_bad_subscribe.lamports, legacy_subscription_before.lamports,
        "account substitution during legacy Subscribe changed legacy Subscription lamports"
    );

    assert!(
        TransferSubscription::new(&mut litesvm, &merchant, subscriber.pubkey(), mint, vnext_subscription, legacy_plan,)
            .amount(10_000)
            .to(merchant_ata)
            .execute()
            .is_err(),
        "legacy TransferSubscription must reject VNext Plan/Subscription account data"
    );
    let legacy_transfer_from_vnext_non_ata = legacy_subscription_transfer_ix(
        legacy_subscription,
        legacy_plan,
        legacy_authority,
        vnext_source,
        merchant_ata,
        mint,
        TOKEN_PROGRAM_ID,
        &subscriber.pubkey(),
        &merchant.pubkey(),
        10_000,
        vec![AccountMeta::new(authority_registry, false), AccountMeta::new(vnext_authority, false)],
    );
    assert!(
        !send_signed(&mut litesvm, &merchant, legacy_transfer_from_vnext_non_ata),
        "legacy TransferSubscription must reject a VNext non-ATA source"
    );

    let legacy_transfer_wrong_token_program = legacy_subscription_transfer_ix(
        legacy_subscription,
        legacy_plan,
        legacy_authority,
        subscriber_ata,
        merchant_ata,
        mint,
        TOKEN_2022_PROGRAM_ID,
        &subscriber.pubkey(),
        &merchant.pubkey(),
        10_000,
        vec![],
    );
    assert!(
        !send_signed(&mut litesvm, &merchant, legacy_transfer_wrong_token_program),
        "legacy TransferSubscription must reject Token Program substitution"
    );

    assert!(
        CancelSubscription::new(&mut litesvm, &subscriber, legacy_plan, vnext_subscription).execute().is_err(),
        "legacy CancelSubscription must not mutate a VNext Subscription"
    );
    assert!(
        CancelSubscriptionNow::new(&mut litesvm, &subscriber, &merchant, legacy_plan, vnext_subscription,)
            .expected_current_period_start_ts(now)
            .execute()
            .is_err(),
        "legacy CancelSubscriptionNow must not mutate a VNext Subscription"
    );
    assert!(
        ResumeSubscription::new(&mut litesvm, &subscriber, legacy_plan, vnext_subscription, mint,)
            .subscription_authority(legacy_authority)
            .expected_expires_at_ts(now + 3_600)
            .execute()
            .is_err(),
        "legacy ResumeSubscription must not mutate a VNext Subscription"
    );
    assert!(
        RevokeSubscription::new(&mut litesvm, &subscriber, vnext_subscription, legacy_plan).execute().is_err(),
        "legacy RevokeSubscription must not close a VNext Subscription"
    );

    let revoke_abandoned_subscription = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(subscriber.pubkey(), true),
            AccountMeta::new(vnext_subscription, false),
            AccountMeta::new_readonly(legacy_authority, false),
            AccountMeta::new_readonly(legacy_plan, false),
        ],
        data: vec![*crate::instructions::revoke_abandoned_subscription::DISCRIMINATOR],
    };
    assert!(
        !send_signed(&mut litesvm, &subscriber, revoke_abandoned_subscription),
        "legacy abandoned-account recovery must not close a VNext Subscription"
    );

    for (address, before, label) in [
        (legacy_plan, legacy_plan_before, "legacy Plan"),
        (legacy_subscription, legacy_subscription_before, "legacy Subscription"),
        (vnext_plan, plan_before, "VNext Plan"),
        (plan_registry, plan_registry_before, "Plan Revision Registry"),
        (vnext_subscription, subscription_before, "VNext Subscription"),
        (lifecycle_registry, lifecycle_before, "Subscription Lifecycle Registry"),
        (authority_registry, authority_registry_before, "Authority Consent Registry"),
        (vnext_authority, authority_before, "VNext Authority"),
        (vnext_source, source_before, "VNext source token account"),
        (subscriber_ata, subscriber_ata_before, "legacy ATA"),
        (merchant_ata, merchant_ata_before, "merchant ATA"),
    ] {
        let after = litesvm.get_account(&address).unwrap();
        assert_eq!(after.data, before.data, "{label} bytes changed after legacy attempts");
        assert_eq!(after.lamports, before.lamports, "{label} lamports changed after legacy attempts");
        assert_eq!(after.owner, before.owner, "{label} owner changed after legacy attempts");
        assert_eq!(after.executable, before.executable, "{label} executable flag changed");
    }

    // Positive controls: the exact same immutable legacy binary must continue
    // to operate a canonical ATA-backed legacy Subscription. These successful
    // operations distinguish VNext account-boundary rejection from a blanket
    // failure of the legacy Subscription instruction family.
    // The legacy Subscription is now real and valid. First execute an otherwise
    // valid SPL Token pull while injecting VNext Registry/Authority as trailing
    // accounts. On a mint without a hook, the legacy path must not interpret or
    // mutate those VNext accounts.
    let legacy_transfer_with_vnext_remaining = legacy_subscription_transfer_ix(
        legacy_subscription,
        legacy_plan,
        legacy_authority,
        subscriber_ata,
        merchant_ata,
        mint,
        TOKEN_PROGRAM_ID,
        &subscriber.pubkey(),
        &merchant.pubkey(),
        10_000,
        vec![AccountMeta::new(authority_registry, false), AccountMeta::new(vnext_authority, false)],
    );
    assert!(
        send_signed(&mut litesvm, &merchant, legacy_transfer_with_vnext_remaining),
        "valid legacy TransferSubscription with unrelated VNext remaining accounts must remain operational"
    );
    assert_vnext_lineage_unchanged(
        &litesvm,
        &authority_registry,
        &authority_registry_before.data,
        authority_registry_before.lamports,
        &vnext_authority,
        &authority_before.data,
        authority_before.lamports,
        &vnext_source,
        &source_before.data,
        source_before.lamports,
        vnext_authority,
    );

    let legacy_cancel = CancelSubscription::new(&mut litesvm, &subscriber, legacy_plan, legacy_subscription).execute();
    assert!(legacy_cancel.is_ok(), "legacy CancelSubscription control case must remain operational");

    let legacy_resume =
        ResumeSubscription::new(&mut litesvm, &subscriber, legacy_plan, legacy_subscription, mint).execute();
    assert!(legacy_resume.is_ok(), "legacy ResumeSubscription control case must remain operational");

    let legacy_cancel_now =
        CancelSubscriptionNow::new(&mut litesvm, &subscriber, &merchant, legacy_plan, legacy_subscription)
            .expected_current_period_start_ts(now)
            .execute();
    assert!(legacy_cancel_now.is_ok(), "legacy CancelSubscriptionNow control case must remain operational");

    let legacy_revoke = RevokeSubscription::new(&mut litesvm, &subscriber, legacy_subscription, legacy_plan).execute();
    assert!(legacy_revoke.is_ok(), "legacy RevokeSubscription control case must remain operational");
    let revoked_subscription = litesvm.get_account(&legacy_subscription);
    assert!(
        revoked_subscription.is_none() || revoked_subscription.as_ref().map(|account| account.lamports).unwrap_or(0) == 0
    );

    // Positive recovery control: resubscribe, close the subscriber Authority, advance beyond
    // its init slot, then let the recorded Subscription payer reclaim the abandoned account.
    let resubscribe =
        Subscribe::new(&mut litesvm, &subscriber, merchant.pubkey(), legacy_plan, plan_id, legacy_plan_bump, mint)
            .execute();
    assert!(resubscribe.is_ok(), "legacy resubscribe control must remain operational");

    let subscription_rent = litesvm.get_account(&legacy_subscription).unwrap().lamports;
    let close_authority = CloseSubscriptionAuthority::new(&mut litesvm, &subscriber, mint).execute();
    assert!(close_authority.is_ok(), "legacy SubscriptionAuthority close control must remain operational");
    advance_slots(&mut litesvm, 1);
    // Snapshot after Authority rent has already been returned, so this assertion
    // isolates the rent refunded by the abandoned-Subscription recovery itself.
    let subscriber_balance_before_recovery = litesvm.get_account(&subscriber.pubkey()).unwrap().lamports;

    let abandoned_recovery =
        RevokeAbandonedSubscription::new(&mut litesvm, &subscriber, subscriber.pubkey(), mint, legacy_plan).execute();
    assert!(abandoned_recovery.is_ok(), "legacy abandoned Subscription recovery control must succeed");
    let recovered_subscription = litesvm.get_account(&legacy_subscription);
    assert!(
        recovered_subscription.is_none()
            || recovered_subscription.as_ref().map(|account| account.lamports).unwrap_or(0) == 0,
        "recovered legacy Subscription must be closed"
    );
    let subscriber_balance_after_recovery = litesvm.get_account(&subscriber.pubkey()).unwrap().lamports;
    assert!(
        subscriber_balance_after_recovery >= subscriber_balance_before_recovery + subscription_rent - 10_000,
        "recorded Subscription payer must receive recovered rent"
    );

    assert_vnext_lineage_unchanged(
        &litesvm,
        &authority_registry,
        &authority_registry_before.data,
        authority_registry_before.lamports,
        &vnext_authority,
        &authority_before.data,
        authority_before.lamports,
        &vnext_source,
        &source_before.data,
        source_before.lamports,
        vnext_authority,
    );
}

/// The immutable v0.5.0 binary must forward Token-2022 TransferHook accounts
/// correctly for an ordinary ATA-backed legacy Subscription. Missing hook
/// accounts must fail atomically; the exact ExtraAccountMetaList accounts
/// must execute the hook once and complete the token transfer.
#[test]
#[ignore = "requires SOLMINT_LEGACY_PROGRAM_SO and transfer_hook_example.so"]
fn vnext_legacy_program_executes_token_2022_transfer_hook_with_extra_accounts() {
    let mut litesvm = load_immutable_legacy_program();
    let subscriber = init_wallet(&mut litesvm, 100_000_000_000);
    let merchant = init_wallet(&mut litesvm, 100_000_000_000);
    load_transfer_hook_example(&mut litesvm);

    let mint = init_mint(
        &mut litesvm,
        TOKEN_2022_PROGRAM_ID,
        MINT_DECIMALS,
        1_000_000,
        Some(subscriber.pubkey()),
        &[ExtensionType::TransferHook],
    );
    set_transfer_hook_config(&mut litesvm, mint, Some(subscriber.pubkey()), Some(TRANSFER_HOOK_EXAMPLE_PROGRAM_ID));
    let (validation_pda, counter) = install_transfer_hook_extra_metas(&mut litesvm, mint);

    let subscriber_ata = init_ata(&mut litesvm, mint, subscriber.pubkey(), 1_000_000);
    let merchant_ata = init_ata(&mut litesvm, mint, merchant.pubkey(), 0);
    let (legacy_init, _legacy_authority, _) = initialize_subscription_authority_action(&mut litesvm, &subscriber, mint);
    assert!(legacy_init.is_ok(), "legacy Token-2022 Authority initialization must succeed");

    let plan_id = 9002u64;
    let (legacy_plan_result, legacy_plan) =
        CreatePlan::new(&mut litesvm, &merchant, mint).plan_id(plan_id).amount(100_000).period_hours(24).execute();
    assert!(legacy_plan_result.is_ok(), "legacy Token-2022 Plan creation must succeed");
    let (_, plan_bump) = crate::tests::pda::get_plan_pda(&merchant.pubkey(), plan_id);
    let subscribe =
        Subscribe::new(&mut litesvm, &subscriber, merchant.pubkey(), legacy_plan, plan_id, plan_bump, mint).execute();
    assert!(subscribe.is_ok(), "legacy Token-2022 Subscription creation must succeed");
    let (legacy_subscription, _) = crate::tests::pda::get_subscription_pda(&legacy_plan, &subscriber.pubkey());

    let subscription_before = litesvm.get_account(&legacy_subscription).unwrap();
    let source_before = litesvm.get_account(&subscriber_ata).unwrap();
    let destination_before = litesvm.get_account(&merchant_ata).unwrap();
    let counter_before = litesvm.get_account(&counter).unwrap();

    let missing_hook_accounts =
        TransferSubscription::new(&mut litesvm, &merchant, subscriber.pubkey(), mint, legacy_subscription, legacy_plan)
            .amount(100_000)
            .to(merchant_ata)
            .execute();
    assert!(missing_hook_accounts.is_err(), "Legacy TransferSubscription without Hook accounts must fail");

    let subscription_after_missing = litesvm.get_account(&legacy_subscription).unwrap();
    let source_after_missing = litesvm.get_account(&subscriber_ata).unwrap();
    let destination_after_missing = litesvm.get_account(&merchant_ata).unwrap();
    let counter_after_missing = litesvm.get_account(&counter).unwrap();
    assert_eq!(subscription_after_missing.data, subscription_before.data);
    assert_eq!(subscription_after_missing.lamports, subscription_before.lamports);
    assert_eq!(source_after_missing.data, source_before.data);
    assert_eq!(source_after_missing.lamports, source_before.lamports);
    assert_eq!(destination_after_missing.data, destination_before.data);
    assert_eq!(destination_after_missing.lamports, destination_before.lamports);
    assert_eq!(counter_after_missing.data, counter_before.data);
    assert_eq!(counter_after_missing.lamports, counter_before.lamports);

    let hooked_transfer =
        TransferSubscription::new(&mut litesvm, &merchant, subscriber.pubkey(), mint, legacy_subscription, legacy_plan)
            .amount(100_000)
            .to(merchant_ata)
            .remaining(vec![
                AccountMeta::new_readonly(TRANSFER_HOOK_EXAMPLE_PROGRAM_ID, false),
                AccountMeta::new_readonly(validation_pda, false),
                AccountMeta::new(counter, false),
            ])
            .execute();
    assert!(hooked_transfer.is_ok(), "Legacy TransferSubscription must execute the active Token-2022 Hook");

    assert_eq!(fetch_account::<TokenAccount>(&litesvm, &subscriber_ata).amount, 900_000);
    assert_eq!(fetch_account::<TokenAccount>(&litesvm, &merchant_ata).amount, 100_000);
    assert_eq!(litesvm.get_account(&counter).unwrap().data[0], 1, "legacy Token-2022 Hook must execute exactly once");
}
