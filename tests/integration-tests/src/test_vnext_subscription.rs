use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use spl_token_2022_interface::state::Account as TokenAccount;

use crate::{
    instructions::{
        create_plan::{PlanData, PlanTerms},
        vnext_plan::{VNextCreatePlanData, VNextPlanUpdateData},
        vnext_subscription::{RevisionActionData, VNextSubscribeData, VNextTransferData},
    },
    state::{
        common::PlanStatus, AuthorityConsentRegistry, PlanRevisionRegistry, SubscriptionLifecycleRegistry,
        VNextPlan, VNextSubscription, VNextSubscriptionAuthority,
    },
    tests::{
        asserts::TransactionResultExt,
        constants::{MINT_DECIMALS, PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_PROGRAM_ID},
        utils::{
            build_and_send_transaction, current_ts, fetch_account, get_ata_balance, init_ata,
            init_aux_token_account, init_mint, setup,
        },
    },
    SubscriptionsError,
};

fn to_address(key: &Pubkey) -> pinocchio::Address {
    pinocchio::Address::from(key.to_bytes())
}

fn to_pubkey(address: pinocchio::Address) -> Pubkey {
    Pubkey::new_from_array(address.to_bytes())
}

fn payload_bytes<T>(value: &T) -> Vec<u8> {
    unsafe {
        core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>()).to_vec()
    }
}

fn instruction(discriminator: u8, payload: &[u8], accounts: Vec<AccountMeta>) -> Instruction {
    let mut data = Vec::with_capacity(1 + payload.len());
    data.push(discriminator);
    data.extend_from_slice(payload);
    Instruction { program_id: PROGRAM_ID, accounts, data }
}

fn event_authority() -> Pubkey {
    Pubkey::find_program_address(&[b"event_authority"], &PROGRAM_ID).0
}

fn metadata(value: &str) -> [u8; 128] {
    let mut result = [0u8; 128];
    result[..value.len()].copy_from_slice(value.as_bytes());
    result
}

fn create_plan_ix(merchant: &Pubkey, mint: Pubkey, plan_id: u64) -> (Instruction, Pubkey, Pubkey) {
    let merchant_address = to_address(merchant);
    let mint_address = to_address(&mint);
    let (plan, _) = VNextPlan::find_pda(&merchant_address, plan_id);
    let (registry, _) = PlanRevisionRegistry::find_pda(&merchant_address, &plan);
    let data = VNextCreatePlanData {
        not_after_ts: current_ts() + 3_600,
        plan_data: PlanData {
            plan_id,
            mint: mint_address,
            terms: PlanTerms { amount: 1_000_000, period_hours: 24, created_at: 0 },
            end_ts: 0,
            destinations: [merchant_address, pinocchio::Address::default(), pinocchio::Address::default(), pinocchio::Address::default()],
            pullers: [pinocchio::Address::default(); 4],
            metadata_uri: metadata("A"),
        },
    };
    let ix = instruction(
        20,
        &payload_bytes(&data),
        vec![
            AccountMeta::new(*merchant, true),
            AccountMeta::new(to_pubkey(plan), false),
            AccountMeta::new(to_pubkey(registry), false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
        ],
    );
    (ix, to_pubkey(plan), to_pubkey(registry))
}

fn update_plan_ix(
    merchant: &Pubkey,
    plan: Pubkey,
    registry: Pubkey,
    expected_revision: u64,
    expected_nonce: u64,
    expected_metadata: &str,
    next_metadata: &str,
) -> Instruction {
    let data = VNextPlanUpdateData {
        expected_revision,
        expected_nonce,
        not_after_ts: current_ts() + 3_600,
        expected_status: PlanStatus::Active as u8,
        status: PlanStatus::Active as u8,
        expected_pullers: [pinocchio::Address::default(); 4],
        pullers: [pinocchio::Address::default(); 4],
        expected_metadata_uri: metadata(expected_metadata),
        metadata_uri: metadata(next_metadata),
    };
    instruction(
        21,
        &payload_bytes(&data),
        vec![
            AccountMeta::new_readonly(*merchant, true),
            AccountMeta::new(plan, false),
            AccountMeta::new(registry, false),
            AccountMeta::new_readonly(event_authority(), false),
            AccountMeta::new_readonly(PROGRAM_ID, false),
        ],
    )
}

fn authorize_ix(
    subscriber: &Pubkey,
    registry: Pubkey,
    authority: Pubkey,
    mint: Pubkey,
    source: Pubkey,
) -> Instruction {
    let mut data = vec![18];
    data.extend_from_slice(&0u64.to_le_bytes()); // expected generation
    data.extend_from_slice(&0u64.to_le_bytes()); // authorize nonce
    data.extend_from_slice(&(current_ts() + 3_600).to_le_bytes());
    instruction(
        18,
        &data[1..],
        vec![
            AccountMeta::new(*subscriber, true),
            AccountMeta::new(registry, false),
            AccountMeta::new(authority, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(source, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
        ],
    )
}

fn subscribe_ix(
    subscriber: &Pubkey,
    merchant: &Pubkey,
    plan: Pubkey,
    plan_revision_registry: Pubkey,
    subscription: Pubkey,
    lifecycle_registry: Pubkey,
    consent_registry: Pubkey,
    authority: Pubkey,
    mint: Pubkey,
    source: Pubkey,
    plan_bump: u8,
    created_at: i64,
    lifecycle_revision: u64,
    lifecycle_nonce: u64,
) -> Instruction {
    let data = VNextSubscribeData {
        plan_id: 7,
        plan_bump,
        expected_plan_revision: 1,
        expected_plan_nonce: 1,
        expected_lifecycle_revision: lifecycle_revision,
        expected_lifecycle_nonce: lifecycle_nonce,
        expected_authority_generation: 1,
        not_after_ts: current_ts() + 3_600,
        expected_mint: to_address(&mint),
        expected_amount: 1_000_000,
        expected_period_hours: 24,
        expected_created_at: created_at,
    };
    instruction(
        22,
        &payload_bytes(&data),
        vec![
            AccountMeta::new(*subscriber, true),
            AccountMeta::new_readonly(*merchant, false),
            AccountMeta::new_readonly(plan, false),
            AccountMeta::new_readonly(plan_revision_registry, false),
            AccountMeta::new(subscription, false),
            AccountMeta::new(lifecycle_registry, false),
            AccountMeta::new_readonly(consent_registry, false),
            AccountMeta::new_readonly(authority, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(source, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
            AccountMeta::new_readonly(event_authority(), false),
            AccountMeta::new_readonly(PROGRAM_ID, false),
        ],
    )
}

fn cancel_ix(
    subscriber: &Pubkey,
    plan: Pubkey,
    plan_revision_registry: Pubkey,
    subscription: Pubkey,
    lifecycle_registry: Pubkey,
    revision: u64,
    nonce: u64,
) -> Instruction {
    let data = RevisionActionData { expected_revision: revision, expected_nonce: nonce, not_after_ts: current_ts() + 3_600 };
    instruction(
        23,
        &payload_bytes(&data),
        vec![
            AccountMeta::new_readonly(*subscriber, true),
            AccountMeta::new_readonly(plan, false),
            AccountMeta::new_readonly(plan_revision_registry, false),
            AccountMeta::new(subscription, false),
            AccountMeta::new(lifecycle_registry, false),
            AccountMeta::new_readonly(event_authority(), false),
            AccountMeta::new_readonly(PROGRAM_ID, false),
        ],
    )
}

fn cancel_now_ix(
    subscriber: &Pubkey,
    merchant: &Pubkey,
    plan: Pubkey,
    plan_revision_registry: Pubkey,
    subscription: Pubkey,
    lifecycle_registry: Pubkey,
    revision: u64,
    nonce: u64,
) -> Instruction {
    let data = RevisionActionData { expected_revision: revision, expected_nonce: nonce, not_after_ts: current_ts() + 3_600 };
    instruction(
        24,
        &payload_bytes(&data),
        vec![
            AccountMeta::new_readonly(*subscriber, true),
            AccountMeta::new_readonly(*merchant, true),
            AccountMeta::new_readonly(plan, false),
            AccountMeta::new_readonly(plan_revision_registry, false),
            AccountMeta::new(subscription, false),
            AccountMeta::new(lifecycle_registry, false),
            AccountMeta::new_readonly(event_authority(), false),
            AccountMeta::new_readonly(PROGRAM_ID, false),
        ],
    )
}

fn resume_ix(
    subscriber: &Pubkey,
    plan: Pubkey,
    plan_revision_registry: Pubkey,
    subscription: Pubkey,
    lifecycle_registry: Pubkey,
    consent_registry: Pubkey,
    authority: Pubkey,
    mint: Pubkey,
    source: Pubkey,
    revision: u64,
    nonce: u64,
) -> Instruction {
    let data = RevisionActionData { expected_revision: revision, expected_nonce: nonce, not_after_ts: current_ts() + 3_600 };
    instruction(
        25,
        &payload_bytes(&data),
        vec![
            AccountMeta::new_readonly(*subscriber, true),
            AccountMeta::new_readonly(plan, false),
            AccountMeta::new_readonly(plan_revision_registry, false),
            AccountMeta::new(subscription, false),
            AccountMeta::new(lifecycle_registry, false),
            AccountMeta::new_readonly(consent_registry, false),
            AccountMeta::new_readonly(authority, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(source, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
            AccountMeta::new_readonly(event_authority(), false),
            AccountMeta::new_readonly(PROGRAM_ID, false),
        ],
    )
}

fn transfer_ix(
    subscriber: &Pubkey,
    merchant: &Pubkey,
    plan: Pubkey,
    plan_revision_registry: Pubkey,
    subscription: Pubkey,
    lifecycle_registry: Pubkey,
    consent_registry: Pubkey,
    authority: Pubkey,
    source: Pubkey,
    destination: Pubkey,
    mint: Pubkey,
    lifecycle_revision: u64,
    lifecycle_nonce: u64,
    amount: u64,
) -> Instruction {
    let data = VNextTransferData {
        amount,
        delegator: to_address(subscriber),
        mint: to_address(&mint),
        expected_plan_revision: 1,
        expected_plan_nonce: 1,
        expected_lifecycle_revision: lifecycle_revision,
        expected_lifecycle_nonce: lifecycle_nonce,
        expected_authority_generation: 1,
        not_after_ts: current_ts() + 3_600,
    };
    instruction(
        26,
        &payload_bytes(&data),
        vec![
            AccountMeta::new(subscription, false),
            AccountMeta::new_readonly(plan, false),
            AccountMeta::new_readonly(plan_revision_registry, false),
            AccountMeta::new_readonly(lifecycle_registry, false),
            AccountMeta::new_readonly(consent_registry, false),
            AccountMeta::new_readonly(authority, false),
            AccountMeta::new(source, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(*merchant, true),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
            AccountMeta::new_readonly(event_authority(), false),
            AccountMeta::new_readonly(PROGRAM_ID, false),
        ],
    )
}

fn signed_transaction(litesvm: &crate::tests::utils::LiteSVM, _signers: &[&solana_keypair::Keypair], _payer: &Pubkey, _ix: &Instruction) -> Transaction {
    unreachable!("constructed in tests with mutable LiteSVM")
}

#[test]
fn vnext_plan_revision_rejects_delayed_aba_update() {
    let (litesvm, merchant) = &mut setup();
    let mint = init_mint(litesvm, TOKEN_PROGRAM_ID, MINT_DECIMALS, 1_000_000_000, None, &[]);
    let (create, plan, registry) = create_plan_ix(&merchant.pubkey(), mint, 7);
    build_and_send_transaction(litesvm, &[merchant], &merchant.pubkey(), &create).assert_ok();

    let stale = update_plan_ix(&merchant.pubkey(), plan, registry, 1, 1, "A", "C");
    let stale_signed = Transaction::new(
        &[merchant],
        Message::new(std::slice::from_ref(&stale), Some(&merchant.pubkey())),
        litesvm.latest_blockhash(),
    );

    let to_b = update_plan_ix(&merchant.pubkey(), plan, registry, 1, 1, "A", "B");
    let tx_b = Transaction::new(
        &[merchant],
        Message::new(std::slice::from_ref(&to_b), Some(&merchant.pubkey())),
        litesvm.latest_blockhash(),
    );
    litesvm.send_transaction(tx_b).assert_ok();

    let to_a = update_plan_ix(&merchant.pubkey(), plan, registry, 2, 2, "B", "A");
    let tx_a = Transaction::new(
        &[merchant],
        Message::new(std::slice::from_ref(&to_a), Some(&merchant.pubkey())),
        litesvm.latest_blockhash(),
    );
    litesvm.send_transaction(tx_a).assert_ok();

    litesvm.send_transaction(stale_signed).assert_err(SubscriptionsError::StalePlanRevision);

    let account = litesvm.get_account(&registry).unwrap();
    let state = PlanRevisionRegistry::load(&account.data).unwrap();
    let revision = state.revision;
    let nonce = state.action_nonce;
    assert_eq!(revision, 3);
    assert_eq!(nonce, 3);
}

#[test]
fn vnext_subscription_lifecycle_invalidates_delayed_subscribe_and_transfer() {
    let (litesvm, subscriber) = &mut setup();
    let merchant = crate::tests::utils::init_wallet(litesvm, 10_000_000_000);
    let mint = init_mint(litesvm, TOKEN_PROGRAM_ID, MINT_DECIMALS, 1_000_000_000, Some(subscriber.pubkey()), &[]);
    let source = init_aux_token_account(litesvm, mint, subscriber.pubkey(), 1_000_000);
    let destination = init_ata(litesvm, mint, merchant.pubkey(), 0);

    let subscriber_address = to_address(&subscriber.pubkey());
    let mint_address = to_address(&mint);
    let source_address = to_address(&source);
    let consent_registry = to_pubkey(AuthorityConsentRegistry::find_pda(&subscriber_address, &mint_address, &source_address).0);
    let authority = to_pubkey(VNextSubscriptionAuthority::find_pda(&subscriber_address, &mint_address, &source_address).0);
    let authorize = authorize_ix(&subscriber.pubkey(), consent_registry, authority, mint, source);
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &authorize).assert_ok();

    let (create, plan, plan_revision_registry) = create_plan_ix(&merchant.pubkey(), mint, 7);
    build_and_send_transaction(litesvm, &[&merchant], &merchant.pubkey(), &create).assert_ok();

    let plan_address = to_address(&plan);
    let subscription = to_pubkey(VNextSubscription::find_pda(&plan_address, &subscriber_address, &source_address).0);
    let lifecycle_registry = to_pubkey(
        SubscriptionLifecycleRegistry::find_pda(&plan_address, &subscriber_address, &source_address).0,
    );
    let plan_bump = VNextPlan::find_pda(&to_address(&merchant.pubkey()), 7).1;
    let plan_account = litesvm.get_account(&plan).unwrap();
    let plan_state = VNextPlan::load(&plan_account.data).unwrap();
    let created_at = plan_state.data.terms.created_at;

    let subscribe = subscribe_ix(
        &subscriber.pubkey(), &merchant.pubkey(), plan, plan_revision_registry, subscription,
        lifecycle_registry, consent_registry, authority, mint, source, plan_bump, created_at, 0, 0,
    );
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &subscribe).assert_ok();

    // Hold both a customer Subscribe and a merchant Pull signed against lifecycle
    // revision/nonce 1. They remain within their recent-blockhash window below.
    let stale_subscribe = subscribe_ix(
        &subscriber.pubkey(), &merchant.pubkey(), plan, plan_revision_registry, subscription,
        lifecycle_registry, consent_registry, authority, mint, source, plan_bump, created_at, 1, 1,
    );
    let stale_subscribe_signed = Transaction::new(
        &[subscriber],
        Message::new(std::slice::from_ref(&stale_subscribe), Some(&subscriber.pubkey())),
        litesvm.latest_blockhash(),
    );

    let fresh_transfer = transfer_ix(
        &subscriber.pubkey(), &merchant.pubkey(), plan, plan_revision_registry, subscription,
        lifecycle_registry, consent_registry, authority, source, destination, mint, 1, 1, 100_000,
    );
    let fresh_transfer_signed = Transaction::new(
        &[&merchant],
        Message::new(std::slice::from_ref(&fresh_transfer), Some(&merchant.pubkey())),
        litesvm.latest_blockhash(),
    );
    litesvm.send_transaction(fresh_transfer_signed).assert_ok();
    assert_eq!(fetch_account::<TokenAccount>(litesvm, &source).amount, 900_000);
    assert_eq!(get_ata_balance(litesvm, &destination), 100_000);

    // Ordinary cancellation and Resume each consume a distinct lifecycle revision.
    let cancel = cancel_ix(&subscriber.pubkey(), plan, plan_revision_registry, subscription, lifecycle_registry, 1, 1);
    let cancel_signed = Transaction::new(
        &[subscriber],
        Message::new(std::slice::from_ref(&cancel), Some(&subscriber.pubkey())),
        litesvm.latest_blockhash(),
    );
    litesvm.send_transaction(cancel_signed).assert_ok();

    let resume = resume_ix(
        &subscriber.pubkey(), plan, plan_revision_registry, subscription, lifecycle_registry,
        consent_registry, authority, mint, source, 2, 2,
    );
    let resume_signed = Transaction::new(
        &[subscriber],
        Message::new(std::slice::from_ref(&resume), Some(&subscriber.pubkey())),
        litesvm.latest_blockhash(),
    );
    litesvm.send_transaction(resume_signed).assert_ok();

    // CancelNow invalidates all previously signed pull/subscribe payloads.
    let cancel_now = cancel_now_ix(
        &subscriber.pubkey(), &merchant.pubkey(), plan, plan_revision_registry, subscription, lifecycle_registry, 3, 3,
    );
    let cancel_now_signed = Transaction::new(
        &[subscriber, &merchant],
        Message::new(std::slice::from_ref(&cancel_now), Some(&merchant.pubkey())),
        litesvm.latest_blockhash(),
    );
    litesvm.send_transaction(cancel_now_signed).assert_ok();

    let resubscribe = subscribe_ix(
        &subscriber.pubkey(), &merchant.pubkey(), plan, plan_revision_registry, subscription,
        lifecycle_registry, consent_registry, authority, mint, source, plan_bump, created_at, 4, 4,
    );
    let resubscribe_signed = Transaction::new(
        &[subscriber],
        Message::new(std::slice::from_ref(&resubscribe), Some(&subscriber.pubkey())),
        litesvm.latest_blockhash(),
    );
    litesvm.send_transaction(resubscribe_signed).assert_ok();

    litesvm
        .send_transaction(stale_subscribe_signed)
        .assert_err(SubscriptionsError::StaleSubscriptionLifecycleRevision);

    // The transfer snapshot is also stale even though the same PDA and source
    // account have been reused by the new Subscription incarnation.
    let stale_transfer = transfer_ix(
        &subscriber.pubkey(), &merchant.pubkey(), plan, plan_revision_registry, subscription,
        lifecycle_registry, consent_registry, authority, source, destination, mint, 1, 1, 200_000,
    );
    let stale_transfer_signed = Transaction::new(
        &[&merchant],
        Message::new(std::slice::from_ref(&stale_transfer), Some(&merchant.pubkey())),
        litesvm.latest_blockhash(),
    );
    litesvm
        .send_transaction(stale_transfer_signed)
        .assert_err(SubscriptionsError::StaleSubscriptionLifecycleRevision);

    let lifecycle_account = litesvm.get_account(&lifecycle_registry).unwrap();
    let lifecycle = SubscriptionLifecycleRegistry::load(&lifecycle_account.data).unwrap();
    let revision = lifecycle.revision;
    let nonce = lifecycle.action_nonce;
    assert_eq!(revision, 5);
    assert_eq!(nonce, 5);
    assert_eq!(fetch_account::<TokenAccount>(litesvm, &source).amount, 900_000);
    assert_eq!(get_ata_balance(litesvm, &destination), 100_000);
}
