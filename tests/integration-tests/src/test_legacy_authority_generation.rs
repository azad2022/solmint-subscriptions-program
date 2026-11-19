use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_program_pack::Pack;
use spl_token_2022_interface::state::Account as TokenAccount;

use crate::{
    tests::{
        asserts::TransactionResultExt,
        constants::{MINT_DECIMALS, PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_PROGRAM_ID},
        utils::{
            build_and_send_transaction, current_ts, get_ata_balance, init_ata, init_mint, init_wallet, setup,
            CreatePlan, CreateSubscription,
        },
    },
    event_engine::event_authority_pda, AuthorityConsentRegistry, SubscriptionAuthority, SubscriptionDelegation,
    SubscriptionsError, AUTHORITY_REGISTRY_ACTIVE, AUTHORITY_REGISTRY_REVOKED,
};

fn to_address(key: &Pubkey) -> pinocchio::Address {
    pinocchio::Address::from(key.to_bytes())
}

fn to_pubkey(address: pinocchio::Address) -> Pubkey {
    Pubkey::new_from_array(address.to_bytes())
}

fn derive_legacy_lineage(subscriber: &Pubkey, mint: &Pubkey, source: &Pubkey) -> (Pubkey, Pubkey) {
    let (registry, _) =
        AuthorityConsentRegistry::find_pda(&to_address(subscriber), &to_address(mint), &to_address(source));
    let (authority, _) = SubscriptionAuthority::find_pda(&to_address(subscriber), &to_address(mint));
    (to_pubkey(registry), to_pubkey(authority))
}

fn action_ix(
    discriminator: u8,
    subscriber: &Pubkey,
    registry: Pubkey,
    authority: Pubkey,
    mint: Pubkey,
    source: Pubkey,
    expected_generation: u64,
    expected_nonce: u64,
) -> Instruction {
    let deadline = current_ts() + 3_600;
    let mut data = vec![discriminator];
    data.extend_from_slice(&expected_generation.to_le_bytes());
    data.extend_from_slice(&expected_nonce.to_le_bytes());
    data.extend_from_slice(&deadline.to_le_bytes());
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*subscriber, true),
            AccountMeta::new(registry, false),
            AccountMeta::new(authority, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(source, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
        ],
        data,
    }
}

/// Seeds a byte-valid legacy Authority and the matching SPL Token delegate,
/// exactly as they exist after a v0.5.0 Init. This is a disposable LiteSVM
/// fixture; no Devnet or Mainnet state is read or mutated.
fn seed_legacy_authority(
    litesvm: &mut litesvm::LiteSVM,
    subscriber: &Pubkey,
    mint: &Pubkey,
    source: &Pubkey,
) -> (Pubkey, i64) {
    let subscriber_address = to_address(subscriber);
    let mint_address = to_address(mint);
    let (authority_address, bump) = SubscriptionAuthority::find_pda(&subscriber_address, &mint_address);
    let authority = to_pubkey(authority_address);
    let legacy_init_id = litesvm.get_sysvar::<solana_clock::Clock>().slot as i64;

    let mut data = vec![0u8; SubscriptionAuthority::LEN];
    SubscriptionAuthority::init(
        &mut data,
        &subscriber_address,
        &mint_address,
        &subscriber_address,
        bump,
        legacy_init_id,
    )
    .unwrap();
    let lamports = litesvm.minimum_balance_for_rent_exemption(data.len());
    litesvm
        .set_account(
            authority,
            Account { lamports, data, owner: PROGRAM_ID, executable: false, rent_epoch: 0 },
        )
        .unwrap();

    let mut token_account = litesvm.get_account(source).unwrap();
    let mut state = TokenAccount::unpack(&token_account.data).unwrap();
    state.delegate = Some(authority).into();
    state.delegated_amount = u64::MAX;
    TokenAccount::pack(state, &mut token_account.data).unwrap();
    litesvm.set_account(*source, token_account).unwrap();

    (authority, legacy_init_id)
}

#[test]
fn legacy_registry_bootstrap_preserves_old_authority_then_revoke_and_reauthorize_do_not_revive_it() {
    let (litesvm, subscriber) = &mut setup();
    let mint = init_mint(litesvm, TOKEN_PROGRAM_ID, MINT_DECIMALS, 1_000_000_000, Some(subscriber.pubkey()), &[]);
    let source = init_ata(litesvm, mint, subscriber.pubkey(), 1_000_000);
    let merchant = init_wallet(litesvm, 10_000_000_000);
    let merchant_ata = init_ata(litesvm, mint, merchant.pubkey(), 0);
    let (registry, authority) = derive_legacy_lineage(&subscriber.pubkey(), &mint, &source);
    let (seeded_authority, old_init_id) = seed_legacy_authority(litesvm, &subscriber.pubkey(), &mint, &source);
    assert_eq!(authority, seeded_authority);

    // Construct a real v0.5.0-shaped Plan and Subscription fixture using the
    // exact production account encoders. The Subscription header stores the
    // old non-negative Authority init_id and must survive the bootstrap intact.
    let (create_plan, legacy_plan) = CreatePlan::new(litesvm, &merchant, mint)
        .plan_id(77)
        .amount(100_000)
        .period_hours(1)
        .execute();
    create_plan.assert_ok();
    let plan_data = litesvm.get_account(&legacy_plan).unwrap();
    let plan = crate::Plan::load(&plan_data.data).unwrap();
    let legacy_terms = plan.data.terms;
    let period_start = litesvm.get_sysvar::<solana_clock::Clock>().unix_timestamp;
    let legacy_subscription = CreateSubscription::new(
        litesvm,
        legacy_plan,
        subscriber.pubkey(),
        mint,
        period_start,
    )
    .terms(legacy_terms)
    .execute();
    let subscription_before_bootstrap = litesvm.get_account(&legacy_subscription).unwrap().data;

    // First signed V2 action is a migration bootstrap only: it must preserve the
    // pre-existing Authority bytes/init_id and current SPL delegate allowance.
    let bootstrap = action_ix(28, &subscriber.pubkey(), registry, authority, mint, source, 0, 0);
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &bootstrap).assert_ok();

    let registry_account = litesvm.get_account(&registry).unwrap();
    let registry_state = AuthorityConsentRegistry::load(&registry_account.data).unwrap();
    let bootstrap_status = registry_state.status;
    let bootstrap_generation = registry_state.authority_generation;
    let bootstrap_authorize_nonce = registry_state.authorize_nonce;
    assert_eq!(bootstrap_status, AUTHORITY_REGISTRY_ACTIVE);
    assert_eq!(bootstrap_generation, 1);
    assert_eq!(bootstrap_authorize_nonce, 1);

    let authority_account = litesvm.get_account(&authority).unwrap();
    let authority_bytes_before_bootstrap = authority_account.data.clone();
    let authority_state = SubscriptionAuthority::load(&authority_account.data).unwrap();
    let migrated_init_id = authority_state.init_id;
    assert_eq!(migrated_init_id, old_init_id);
    assert_eq!(authority_bytes_before_bootstrap, authority_account.data);
    let subscription_after_bootstrap = litesvm.get_account(&legacy_subscription).unwrap().data;
    assert_eq!(subscription_after_bootstrap, subscription_before_bootstrap);
    let subscription_state = SubscriptionDelegation::load(&subscription_after_bootstrap).unwrap();
    let subscription_init_id = subscription_state.header.init_id;
    assert_eq!(subscription_init_id, old_init_id);
    let token_after_bootstrap = crate::tests::utils::fetch_account::<TokenAccount>(litesvm, &source);
    assert_eq!(token_after_bootstrap.delegate, Some(authority));
    assert_eq!(token_after_bootstrap.delegated_amount, u64::MAX);

    // Prove the existing legacy Subscription remains usable through the new
    // generation-bound transfer discriminator. This keeps original period
    // accounting and destination validation in the old audited transfer core.
    let transfer_amount = 10_000u64;
    let event_authority = Pubkey::new_from_array(event_authority_pda::ID.to_bytes());
    let mut transfer_data = vec![30u8];
    transfer_data.extend_from_slice(&transfer_amount.to_le_bytes());
    transfer_data.extend_from_slice(subscriber.pubkey().as_ref());
    transfer_data.extend_from_slice(mint.as_ref());
    transfer_data.extend_from_slice(&period_start.to_le_bytes());
    transfer_data.extend_from_slice(&0u64.to_le_bytes());
    transfer_data.extend_from_slice(&1u64.to_le_bytes());
    transfer_data.extend_from_slice(&(period_start + 3_600).to_le_bytes());
    let transfer_ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(legacy_subscription, false),
            AccountMeta::new_readonly(legacy_plan, false),
            AccountMeta::new_readonly(authority, false),
            AccountMeta::new(source, false),
            AccountMeta::new(merchant_ata, false),
            AccountMeta::new_readonly(merchant.pubkey(), true),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
            AccountMeta::new_readonly(event_authority, false),
            AccountMeta::new_readonly(PROGRAM_ID, false),
            AccountMeta::new_readonly(registry, false),
        ],
        data: transfer_data,
    };
    let merchant_before = get_ata_balance(litesvm, &merchant_ata);
    build_and_send_transaction(litesvm, &[&merchant], &merchant.pubkey(), &transfer_ix).assert_ok();
    assert_eq!(get_ata_balance(litesvm, &merchant_ata), merchant_before + transfer_amount);
    let after_transfer = litesvm.get_account(&legacy_subscription).unwrap();
    let after_transfer_state = SubscriptionDelegation::load(&after_transfer.data).unwrap();
    let pulled_amount = after_transfer_state.amount_pulled_in_period;
    assert_eq!(pulled_amount, transfer_amount);

    // Revocation advances the durable lineage, clears the exact delegate and
    // closes only the legacy Authority; existing subscription PDAs are not
    // deleted or rewritten by this lifecycle transition.
    let revoke = action_ix(29, &subscriber.pubkey(), registry, authority, mint, source, 1, 0);
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &revoke).assert_ok();

    let registry_after_revoke = litesvm.get_account(&registry).unwrap();
    let state_after_revoke = AuthorityConsentRegistry::load(&registry_after_revoke.data).unwrap();
    let revoke_status = state_after_revoke.status;
    let revoke_generation = state_after_revoke.authority_generation;
    let revoke_nonce = state_after_revoke.revoke_nonce;
    assert_eq!(revoke_status, AUTHORITY_REGISTRY_REVOKED);
    assert_eq!(revoke_generation, 2);
    assert_eq!(revoke_nonce, 1);
    assert!(litesvm.get_account(&authority).is_none());
    assert!(litesvm.get_account(&legacy_subscription).is_some(), "legacy Subscription evidence must remain readable after revoke");
    let token_after_revoke = crate::tests::utils::fetch_account::<TokenAccount>(litesvm, &source);
    assert!(token_after_revoke.delegate.is_none());
    assert_eq!(token_after_revoke.delegated_amount, 0);

    // The same legacy Subscription remains on-chain as immutable evidence but
    // the versioned pull path must reject collection after Registry revocation.
    let source_before_replay = token_after_revoke.amount;
    let merchant_before_replay = get_ata_balance(litesvm, &merchant_ata);
    let subscription_before_replay = litesvm.get_account(&legacy_subscription).unwrap().data;
    let mut stale_transfer_data = vec![30u8];
    stale_transfer_data.extend_from_slice(&transfer_amount.to_le_bytes());
    stale_transfer_data.extend_from_slice(subscriber.pubkey().as_ref());
    stale_transfer_data.extend_from_slice(mint.as_ref());
    stale_transfer_data.extend_from_slice(&period_start.to_le_bytes());
    stale_transfer_data.extend_from_slice(&transfer_amount.to_le_bytes());
    stale_transfer_data.extend_from_slice(&1u64.to_le_bytes());
    stale_transfer_data.extend_from_slice(&(period_start + 3_600).to_le_bytes());
    let stale_transfer_ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: transfer_ix.accounts.clone(),
        data: stale_transfer_data,
    };
    build_and_send_transaction(litesvm, &[&merchant], &merchant.pubkey(), &stale_transfer_ix)
        .assert_err(SubscriptionsError::StaleAuthorityGeneration);
    assert_eq!(
        crate::tests::utils::fetch_account::<TokenAccount>(litesvm, &source).amount,
        source_before_replay
    );
    assert_eq!(get_ata_balance(litesvm, &merchant_ata), merchant_before_replay);
    assert_eq!(
        litesvm.get_account(&legacy_subscription).unwrap().data,
        subscription_before_replay
    );

    // Replaying the old, validly signed bootstrap payload with a fresh blockhash
    // must not recreate the previous generation.
    let stale_replay = Transaction::new(
        &[&*subscriber],
        Message::new(std::slice::from_ref(&bootstrap), Some(&subscriber.pubkey())),
        litesvm.latest_blockhash(),
    );
    litesvm.send_transaction(stale_replay).assert_err(SubscriptionsError::StaleAuthorityGeneration);

    // A revoked canonical-ATA lineage is permanently closed to Legacy
    // reauthorization. Otherwise the Program would grant a max delegate for
    // which the generation-bound Legacy Subscribe path is intentionally absent.
    let reauthorize_legacy = action_ix(28, &subscriber.pubkey(), registry, authority, mint, source, 2, 1);
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &reauthorize_legacy)
        .assert_err(SubscriptionsError::LegacyInstructionDisabled);
    assert!(litesvm.get_account(&authority).is_none());

    let registry_after_reauth = litesvm.get_account(&registry).unwrap();
    let final_registry = AuthorityConsentRegistry::load(&registry_after_reauth.data).unwrap();
    let final_status = final_registry.status;
    let final_generation = final_registry.authority_generation;
    let final_authorize_nonce = final_registry.authorize_nonce;
    assert_eq!(final_status, AUTHORITY_REGISTRY_REVOKED);
    assert_eq!(final_generation, 2);
    assert_eq!(final_authorize_nonce, 1);
    let token_after_reauth = crate::tests::utils::fetch_account::<TokenAccount>(litesvm, &source);
    assert!(token_after_reauth.delegate.is_none());
    assert_eq!(token_after_reauth.delegated_amount, 0);
    assert_ne!(old_init_id, i64::MIN);
}

#[test]
fn legacy_revoke_tombstone_invalidates_a_previously_signed_unsubmitted_authorization() {
    let (litesvm, subscriber) = &mut setup();
    let mint = init_mint(litesvm, TOKEN_PROGRAM_ID, MINT_DECIMALS, 1_000_000_000, Some(subscriber.pubkey()), &[]);
    let source = init_ata(litesvm, mint, subscriber.pubkey(), 1_000_000);
    let (registry, authority) = derive_legacy_lineage(&subscriber.pubkey(), &mint, &source);

    // This action is signed at generation zero and deliberately withheld.
    let delayed_authorize_ix = action_ix(28, &subscriber.pubkey(), registry, authority, mint, source, 0, 0);
    let delayed_authorize = Transaction::new(
        &[&*subscriber],
        Message::new(std::slice::from_ref(&delayed_authorize_ix), Some(&subscriber.pubkey())),
        litesvm.latest_blockhash(),
    );

    // A customer-signed tombstone wins first, even though neither Registry nor
    // Authority existed when the delayed authorization was signed.
    let revoke = action_ix(29, &subscriber.pubkey(), registry, authority, mint, source, 1, 0);
    let revoke_signed = Transaction::new(
        &[&*subscriber],
        Message::new(std::slice::from_ref(&revoke), Some(&subscriber.pubkey())),
        litesvm.latest_blockhash(),
    );
    litesvm.send_transaction(revoke_signed).assert_ok();

    let registry_account = litesvm.get_account(&registry).unwrap();
    let registry_state = AuthorityConsentRegistry::load(&registry_account.data).unwrap();
    let tombstone_status = registry_state.status;
    let tombstone_generation = registry_state.authority_generation;
    assert_eq!(tombstone_status, AUTHORITY_REGISTRY_REVOKED);
    assert_eq!(tombstone_generation, 2);
    assert!(litesvm.get_account(&authority).is_none());

    litesvm.send_transaction(delayed_authorize).assert_err(SubscriptionsError::StaleAuthorityGeneration);
    litesvm.expire_blockhash();

    // Re-sign the identical stale payload using a fresh blockhash. Rejection is
    // now attributable to the permanent Registry generation, not blockhash expiry.
    let fresh_blockhash_replay = Transaction::new(
        &[&*subscriber],
        Message::new(std::slice::from_ref(&delayed_authorize_ix), Some(&subscriber.pubkey())),
        litesvm.latest_blockhash(),
    );
    litesvm.send_transaction(fresh_blockhash_replay).assert_err(SubscriptionsError::StaleAuthorityGeneration);

    let final_registry_account = litesvm.get_account(&registry).unwrap();
    let final_registry = AuthorityConsentRegistry::load(&final_registry_account.data).unwrap();
    let final_generation = final_registry.authority_generation;
    let final_status = final_registry.status;
    assert_eq!(final_generation, 2);
    assert_eq!(final_status, AUTHORITY_REGISTRY_REVOKED);
    assert!(litesvm.get_account(&authority).is_none());
    let token = crate::tests::utils::fetch_account::<TokenAccount>(litesvm, &source);
    assert!(token.delegate.is_none());
    assert_eq!(token.delegated_amount, 0);
}

#[test]
fn unversioned_legacy_authority_and_permission_paths_are_closed_at_dispatch() {
    let (litesvm, subscriber) = &mut setup();
    let cases = [
        (0u8, 0usize), // InitSubscriptionAuthority
        (1u8, crate::instructions::create_fixed_delegation::CreateFixedDelegationData::LEN),
        (2u8, crate::instructions::create_recurring_delegation::CreateRecurringDelegationData::LEN),
        (4u8, crate::instructions::helpers::TransferData::LEN), // TransferFixed
        (5u8, crate::instructions::helpers::TransferData::LEN), // TransferRecurring
        (6u8, 0usize), // CloseSubscriptionAuthority
        (10u8, crate::instructions::helpers::TransferData::LEN), // TransferSubscription
        (11u8, crate::instructions::subscribe::SubscribeData::LEN), // Subscribe
        (14u8, 0usize), // RevokeSubscriptionAuthority
    ];

    for (discriminator, payload_len) in cases {
        let mut data = vec![discriminator];
        data.resize(1 + payload_len, 0);
        let ix = Instruction { program_id: PROGRAM_ID, accounts: vec![], data };
        build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &ix)
            .assert_err(SubscriptionsError::LegacyInstructionDisabled);
    }
}
