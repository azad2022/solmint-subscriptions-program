use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_nonce::{state::State as NonceState, versions::Versions as NonceVersions};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_system_interface::instruction::{advance_nonce_account, create_nonce_account};
use solana_transaction::Transaction;
use spl_token_2022_interface::state::Account as TokenAccount;

use crate::{
    tests::{
        asserts::TransactionResultExt,
        constants::{MINT_DECIMALS, PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_PROGRAM_ID},
        utils::{build_and_send_transaction, fetch_account, init_ata, init_aux_token_account, init_mint, setup},
    },
    AuthorityConsentRegistry, SubscriptionsError, VNextSubscriptionAuthority, AUTHORITY_REGISTRY_ACTIVE,
    AUTHORITY_REGISTRY_REVOKED,
};

fn create_initialized_nonce_account(
    litesvm: &mut litesvm::LiteSVM,
    payer: &Keypair,
    nonce_authority: &Keypair,
) -> Pubkey {
    let nonce_account = Keypair::new();
    let nonce_lamports = litesvm.minimum_balance_for_rent_exemption(NonceState::size());
    let create_instructions =
        create_nonce_account(&payer.pubkey(), &nonce_account.pubkey(), &nonce_authority.pubkey(), nonce_lamports);
    let create_transaction = Transaction::new(
        &[payer, &nonce_account],
        Message::new(&create_instructions, Some(&payer.pubkey())),
        litesvm.latest_blockhash(),
    );
    litesvm.send_transaction(create_transaction).assert_ok();

    let account = litesvm.get_account(&nonce_account.pubkey()).unwrap();
    assert_eq!(account.owner, SYSTEM_PROGRAM_ID);
    let versions: NonceVersions = bincode::deserialize(&account.data).unwrap();
    match versions.state() {
        NonceState::Initialized(data) => assert_eq!(data.authority, nonce_authority.pubkey()),
        NonceState::Uninitialized => panic!("System Program did not initialize the nonce account"),
    }

    nonce_account.pubkey()
}

fn read_initialized_nonce_hash(litesvm: &litesvm::LiteSVM, nonce_account: &Pubkey) -> Hash {
    let account = litesvm.get_account(nonce_account).unwrap();
    assert_eq!(account.owner, SYSTEM_PROGRAM_ID);
    let versions: NonceVersions = bincode::deserialize(&account.data).unwrap();
    match versions.state() {
        NonceState::Initialized(data) => data.blockhash(),
        NonceState::Uninitialized => panic!("Durable nonce account is not initialized"),
    }
}

fn sign_durable_nonce_authorization(
    subscriber: &Keypair,
    nonce_authority: &Keypair,
    nonce_account: &Pubkey,
    nonce_hash: Hash,
    authorize: &Instruction,
) -> Transaction {
    let instructions = [advance_nonce_account(nonce_account, &nonce_authority.pubkey()), authorize.clone()];
    assert_eq!(instructions[0].program_id, SYSTEM_PROGRAM_ID);
    Transaction::new(
        &[subscriber, nonce_authority],
        Message::new(&instructions, Some(&subscriber.pubkey())),
        nonce_hash,
    )
}

fn to_address(key: &Pubkey) -> pinocchio::Address {
    pinocchio::Address::from(key.to_bytes())
}

fn to_pubkey(address: pinocchio::Address) -> Pubkey {
    Pubkey::new_from_array(address.to_bytes())
}

fn derive_vnext_accounts(subscriber: &Pubkey, mint: &Pubkey, source: &Pubkey) -> (Pubkey, Pubkey) {
    let subscriber = to_address(subscriber);
    let mint = to_address(mint);
    let source = to_address(source);

    let registry = AuthorityConsentRegistry::find_pda(&subscriber, &mint, &source).0;
    let authority = VNextSubscriptionAuthority::find_pda(&subscriber, &mint, &source).0;

    (to_pubkey(registry), to_pubkey(authority))
}

fn authority_action_data(
    discriminator: u8,
    expected_generation: u64,
    expected_nonce: u64,
    not_after_ts: i64,
) -> Vec<u8> {
    [
        vec![discriminator],
        expected_generation.to_le_bytes().to_vec(),
        expected_nonce.to_le_bytes().to_vec(),
        not_after_ts.to_le_bytes().to_vec(),
    ]
    .concat()
}

fn authorize_ix(
    subscriber: &Pubkey,
    registry: Pubkey,
    authority: Pubkey,
    mint: Pubkey,
    source: Pubkey,
    expected_generation: u64,
    expected_nonce: u64,
    not_after_ts: i64,
) -> Instruction {
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
        data: authority_action_data(18, expected_generation, expected_nonce, not_after_ts),
    }
}

fn revoke_ix(
    subscriber: &Pubkey,
    registry: Pubkey,
    authority: Pubkey,
    mint: Pubkey,
    source: Pubkey,
    expected_generation: u64,
    expected_nonce: u64,
    not_after_ts: i64,
) -> Instruction {
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
        data: authority_action_data(19, expected_generation, expected_nonce, not_after_ts),
    }
}

#[test]
fn vnext_authorize_and_revoke_preserve_persistent_generation() {
    let (litesvm, subscriber) = &mut setup();
    let mint = init_mint(litesvm, TOKEN_PROGRAM_ID, MINT_DECIMALS, 1_000_000_000, Some(subscriber.pubkey()), &[]);
    let source = init_aux_token_account(litesvm, mint, subscriber.pubkey(), 1_000_000);
    let (registry, authority) = derive_vnext_accounts(&subscriber.pubkey(), &mint, &source);
    let deadline = crate::tests::utils::current_ts() + 3_600;

    let authorize = authorize_ix(&subscriber.pubkey(), registry, authority, mint, source, 0, 0, deadline);
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &authorize).assert_ok();

    let registry_account = litesvm.get_account(&registry).unwrap();
    let registry_state = AuthorityConsentRegistry::load(&registry_account.data).unwrap();
    let generation = registry_state.authority_generation;
    let authorize_nonce = registry_state.authorize_nonce;
    let status = registry_state.status;
    assert_eq!(generation, 1);
    assert_eq!(authorize_nonce, 1);
    assert_eq!(status, AUTHORITY_REGISTRY_ACTIVE);

    let authority_account = litesvm.get_account(&authority).unwrap();
    let authority_state = VNextSubscriptionAuthority::load(&authority_account.data).unwrap();
    let authority_generation = authority_state.authority_generation;
    let authority_source = authority_state.source_token_account;
    assert_eq!(authority_generation, 1);
    assert_eq!(authority_source.to_bytes(), source.to_bytes());

    let source_state = fetch_account::<TokenAccount>(litesvm, &source);
    assert!(source_state.delegate.is_some());
    assert_eq!(source_state.delegate.unwrap(), authority);
    assert_eq!(source_state.delegated_amount, u64::MAX);

    let revoke = revoke_ix(
        &subscriber.pubkey(),
        registry,
        authority,
        mint,
        source,
        1,
        0,
        crate::tests::utils::current_ts() + 3_600,
    );
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &revoke).assert_ok();

    let registry_account = litesvm.get_account(&registry).unwrap();
    let registry_state = AuthorityConsentRegistry::load(&registry_account.data).unwrap();
    let generation = registry_state.authority_generation;
    let revoke_nonce = registry_state.revoke_nonce;
    let status = registry_state.status;
    assert_eq!(generation, 2);
    assert_eq!(revoke_nonce, 1);
    assert_eq!(status, AUTHORITY_REGISTRY_REVOKED);

    let source_state = fetch_account::<TokenAccount>(litesvm, &source);
    assert!(source_state.delegate.is_none());
    assert_eq!(source_state.delegated_amount, 0);
    assert!(litesvm.get_account(&authority).is_none());
}

#[test]
fn vnext_revoke_tombstone_preempts_unsubmitted_authorization() {
    let (litesvm, subscriber) = &mut setup();
    let mint = init_mint(litesvm, TOKEN_PROGRAM_ID, MINT_DECIMALS, 1_000_000_000, Some(subscriber.pubkey()), &[]);
    let source = init_aux_token_account(litesvm, mint, subscriber.pubkey(), 1_000_000);
    let (registry, authority) = derive_vnext_accounts(&subscriber.pubkey(), &mint, &source);

    // Keep a real customer-signed authorization transaction pending while the
    // revoke tombstone is submitted with the same still-valid recent blockhash.
    let stale_authorize = authorize_ix(
        &subscriber.pubkey(),
        registry,
        authority,
        mint,
        source,
        0,
        0,
        crate::tests::utils::current_ts() + 3_600,
    );
    let stale_signed = Transaction::new(
        &[&*subscriber],
        Message::new(std::slice::from_ref(&stale_authorize), Some(&subscriber.pubkey())),
        litesvm.latest_blockhash(),
    );

    let revoke = revoke_ix(
        &subscriber.pubkey(),
        registry,
        authority,
        mint,
        source,
        1,
        0,
        crate::tests::utils::current_ts() + 3_600,
    );
    let revoke_signed = Transaction::new(
        &[&*subscriber],
        Message::new(std::slice::from_ref(&revoke), Some(&subscriber.pubkey())),
        litesvm.latest_blockhash(),
    );
    litesvm.send_transaction(revoke_signed).assert_ok();

    let registry_account = litesvm.get_account(&registry).unwrap();
    let registry_state = AuthorityConsentRegistry::load(&registry_account.data).unwrap();
    let generation = registry_state.authority_generation;
    let status = registry_state.status;
    assert_eq!(generation, 2);
    assert_eq!(status, AUTHORITY_REGISTRY_REVOKED);
    assert!(litesvm.get_account(&authority).is_none());

    // The exact transaction signed before revoke is still submitted after
    // invalidation. It must fail on the persistent generation tombstone.
    litesvm.send_transaction(stale_signed).assert_err(SubscriptionsError::StaleAuthorityGeneration);

    // Re-sign the same stale instruction with a fresh recent blockhash. This
    // rules out blockhash expiry as the reason the replay is rejected.
    litesvm.expire_blockhash();
    let replay_signed = Transaction::new(
        &[&*subscriber],
        Message::new(std::slice::from_ref(&stale_authorize), Some(&subscriber.pubkey())),
        litesvm.latest_blockhash(),
    );
    litesvm.send_transaction(replay_signed).assert_err(SubscriptionsError::StaleAuthorityGeneration);

    let source_state = fetch_account::<TokenAccount>(litesvm, &source);
    assert!(source_state.delegate.is_none());
    assert!(litesvm.get_account(&authority).is_none());
}

#[test]
fn vnext_authorize_rejects_a_signed_action_after_its_onchain_deadline() {
    let (litesvm, subscriber) = &mut setup();
    let mint = init_mint(litesvm, TOKEN_PROGRAM_ID, MINT_DECIMALS, 1_000_000_000, Some(subscriber.pubkey()), &[]);
    let source = init_aux_token_account(litesvm, mint, subscriber.pubkey(), 1_000_000);
    let (registry, authority) = derive_vnext_accounts(&subscriber.pubkey(), &mint, &source);

    let deadline = crate::tests::utils::current_ts() + 60;
    let authorize = authorize_ix(&subscriber.pubkey(), registry, authority, mint, source, 0, 0, deadline);
    let signed = Transaction::new(
        &[&*subscriber],
        Message::new(std::slice::from_ref(&authorize), Some(&subscriber.pubkey())),
        litesvm.latest_blockhash(),
    );

    // Move only the on-chain Unix clock. The recent blockhash/slot remains
    // valid, so the Program deadline—not transaction expiry—must reject it.
    let original_slot = litesvm.get_sysvar::<solana_clock::Clock>().slot;
    crate::tests::utils::set_clock(litesvm, deadline + 1);
    assert_eq!(litesvm.get_sysvar::<solana_clock::Clock>().slot, original_slot);

    litesvm.send_transaction(signed).assert_err(SubscriptionsError::AuthorityActionExpired);

    assert!(litesvm.get_account(&registry).is_none());
    assert!(litesvm.get_account(&authority).is_none());
    let source_state = fetch_account::<TokenAccount>(litesvm, &source);
    assert_eq!(source_state.amount, 1_000_000);
    assert!(source_state.delegate.is_none());
}

#[test]
fn vnext_authorize_rejects_ata_source_account() {
    let (litesvm, subscriber) = &mut setup();
    let mint = init_mint(litesvm, TOKEN_PROGRAM_ID, MINT_DECIMALS, 1_000_000_000, Some(subscriber.pubkey()), &[]);
    let ata = init_ata(litesvm, mint, subscriber.pubkey(), 1_000_000);
    let (registry, authority) = derive_vnext_accounts(&subscriber.pubkey(), &mint, &ata);

    let authorize = authorize_ix(
        &subscriber.pubkey(),
        registry,
        authority,
        mint,
        ata,
        0,
        0,
        crate::tests::utils::current_ts() + 3_600,
    );
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &authorize)
        .assert_err(SubscriptionsError::NonAssociatedSourceAccountRequired);

    let revoke = revoke_ix(
        &subscriber.pubkey(),
        registry,
        authority,
        mint,
        ata,
        1,
        0,
        crate::tests::utils::current_ts() + 3_600,
    );
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &revoke)
        .assert_err(SubscriptionsError::NonAssociatedSourceAccountRequired);
}

#[test]
fn vnext_authority_consent_is_bound_to_exact_non_ata_source_account() {
    let (litesvm, subscriber) = &mut setup();
    let mint = init_mint(litesvm, TOKEN_PROGRAM_ID, MINT_DECIMALS, 1_000_000_000, Some(subscriber.pubkey()), &[]);
    let source_a = init_aux_token_account(litesvm, mint, subscriber.pubkey(), 1_000_000);
    let source_b = init_aux_token_account(litesvm, mint, subscriber.pubkey(), 1_000_000);
    assert_ne!(source_a, source_b);

    let (registry_a, authority_a) = derive_vnext_accounts(&subscriber.pubkey(), &mint, &source_a);
    let (registry_b, authority_b) = derive_vnext_accounts(&subscriber.pubkey(), &mint, &source_b);
    assert_ne!(registry_a, registry_b);
    assert_ne!(authority_a, authority_b);

    let deadline = crate::tests::utils::current_ts() + 3_600;
    let authorize_a = authorize_ix(&subscriber.pubkey(), registry_a, authority_a, mint, source_a, 0, 0, deadline);
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &authorize_a).assert_ok();

    let source_a_state = fetch_account::<TokenAccount>(litesvm, &source_a);
    assert_eq!(source_a_state.delegate.unwrap(), authority_a);
    assert_eq!(source_a_state.delegated_amount, u64::MAX);
    assert!(litesvm.get_account(&registry_b).is_none());
    assert!(litesvm.get_account(&authority_b).is_none());

    // A Registry for source B cannot be paired with source A's Authority.
    let cross_bound_authorize =
        authorize_ix(&subscriber.pubkey(), registry_b, authority_a, mint, source_b, 0, 0, deadline);
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &cross_bound_authorize)
        .assert_err(SubscriptionsError::VNextAuthorityInvalidPda);

    // Source A's Registry cannot be replayed against source B, including for revoke.
    let substituted_authorize =
        authorize_ix(&subscriber.pubkey(), registry_a, authority_a, mint, source_b, 0, 0, deadline);
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &substituted_authorize)
        .assert_err(SubscriptionsError::AuthorityConsentRegistryInvalidPda);

    let substituted_revoke = revoke_ix(&subscriber.pubkey(), registry_a, authority_a, mint, source_b, 1, 0, deadline);
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &substituted_revoke)
        .assert_err(SubscriptionsError::AuthorityConsentRegistryInvalidPda);

    let source_b_state = fetch_account::<TokenAccount>(litesvm, &source_b);
    assert!(source_b_state.delegate.is_none());
    assert_eq!(source_b_state.amount, 1_000_000);
    assert!(litesvm.get_account(&registry_b).is_none());
    assert!(litesvm.get_account(&authority_b).is_none());

    // The second source can be authorized independently; revoking A must not
    // revoke B because the persistent consent lineage is tuple-bound.
    let authorize_b = authorize_ix(&subscriber.pubkey(), registry_b, authority_b, mint, source_b, 0, 0, deadline);
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &authorize_b).assert_ok();

    let revoke_a = revoke_ix(
        &subscriber.pubkey(),
        registry_a,
        authority_a,
        mint,
        source_a,
        1,
        0,
        crate::tests::utils::current_ts() + 3_600,
    );
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &revoke_a).assert_ok();

    let source_a_after_revoke = fetch_account::<TokenAccount>(litesvm, &source_a);
    let source_b_after_revoke = fetch_account::<TokenAccount>(litesvm, &source_b);
    assert!(source_a_after_revoke.delegate.is_none());
    assert_eq!(source_a_after_revoke.delegated_amount, 0);
    assert_eq!(source_b_after_revoke.delegate.unwrap(), authority_b);
    assert_eq!(source_b_after_revoke.delegated_amount, u64::MAX);

    let registry_a_account = litesvm.get_account(&registry_a).unwrap();
    let registry_b_account = litesvm.get_account(&registry_b).unwrap();
    let registry_a_state = AuthorityConsentRegistry::load(&registry_a_account.data).unwrap();
    let registry_b_state = AuthorityConsentRegistry::load(&registry_b_account.data).unwrap();
    let registry_a_generation = registry_a_state.authority_generation;
    let registry_a_status = registry_a_state.status;
    let registry_b_generation = registry_b_state.authority_generation;
    let registry_b_status = registry_b_state.status;
    assert_eq!(registry_a_generation, 2);
    assert_eq!(registry_a_status, AUTHORITY_REGISTRY_REVOKED);
    assert_eq!(registry_b_generation, 1);
    assert_eq!(registry_b_status, AUTHORITY_REGISTRY_ACTIVE);
}

#[test]
fn vnext_authority_consent_rejects_multiple_remaining_accounts_atomically() {
    let (litesvm, subscriber) = &mut setup();
    let mint = init_mint(litesvm, TOKEN_PROGRAM_ID, MINT_DECIMALS, 1_000_000_000, Some(subscriber.pubkey()), &[]);
    let source = init_aux_token_account(litesvm, mint, subscriber.pubkey(), 1_000_000);
    let (registry, authority) = derive_vnext_accounts(&subscriber.pubkey(), &mint, &source);
    let extra_a = crate::tests::utils::init_wallet(litesvm, 1_000_000);
    let extra_b = crate::tests::utils::init_wallet(litesvm, 1_000_000);
    let deadline = crate::tests::utils::current_ts() + 3_600;

    // More than one trailing account must be rejected before Registry,
    // Authority, or token-delegate state is initialized.
    let mut malformed_authorize = authorize_ix(&subscriber.pubkey(), registry, authority, mint, source, 0, 0, deadline);
    malformed_authorize.accounts.push(AccountMeta::new_readonly(extra_a.pubkey(), false));
    malformed_authorize.accounts.push(AccountMeta::new_readonly(extra_b.pubkey(), false));
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &malformed_authorize)
        .assert_err(SubscriptionsError::InvalidInstructionData);

    assert!(litesvm.get_account(&registry).is_none());
    assert!(litesvm.get_account(&authority).is_none());
    let source_after_failed_authorize = fetch_account::<TokenAccount>(litesvm, &source);
    assert!(source_after_failed_authorize.delegate.is_none());
    assert_eq!(source_after_failed_authorize.amount, 1_000_000);

    // A malformed Revoke must not advance the Registry or remove an existing
    // delegate. The same exact one-account tail policy applies to both paths.
    let authorize = authorize_ix(&subscriber.pubkey(), registry, authority, mint, source, 0, 0, deadline);
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &authorize).assert_ok();

    let mut malformed_revoke = revoke_ix(
        &subscriber.pubkey(),
        registry,
        authority,
        mint,
        source,
        1,
        0,
        crate::tests::utils::current_ts() + 3_600,
    );
    malformed_revoke.accounts.push(AccountMeta::new_readonly(extra_a.pubkey(), false));
    malformed_revoke.accounts.push(AccountMeta::new_readonly(extra_b.pubkey(), false));
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &malformed_revoke)
        .assert_err(SubscriptionsError::InvalidInstructionData);

    let registry_account = litesvm.get_account(&registry).unwrap();
    let registry_state = AuthorityConsentRegistry::load(&registry_account.data).unwrap();
    let generation = registry_state.authority_generation;
    let authorize_nonce = registry_state.authorize_nonce;
    let revoke_nonce = registry_state.revoke_nonce;
    let status = registry_state.status;
    assert_eq!(generation, 1);
    assert_eq!(authorize_nonce, 1);
    assert_eq!(revoke_nonce, 0);
    assert_eq!(status, AUTHORITY_REGISTRY_ACTIVE);

    assert!(litesvm.get_account(&authority).is_some());
    let source_after_failed_revoke = fetch_account::<TokenAccount>(litesvm, &source);
    assert_eq!(source_after_failed_revoke.delegate.unwrap(), authority);
    assert_eq!(source_after_failed_revoke.delegated_amount, u64::MAX);
}

#[test]
fn vnext_durable_nonce_authorization_is_rejected_after_generation_invalidation() {
    let (litesvm, subscriber) = &mut setup();
    let mint = init_mint(litesvm, TOKEN_PROGRAM_ID, MINT_DECIMALS, 1_000_000_000, Some(subscriber.pubkey()), &[]);
    let source = init_aux_token_account(litesvm, mint, subscriber.pubkey(), 1_000_000);
    let (registry, authority) = derive_vnext_accounts(&subscriber.pubkey(), &mint, &source);

    let nonce_authority = Keypair::new();
    let nonce_account = create_initialized_nonce_account(litesvm, subscriber, &nonce_authority);
    let original_nonce_hash = read_initialized_nonce_hash(litesvm, &nonce_account);
    let deadline = crate::tests::utils::current_ts() + 3_600;
    let authorize = authorize_ix(&subscriber.pubkey(), registry, authority, mint, source, 0, 0, deadline);

    // Retain both a regular-blockhash transaction and a genuine durable-nonce
    // transaction before the subscriber invalidates the Authority generation.
    let recent_blockhash_transaction = Transaction::new(
        &[&*subscriber],
        Message::new(std::slice::from_ref(&authorize), Some(&subscriber.pubkey())),
        litesvm.latest_blockhash(),
    );
    let durable_nonce_transaction =
        sign_durable_nonce_authorization(subscriber, &nonce_authority, &nonce_account, original_nonce_hash, &authorize);
    let durable_nonce_replay = durable_nonce_transaction.clone();

    let revoke = revoke_ix(
        &subscriber.pubkey(),
        registry,
        authority,
        mint,
        source,
        1,
        0,
        crate::tests::utils::current_ts() + 3_600,
    );
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &revoke).assert_ok();

    let revoked_registry_account = litesvm.get_account(&registry).unwrap();
    let revoked_registry = AuthorityConsentRegistry::load(&revoked_registry_account.data).unwrap();
    let revoked_generation = revoked_registry.authority_generation;
    let revoked_status = revoked_registry.status;
    assert_eq!(revoked_generation, 2);
    assert_eq!(revoked_status, AUTHORITY_REGISTRY_REVOKED);
    assert!(litesvm.get_account(&authority).is_none());

    // Expire the ordinary recent blockhash explicitly. LiteSVM's Revoke
    // helper also rotates it, but this explicit call makes the test's premise
    // independent of helper side effects. The action deadline remains valid.
    litesvm.expire_blockhash();
    assert!(litesvm.get_sysvar::<solana_clock::Clock>().unix_timestamp < deadline);
    assert!(
        litesvm.send_transaction(recent_blockhash_transaction).is_err(),
        "a regular recent-blockhash transaction must expire after the slot window"
    );
    assert_eq!(read_initialized_nonce_hash(litesvm, &nonce_account), original_nonce_hash);

    // The nonce transaction passes runtime nonce validation and reaches the
    // VNext instruction, which must reject its stale expected generation.
    litesvm.send_transaction(durable_nonce_transaction).assert_err_at(1, SubscriptionsError::StaleAuthorityGeneration);

    // Solana consumes a valid durable nonce even when a later instruction
    // fails. The failed authorization must not restore that nonce or replay.
    let consumed_nonce_hash = read_initialized_nonce_hash(litesvm, &nonce_account);
    assert_ne!(consumed_nonce_hash, original_nonce_hash);
    assert!(litesvm.send_transaction(durable_nonce_replay).is_err());
    assert_eq!(read_initialized_nonce_hash(litesvm, &nonce_account), consumed_nonce_hash);

    let final_registry_account = litesvm.get_account(&registry).unwrap();
    let final_registry = AuthorityConsentRegistry::load(&final_registry_account.data).unwrap();
    let final_generation = final_registry.authority_generation;
    let final_status = final_registry.status;
    assert_eq!(final_generation, 2);
    assert_eq!(final_status, AUTHORITY_REGISTRY_REVOKED);
    assert!(litesvm.get_account(&authority).is_none());
    let source_state = fetch_account::<TokenAccount>(litesvm, &source);
    assert!(source_state.delegate.is_none());
    assert_eq!(source_state.delegated_amount, 0);
    assert_eq!(source_state.amount, 1_000_000);
}

#[test]
fn vnext_durable_nonce_authorization_is_rejected_after_onchain_deadline() {
    let (litesvm, subscriber) = &mut setup();
    let mint = init_mint(litesvm, TOKEN_PROGRAM_ID, MINT_DECIMALS, 1_000_000_000, Some(subscriber.pubkey()), &[]);
    let source = init_aux_token_account(litesvm, mint, subscriber.pubkey(), 1_000_000);
    let (registry, authority) = derive_vnext_accounts(&subscriber.pubkey(), &mint, &source);

    let nonce_authority = Keypair::new();
    let nonce_account = create_initialized_nonce_account(litesvm, subscriber, &nonce_authority);
    let original_nonce_hash = read_initialized_nonce_hash(litesvm, &nonce_account);
    let deadline = crate::tests::utils::current_ts() + 3_600;
    let authorize = authorize_ix(&subscriber.pubkey(), registry, authority, mint, source, 0, 0, deadline);
    let durable_nonce_transaction =
        sign_durable_nonce_authorization(subscriber, &nonce_authority, &nonce_account, original_nonce_hash, &authorize);
    let durable_nonce_replay = durable_nonce_transaction.clone();

    // Expire the ordinary recent blockhash and advance only the on-chain
    // action clock. The stored nonce must still reach the Program, which
    // enforces its original deadline independently of transaction freshness.
    litesvm.expire_blockhash();
    crate::tests::utils::set_clock(litesvm, deadline + 1);
    assert!(litesvm.get_sysvar::<solana_clock::Clock>().unix_timestamp > deadline);

    litesvm.send_transaction(durable_nonce_transaction).assert_err_at(1, SubscriptionsError::AuthorityActionExpired);

    let consumed_nonce_hash = read_initialized_nonce_hash(litesvm, &nonce_account);
    assert_ne!(consumed_nonce_hash, original_nonce_hash);
    assert!(litesvm.send_transaction(durable_nonce_replay).is_err());
    assert_eq!(read_initialized_nonce_hash(litesvm, &nonce_account), consumed_nonce_hash);

    assert!(litesvm.get_account(&registry).is_none());
    assert!(litesvm.get_account(&authority).is_none());
    let source_state = fetch_account::<TokenAccount>(litesvm, &source);
    assert!(source_state.delegate.is_none());
    assert_eq!(source_state.delegated_amount, 0);
    assert_eq!(source_state.amount, 1_000_000);
}
