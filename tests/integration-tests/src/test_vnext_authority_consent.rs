use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
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
    let status = registry_state.status;
    assert_eq!(generation, 2);
    assert_eq!(status, AUTHORITY_REGISTRY_REVOKED);
    assert!(litesvm.get_account(&authority).is_none());

    // This is the old signed authorization payload: its generation and nonce
    // are stale after the tombstone, so it cannot create a delegate.
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
    build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &stale_authorize)
        .assert_err(SubscriptionsError::StaleAuthorityGeneration);

    let source_state = fetch_account::<TokenAccount>(litesvm, &source);
    assert!(source_state.delegate.is_none());
    assert!(litesvm.get_account(&authority).is_none());
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
