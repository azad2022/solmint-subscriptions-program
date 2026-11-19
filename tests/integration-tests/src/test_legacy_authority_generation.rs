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
        utils::{build_and_send_transaction, current_ts, init_ata, init_mint, setup},
    },
    AuthorityConsentRegistry, SubscriptionAuthority, SubscriptionsError,
    AUTHORITY_REGISTRY_ACTIVE, AUTHORITY_REGISTRY_REVOKED,
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
    let (registry, authority) = derive_legacy_lineage(&subscriber.pubkey(), &mint, &source);
    let (seeded_authority, old_init_id) = seed_legacy_authority(litesvm, &subscriber.pubkey(), &mint, &source);
    assert_eq!(authority, seeded_authority);

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
    let authority_state = SubscriptionAuthority::load(&authority_account.data).unwrap();
    let migrated_init_id = authority_state.init_id;
    assert_eq!(migrated_init_id, old_init_id);
    let token_after_bootstrap = crate::tests::utils::fetch_account::<TokenAccount>(litesvm, &source);
    assert_eq!(token_after_bootstrap.delegate, Some(authority));
    assert_eq!(token_after_bootstrap.delegated_amount, u64::MAX);

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
    let token_after_revoke = crate::tests::utils::fetch_account::<TokenAccount>(litesvm, &source);
    assert!(token_after_revoke.delegate.is_none());
    assert_eq!(token_after_revoke.delegated_amount, 0);

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
    assert_eq!(registry_state.status, AUTHORITY_REGISTRY_REVOKED);
    assert_eq!(registry_state.authority_generation, 2);
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
    assert_eq!(final_registry.authority_generation, 2);
    assert_eq!(final_registry.status, AUTHORITY_REGISTRY_REVOKED);
    assert!(litesvm.get_account(&authority).is_none());
    let token = crate::tests::utils::fetch_account::<TokenAccount>(litesvm, &source);
    assert!(token.delegate.is_none());
    assert_eq!(token.delegated_amount, 0);
}

#[test]
fn unversioned_legacy_authority_mutations_are_closed_at_dispatch() {
    let (litesvm, subscriber) = &mut setup();
    for discriminator in [0u8, 6u8, 14u8] {
        let ix = Instruction { program_id: PROGRAM_ID, accounts: vec![], data: vec![discriminator] };
        build_and_send_transaction(litesvm, &[subscriber], &subscriber.pubkey(), &ix)
            .assert_err(SubscriptionsError::LegacyInstructionDisabled);
    }
}
