use litesvm::LiteSVM;
use solana_clock::Clock;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use spl_token_2022_interface::state::Account as TokenAccount;

use crate::{
    state::{AuthorityConsentRegistry, VNextSubscriptionAuthority},
    tests::{
        constants::{MINT_DECIMALS, PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_PROGRAM_ID},
        utils::{current_ts, fetch_account, init_aux_token_account, init_mint, init_wallet},
    },
    SubscriptionAuthority,
};

fn to_address(key: &Pubkey) -> pinocchio::Address {
    pinocchio::Address::from(key.to_bytes())
}

/// This test deliberately loads the immutable v0.5.0 Program binary, not the
/// current VNext SBF. CI supplies the binary built from the pinned upstream SHA.
#[test]
#[ignore = "requires SOLMINT_LEGACY_PROGRAM_SO from the immutable v0.5.0 build"]
fn vnext_legacy_program_cannot_delegate_a_non_ata_source() {
    let legacy_program = std::env::var("SOLMINT_LEGACY_PROGRAM_SO")
        .expect("CI must supply the exact immutable legacy Program binary");
    let mut litesvm = LiteSVM::new();
    litesvm.add_program_from_file(PROGRAM_ID.to_bytes(), legacy_program).unwrap();

    let mut clock = litesvm.get_sysvar::<Clock>();
    clock.unix_timestamp = current_ts();
    litesvm.set_sysvar::<Clock>(&clock);

    let subscriber = init_wallet(&mut litesvm, 100_000_000_000);
    let mint = init_mint(
        &mut litesvm,
        TOKEN_PROGRAM_ID,
        MINT_DECIMALS,
        1_000_000_000,
        Some(subscriber.pubkey()),
        &[],
    );
    let source = init_aux_token_account(&mut litesvm, mint, subscriber.pubkey(), 1_000_000);

    let subscriber_address = to_address(&subscriber.pubkey());
    let mint_address = to_address(&mint);
    let source_address = to_address(&source);
    let vnext_registry = Pubkey::new_from_array(
        AuthorityConsentRegistry::find_pda(&subscriber_address, &mint_address, &source_address).0.to_bytes(),
    );
    let vnext_authority = Pubkey::new_from_array(
        VNextSubscriptionAuthority::find_pda(&subscriber_address, &mint_address, &source_address).0.to_bytes(),
    );
    let (legacy_authority, _) = Pubkey::find_program_address(
        &[SubscriptionAuthority::SEED, subscriber.pubkey().as_ref(), mint.as_ref()],
        &PROGRAM_ID,
    );

    // Legacy InitSubscriptionAuthority receives the non-ATA source in the old
    // user_ata position. The pinned v0.5.0 Program must reject it atomically.
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
    let transaction = Transaction::new(
        &[&subscriber],
        Message::new(std::slice::from_ref(&init), Some(&subscriber.pubkey())),
        litesvm.latest_blockhash(),
    );
    assert!(litesvm.send_transaction(transaction).is_err());

    let source_state = fetch_account::<TokenAccount>(&litesvm, &source);
    assert_eq!(source_state.amount, 1_000_000);
    assert!(source_state.delegate.is_none());

    // The old instruction derives only the legacy user+mint Authority PDA.
    // It cannot create either VNext PDA or leave a partial legacy Authority.
    assert!(litesvm.get_account(&legacy_authority).is_none());
    assert!(litesvm.get_account(&vnext_registry).is_none());
    assert!(litesvm.get_account(&vnext_authority).is_none());
}
