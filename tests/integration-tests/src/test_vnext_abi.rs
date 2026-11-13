use core::mem::size_of;

use serde_json::Value;
use subscriptions::instructions::{
    create_plan::{PlanData, PlanTerms},
    AuthorityActionData, RevisionActionData, SubscriptionsInstruction, VNextCreatePlanData, VNextPlanUpdateData,
    VNextSubscribeData, VNextTransferData, VNextTransferV2Data,
};

const COMMITTED_IDL: &str = include_str!("../../../idl/subscriptions.json");

type GoldenAccount = (&'static str, bool, bool, bool);

fn bytes_of<T>(value: &T) -> &[u8] {
    // Reading an object representation as u8 bytes does not create an
    // aligned reference to any packed field.
    unsafe { core::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) }
}

fn assert_instruction_contract(
    idl: &Value,
    idl_name: &str,
    discriminator: u8,
    payload_type: &str,
    payload_len: usize,
    parser_name: &str,
    expected_accounts: &[GoldenAccount],
) {
    let instruction = idl["program"]["instructions"]
        .as_array()
        .expect("committed Codama IDL must contain program instructions")
        .iter()
        .find(|candidate| candidate["name"].as_str() == Some(idl_name))
        .unwrap_or_else(|| panic!("missing VNext instruction in IDL: {idl_name}"));

    let args = instruction["args"].as_array().expect("instruction args must be an array");
    assert_eq!(args.len(), 2, "{idl_name}: unexpected argument count");
    assert_eq!(args[0]["name"], "discriminator");
    assert_eq!(
        args[0]["defaultValue"]["number"].as_u64(),
        Some(u64::from(discriminator)),
        "{idl_name}: discriminator drift"
    );
    assert_eq!(args[1]["type"]["kind"], "definedTypeLinkNode");
    assert_eq!(
        args[1]["type"]["name"],
        payload_type,
        "{idl_name}: payload type drift"
    );

    let actual_accounts: Vec<(String, bool, bool, bool)> = instruction["accounts"]
        .as_array()
        .expect("instruction accounts must be an array")
        .iter()
        .map(|account| {
            (
                account["name"].as_str().expect("account name").to_owned(),
                account["isSigner"].as_bool().unwrap_or(false),
                account["isWritable"].as_bool().unwrap_or(false),
                account["isOptional"].as_bool().unwrap_or(false),
            )
        })
        .collect();

    let expected_accounts: Vec<(String, bool, bool, bool)> = expected_accounts
        .iter()
        .map(|(name, signer, writable, optional)| {
            ((*name).to_owned(), *signer, *writable, *optional)
        })
        .collect();
    assert_eq!(actual_accounts, expected_accounts, "{idl_name}: account-meta ABI drift");

    // Verify that the on-chain parser accepts exactly the golden payload length.
    let mut valid = vec![0u8; payload_len + 1];
    valid[0] = discriminator;
    let parsed = SubscriptionsInstruction::from_bytes(&valid)
        .unwrap_or_else(|error| panic!("{idl_name}: parser rejected the golden ABI: {error:?}"));
    assert_eq!(parsed.to_string(), parser_name, "{idl_name}: parser route drift");

    // Both truncation and trailing bytes are rejected; neither may be silently decoded.
    let mut truncated = vec![0u8; payload_len];
    truncated[0] = discriminator;
    assert!(SubscriptionsInstruction::from_bytes(&truncated).is_err(), "{idl_name}: accepted truncated payload");

    valid.push(0);
    assert!(SubscriptionsInstruction::from_bytes(&valid).is_err(), "{idl_name}: accepted trailing payload byte");
}

#[test]
fn vnext_instruction_payload_lengths_and_offsets_are_frozen() {
    assert_eq!(size_of::<PlanTerms>(), 24);
    assert_eq!(core::mem::offset_of!(PlanTerms, amount), 0);
    assert_eq!(core::mem::offset_of!(PlanTerms, period_hours), 8);
    assert_eq!(core::mem::offset_of!(PlanTerms, created_at), 16);

    assert_eq!(PlanData::LEN, 456);
    assert_eq!(core::mem::offset_of!(PlanData, plan_id), 0);
    assert_eq!(core::mem::offset_of!(PlanData, mint), 8);
    assert_eq!(core::mem::offset_of!(PlanData, terms), 40);
    assert_eq!(core::mem::offset_of!(PlanData, end_ts), 64);
    assert_eq!(core::mem::offset_of!(PlanData, destinations), 72);
    assert_eq!(core::mem::offset_of!(PlanData, pullers), 200);
    assert_eq!(core::mem::offset_of!(PlanData, metadata_uri), 328);

    assert_eq!(AuthorityActionData::LEN, 24);
    assert_eq!(core::mem::offset_of!(AuthorityActionData, expected_generation), 0);
    assert_eq!(core::mem::offset_of!(AuthorityActionData, expected_nonce), 8);
    assert_eq!(core::mem::offset_of!(AuthorityActionData, not_after_ts), 16);

    assert_eq!(VNextCreatePlanData::LEN, 464);
    assert_eq!(core::mem::offset_of!(VNextCreatePlanData, not_after_ts), 0);
    assert_eq!(core::mem::offset_of!(VNextCreatePlanData, plan_data), 8);

    assert_eq!(VNextPlanUpdateData::LEN, 538);
    assert_eq!(core::mem::offset_of!(VNextPlanUpdateData, expected_revision), 0);
    assert_eq!(core::mem::offset_of!(VNextPlanUpdateData, expected_nonce), 8);
    assert_eq!(core::mem::offset_of!(VNextPlanUpdateData, not_after_ts), 16);
    assert_eq!(core::mem::offset_of!(VNextPlanUpdateData, expected_status), 24);
    assert_eq!(core::mem::offset_of!(VNextPlanUpdateData, status), 25);
    assert_eq!(core::mem::offset_of!(VNextPlanUpdateData, expected_pullers), 26);
    assert_eq!(core::mem::offset_of!(VNextPlanUpdateData, pullers), 154);
    assert_eq!(core::mem::offset_of!(VNextPlanUpdateData, expected_metadata_uri), 282);
    assert_eq!(core::mem::offset_of!(VNextPlanUpdateData, metadata_uri), 410);

    assert_eq!(RevisionActionData::LEN, 24);
    assert_eq!(core::mem::offset_of!(RevisionActionData, expected_revision), 0);
    assert_eq!(core::mem::offset_of!(RevisionActionData, expected_nonce), 8);
    assert_eq!(core::mem::offset_of!(RevisionActionData, not_after_ts), 16);

    assert_eq!(VNextSubscribeData::LEN, 113);
    assert_eq!(core::mem::offset_of!(VNextSubscribeData, plan_id), 0);
    assert_eq!(core::mem::offset_of!(VNextSubscribeData, plan_bump), 8);
    assert_eq!(core::mem::offset_of!(VNextSubscribeData, expected_plan_revision), 9);
    assert_eq!(core::mem::offset_of!(VNextSubscribeData, expected_plan_nonce), 17);
    assert_eq!(core::mem::offset_of!(VNextSubscribeData, expected_lifecycle_revision), 25);
    assert_eq!(core::mem::offset_of!(VNextSubscribeData, expected_lifecycle_nonce), 33);
    assert_eq!(core::mem::offset_of!(VNextSubscribeData, expected_authority_generation), 41);
    assert_eq!(core::mem::offset_of!(VNextSubscribeData, not_after_ts), 49);
    assert_eq!(core::mem::offset_of!(VNextSubscribeData, expected_mint), 57);
    assert_eq!(core::mem::offset_of!(VNextSubscribeData, expected_amount), 89);
    assert_eq!(core::mem::offset_of!(VNextSubscribeData, expected_period_hours), 97);
    assert_eq!(core::mem::offset_of!(VNextSubscribeData, expected_created_at), 105);

    assert_eq!(VNextTransferData::LEN, 120);
    assert_eq!(core::mem::offset_of!(VNextTransferData, amount), 0);
    assert_eq!(core::mem::offset_of!(VNextTransferData, delegator), 8);
    assert_eq!(core::mem::offset_of!(VNextTransferData, mint), 40);
    assert_eq!(core::mem::offset_of!(VNextTransferData, expected_plan_revision), 72);
    assert_eq!(core::mem::offset_of!(VNextTransferData, expected_plan_nonce), 80);
    assert_eq!(core::mem::offset_of!(VNextTransferData, expected_lifecycle_revision), 88);
    assert_eq!(core::mem::offset_of!(VNextTransferData, expected_lifecycle_nonce), 96);
    assert_eq!(core::mem::offset_of!(VNextTransferData, expected_authority_generation), 104);
    assert_eq!(core::mem::offset_of!(VNextTransferData, not_after_ts), 112);

    assert_eq!(VNextTransferV2Data::LEN, 136);
    assert_eq!(core::mem::offset_of!(VNextTransferV2Data, amount), 0);
    assert_eq!(core::mem::offset_of!(VNextTransferV2Data, delegator), 8);
    assert_eq!(core::mem::offset_of!(VNextTransferV2Data, mint), 40);
    assert_eq!(core::mem::offset_of!(VNextTransferV2Data, expected_period_start_ts), 72);
    assert_eq!(core::mem::offset_of!(VNextTransferV2Data, expected_amount_pulled_in_period), 80);
    assert_eq!(core::mem::offset_of!(VNextTransferV2Data, expected_plan_revision), 88);
    assert_eq!(core::mem::offset_of!(VNextTransferV2Data, expected_plan_nonce), 96);
    assert_eq!(core::mem::offset_of!(VNextTransferV2Data, expected_lifecycle_revision), 104);
    assert_eq!(core::mem::offset_of!(VNextTransferV2Data, expected_lifecycle_nonce), 112);
    assert_eq!(core::mem::offset_of!(VNextTransferV2Data, expected_authority_generation), 120);
    assert_eq!(core::mem::offset_of!(VNextTransferV2Data, not_after_ts), 128);
}

#[test]
fn vnext_integer_payloads_are_little_endian_golden_bytes() {
    let payload = AuthorityActionData {
        expected_generation: 0x0807_0605_0403_0201,
        expected_nonce: 0x1817_1615_1413_1211,
        not_after_ts: -2,
    };
    assert_eq!(
        bytes_of(&payload),
        &[
            1, 2, 3, 4, 5, 6, 7, 8, 17, 18, 19, 20, 21, 22, 23, 24, 254, 255, 255, 255, 255, 255, 255, 255,
        ]
    );
}

#[test]
fn vnext_idl_account_meta_and_discriminator_contract_is_golden() {
    let idl: Value = serde_json::from_str(COMMITTED_IDL).expect("committed Codama IDL must parse");

    assert_instruction_contract(
        &idl,
        "authorizeSubscriptionAuthorityVnext",
        18,
        "authorityActionData",
        AuthorityActionData::LEN,
        "authorize_subscription_authority_vnext",
        &[
            ("subscriber", true, true, false),
            ("registry", false, true, false),
            ("authority", false, true, false),
            ("tokenMint", false, false, false),
            ("sourceTokenAccount", false, true, false),
            ("systemProgram", false, false, false),
            ("tokenProgram", false, false, false),
            ("payer", true, true, true),
        ],
    );
    assert_instruction_contract(
        &idl,
        "revokeSubscriptionAuthorityVnext",
        19,
        "authorityActionData",
        AuthorityActionData::LEN,
        "revoke_subscription_authority_vnext",
        &[
            ("subscriber", true, true, false),
            ("registry", false, true, false),
            ("authority", false, true, false),
            ("tokenMint", false, false, false),
            ("sourceTokenAccount", false, true, false),
            ("systemProgram", false, false, false),
            ("tokenProgram", false, false, false),
            ("receiver", false, true, true),
        ],
    );
    assert_instruction_contract(
        &idl,
        "createPlanVnext",
        20,
        "vnextCreatePlanData",
        VNextCreatePlanData::LEN,
        "create_plan_vnext",
        &[
            ("merchant", true, true, false),
            ("planPda", false, true, false),
            ("planRevisionRegistry", false, true, false),
            ("tokenMint", false, false, false),
            ("systemProgram", false, false, false),
            ("tokenProgram", false, false, false),
        ],
    );
    assert_instruction_contract(
        &idl,
        "updatePlanVnext",
        21,
        "vnextPlanUpdateData",
        VNextPlanUpdateData::LEN,
        "update_plan_vnext",
        &[
            ("merchant", true, false, false),
            ("planPda", false, true, false),
            ("planRevisionRegistry", false, true, false),
            ("eventAuthority", false, false, false),
            ("selfProgram", false, false, false),
        ],
    );
    assert_instruction_contract(
        &idl,
        "subscribeVnext",
        22,
        "vnextSubscribeData",
        VNextSubscribeData::LEN,
        "subscribe_vnext",
        &[
            ("subscriber", true, true, false),
            ("merchant", false, false, false),
            ("planPda", false, false, false),
            ("planRevisionRegistry", false, false, false),
            ("subscriptionPda", false, true, false),
            ("lifecycleRegistry", false, true, false),
            ("consentRegistry", false, false, false),
            ("authority", false, false, false),
            ("tokenMint", false, false, false),
            ("sourceTokenAccount", false, true, false),
            ("systemProgram", false, false, false),
            ("tokenProgram", false, false, false),
            ("eventAuthority", false, false, false),
            ("selfProgram", false, false, false),
        ],
    );
    assert_instruction_contract(
        &idl,
        "cancelSubscriptionVnext",
        23,
        "revisionActionData",
        RevisionActionData::LEN,
        "cancel_subscription_vnext",
        &[
            ("subscriber", true, false, false),
            ("planPda", false, false, false),
            ("planRevisionRegistry", false, false, false),
            ("subscriptionPda", false, true, false),
            ("lifecycleRegistry", false, true, false),
            ("eventAuthority", false, false, false),
            ("selfProgram", false, false, false),
        ],
    );
    assert_instruction_contract(
        &idl,
        "cancelSubscriptionNowVnext",
        24,
        "revisionActionData",
        RevisionActionData::LEN,
        "cancel_subscription_now_vnext",
        &[
            ("subscriber", true, false, false),
            ("merchant", true, false, false),
            ("planPda", false, false, false),
            ("planRevisionRegistry", false, false, false),
            ("subscriptionPda", false, true, false),
            ("lifecycleRegistry", false, true, false),
            ("eventAuthority", false, false, false),
            ("selfProgram", false, false, false),
        ],
    );
    assert_instruction_contract(
        &idl,
        "resumeSubscriptionVnext",
        25,
        "revisionActionData",
        RevisionActionData::LEN,
        "resume_subscription_vnext",
        &[
            ("subscriber", true, false, false),
            ("planPda", false, false, false),
            ("planRevisionRegistry", false, false, false),
            ("subscriptionPda", false, true, false),
            ("lifecycleRegistry", false, true, false),
            ("consentRegistry", false, false, false),
            ("authority", false, false, false),
            ("tokenMint", false, false, false),
            ("sourceTokenAccount", false, false, false),
            ("tokenProgram", false, false, false),
            ("eventAuthority", false, false, false),
            ("selfProgram", false, false, false),
        ],
    );
    assert_instruction_contract(
        &idl,
        "transferSubscriptionVnext",
        26,
        "vnextTransferData",
        VNextTransferData::LEN,
        "transfer_subscription_vnext_v1_disabled",
        &[
            ("subscriptionPda", false, true, false),
            ("planPda", false, false, false),
            ("planRevisionRegistry", false, false, false),
            ("lifecycleRegistry", false, false, false),
            ("consentRegistry", false, false, false),
            ("authority", false, false, false),
            ("sourceTokenAccount", false, true, false),
            ("destinationTokenAccount", false, true, false),
            ("caller", true, false, false),
            ("tokenMint", false, false, false),
            ("tokenProgram", false, false, false),
            ("eventAuthority", false, false, false),
            ("selfProgram", false, false, false),
        ],
    );
    assert_instruction_contract(
        &idl,
        "transferSubscriptionVnextV2",
        27,
        "vnextTransferV2Data",
        VNextTransferV2Data::LEN,
        "transfer_subscription_vnext_v2",
        &[
            ("subscriptionPda", false, true, false),
            ("planPda", false, false, false),
            ("planRevisionRegistry", false, false, false),
            ("lifecycleRegistry", false, false, false),
            ("consentRegistry", false, false, false),
            ("authority", false, false, false),
            ("sourceTokenAccount", false, true, false),
            ("destinationTokenAccount", false, true, false),
            ("caller", true, false, false),
            ("tokenMint", false, false, false),
            ("tokenProgram", false, false, false),
            ("eventAuthority", false, false, false),
            ("selfProgram", false, false, false),
        ],
    );
}
