use pinocchio::{account::AccountView, entrypoint, Address, ProgramResult};

use crate::instructions::{
    authorize_subscription_authority_vnext, cancel_subscription, cancel_subscription_now, create_plan, delete_plan,
    emit_event, legacy_subscription_authority_vnext, resume_subscription, revoke_abandoned_delegation,
    revoke_abandoned_subscription, revoke_delegation, revoke_subscription_authority_vnext, transfer_subscription,
    update_plan, vnext_plan, vnext_subscription,
    SubscriptionsInstruction,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = SubscriptionsInstruction::from_bytes(instruction_data)?;

    match instruction {
        SubscriptionsInstruction::InitSubscriptionAuthority
        | SubscriptionsInstruction::CreateFixedDelegation(_)
        | SubscriptionsInstruction::CreateRecurringDelegation(_)
        | SubscriptionsInstruction::TransferFixed(_)
        | SubscriptionsInstruction::TransferRecurring(_)
        | SubscriptionsInstruction::CloseSubscriptionAuthority
        | SubscriptionsInstruction::TransferSubscription(_)
        | SubscriptionsInstruction::Subscribe(_)
        | SubscriptionsInstruction::RevokeSubscriptionAuthority => {
            Err(crate::SubscriptionsError::LegacyInstructionDisabled.into())
        }
        SubscriptionsInstruction::AuthorizeLegacySubscriptionAuthorityVNext(data) => {
            legacy_subscription_authority_vnext::process_authorize(accounts, &data)
        }
        SubscriptionsInstruction::RevokeLegacySubscriptionAuthorityVNext(data) => {
            legacy_subscription_authority_vnext::process_revoke(accounts, &data)
        }
        SubscriptionsInstruction::TransferLegacySubscriptionVNextV2(data) => {
            transfer_subscription::process_legacy_vnext_v2(accounts, &data)
        }
        SubscriptionsInstruction::AuthorizeSubscriptionAuthorityVNext(data) => {
            authorize_subscription_authority_vnext::process(accounts, &data)
        }
        SubscriptionsInstruction::RevokeSubscriptionAuthorityVNext(data) => {
            revoke_subscription_authority_vnext::process(accounts, &data)
        }
        SubscriptionsInstruction::CreatePlanVNext(data) => vnext_plan::process_create(accounts, &data),
        SubscriptionsInstruction::UpdatePlanVNext(data) => vnext_plan::process_update(accounts, &data),
        SubscriptionsInstruction::SubscribeVNext(data) => vnext_subscription::process_subscribe(accounts, &data),
        SubscriptionsInstruction::CancelSubscriptionVNext(data) => vnext_subscription::process_cancel(accounts, &data),
        SubscriptionsInstruction::CancelSubscriptionNowVNext(data) => {
            vnext_subscription::process_cancel_now(accounts, &data)
        }
        SubscriptionsInstruction::ResumeSubscriptionVNext(data) => vnext_subscription::process_resume(accounts, &data),
        SubscriptionsInstruction::TransferSubscriptionVNext(data) => {
            vnext_subscription::process_transfer(accounts, &data)
        }
        SubscriptionsInstruction::TransferSubscriptionVNextV2(data) => {
            vnext_subscription::process_transfer_v2(accounts, &data)
        }
        SubscriptionsInstruction::RevokeDelegation => revoke_delegation::process(accounts),
        SubscriptionsInstruction::CreatePlan(data) => create_plan::process(accounts, &data),
        SubscriptionsInstruction::UpdatePlan(data) => update_plan::process(accounts, &data),
        SubscriptionsInstruction::DeletePlan => delete_plan::process(accounts),
        SubscriptionsInstruction::CancelSubscription => cancel_subscription::process(accounts),
        SubscriptionsInstruction::CancelSubscriptionNow(data) => cancel_subscription_now::process(accounts, &data),
        SubscriptionsInstruction::ResumeSubscription(data) => resume_subscription::process(accounts, &data),
        SubscriptionsInstruction::RevokeAbandonedDelegation => revoke_abandoned_delegation::process(accounts),
        SubscriptionsInstruction::RevokeAbandonedSubscription => revoke_abandoned_subscription::process(accounts),
        SubscriptionsInstruction::EmitEvent => emit_event::process(program_id, accounts),
    }
}
