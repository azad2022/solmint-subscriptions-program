use codama::CodamaType;
use core::mem::{size_of, transmute};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};

use crate::{
    check_and_update_version,
    event_engine::{self, EventSerialize},
    events::SubscriptionTransferEvent,
    helpers::{transfer_with_delegate, validate_recurring_transfer, TransferAccounts, TransferData},
    state::{
        common::AccountDiscriminator, plan::Plan, subscription_authority::SubscriptionAuthority,
        subscription_delegation::SubscriptionDelegation, AuthorityConsentRegistry, AUTHORITY_REGISTRY_ACTIVE,
    },
    AccountCheck, MintInterface, ProgramAccount, SignerAccount, SubscriptionAuthorityAccount, SubscriptionsError,
    TokenAccountInterface, TokenProgramInterface, WritableAccount,
};

use crate::get_token_account_owner;

/// Instruction discriminator byte for `TransferSubscription`.
pub const DISCRIMINATOR: &u8 = &10;
/// Discriminator for generation-bound transfers of existing legacy subscriptions.
pub const LEGACY_VNEXT_V2_DISCRIMINATOR: &u8 = &30;

/// Executes a transfer against a [`SubscriptionDelegation`].
///
/// Validates the caller is an authorized puller, checks the receiver against
/// the plan's destination whitelist, enforces per-period limits, performs the
/// SPL token transfer, and emits a
/// [`SubscriptionTransferEvent`].
pub fn process(accounts: &mut [AccountView], transfer_data: &TransferData) -> ProgramResult {
    let accounts_struct = TransferSubscriptionAccounts::try_from(accounts)?;

    let current_ts = Clock::get()?.unix_timestamp;

    // Plan and SubscriptionDelegation are loaded in separate borrow scopes so the immutable plan borrow drops before the mutable subscription borrow.
    let plan_terms: crate::instructions::create_plan::PlanTerms;
    let plan_end_ts: i64;
    let receiver_owner: Address;
    {
        let plan_data = accounts_struct.plan_pda.try_borrow()?;
        let plan = Plan::load(&plan_data)?;

        if plan.data.mint != transfer_data.mint {
            return Err(SubscriptionsError::MintMismatch.into());
        }

        plan_end_ts = plan.data.end_ts;
        if plan_end_ts != 0 && current_ts > plan_end_ts {
            return Err(SubscriptionsError::PlanExpired.into());
        }

        plan.can_pull(accounts_struct.caller.address())?;

        let receiver_data = accounts_struct.receiver_ata.try_borrow()?;
        receiver_owner = get_token_account_owner(&receiver_data)?;
        plan.check_destination(&receiver_owner)?;

        plan_terms = plan.data.terms;
    }

    let amount_per_period: u64;
    let period_length_s: u64;
    let period_start: i64;
    let amount_pulled_in_period: u64;
    let init_id: i64;
    {
        let mut binding = accounts_struct.subscription_pda.try_borrow_mut()?;
        check_and_update_version(&mut binding, AccountDiscriminator::SubscriptionDelegation)?;
        let subscription = SubscriptionDelegation::load_mut(&mut binding)?;

        subscription.check_plan_terms(&plan_terms)?;

        let delegator = subscription.header.delegator;

        if subscription.header.delegatee != *accounts_struct.plan_pda.address() {
            return Err(SubscriptionsError::SubscriptionPlanMismatch.into());
        }

        if delegator != transfer_data.delegator {
            return Err(SubscriptionsError::Unauthorized.into());
        }

        // expires_at_ts is pre-computed at cancellation time so the transfer path stays branch-light.
        let expires_at_ts = subscription.expires_at_ts;
        if expires_at_ts != 0 && current_ts >= expires_at_ts {
            return Err(SubscriptionsError::SubscriptionCancelled.into());
        }

        amount_per_period = subscription.terms.amount;
        period_length_s = subscription.terms.period_length_secs()?;

        let mut ps = subscription.current_period_start_ts;
        let mut pulled = subscription.amount_pulled_in_period;
        validate_recurring_transfer(
            transfer_data.amount,
            amount_per_period,
            period_length_s,
            &mut ps,
            &mut pulled,
            plan_end_ts,
            current_ts,
        )?;
        subscription.current_period_start_ts = ps;
        subscription.amount_pulled_in_period = pulled;

        period_start = ps;
        amount_pulled_in_period = pulled;
        init_id = subscription.header.init_id;
    }

    transfer_with_delegate(
        transfer_data.amount,
        &transfer_data.delegator,
        &transfer_data.mint,
        init_id,
        &TransferAccounts {
            delegator_ata: accounts_struct.delegator_ata,
            to_ata: accounts_struct.receiver_ata,
            token_mint: accounts_struct.token_mint,
            subscription_authority_pda: accounts_struct.subscription_authority,
            token_program: accounts_struct.token_program,
        },
        accounts_struct.remaining,
    )?;

    let period_end_ts = {
        let end = period_start + period_length_s as i64;
        if plan_end_ts != 0 && end > plan_end_ts {
            plan_end_ts
        } else {
            end
        }
    };

    let event = SubscriptionTransferEvent::new(
        *accounts_struct.subscription_pda.address(),
        *accounts_struct.plan_pda.address(),
        transfer_data.delegator,
        transfer_data.mint,
        transfer_data.amount,
        period_start,
        period_end_ts,
        amount_pulled_in_period,
        receiver_owner,
        *accounts_struct.receiver_ata.address(),
        *accounts_struct.caller.address(),
    );
    let event_data = event.to_bytes();
    event_engine::emit_event(&crate::ID, accounts_struct.event_authority, accounts_struct.self_program, &event_data)?;

    Ok(())
}

/// Validated accounts for the [`TransferSubscription`](crate::SubscriptionsInstruction::TransferSubscription) instruction.
pub struct TransferSubscriptionAccounts<'a> {
    pub subscription_pda: &'a mut AccountView,
    pub plan_pda: &'a AccountView,
    pub subscription_authority: &'a AccountView,
    pub delegator_ata: &'a AccountView,
    pub receiver_ata: &'a AccountView,
    pub caller: &'a AccountView,
    pub token_mint: &'a AccountView,
    pub token_program: &'a AccountView,
    pub event_authority: &'a AccountView,
    pub self_program: &'a AccountView,
    pub remaining: &'a [AccountView],
}

impl<'a> TryFrom<&'a mut [AccountView]> for TransferSubscriptionAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a mut [AccountView]) -> Result<Self, Self::Error> {
        let [subscription_pda, plan_pda, subscription_authority, delegator_ata, receiver_ata, caller, token_mint, token_program, event_authority, self_program, remaining @ ..] =
            accounts
        else {
            return Err(SubscriptionsError::NotEnoughAccountKeys.into());
        };

        ProgramAccount::check(subscription_pda)?;
        WritableAccount::check(subscription_pda)?;
        // Return a specific error if the plan account has been closed
        if !plan_pda.owned_by(&crate::ID) {
            return Err(SubscriptionsError::PlanClosed.into());
        }
        SubscriptionAuthorityAccount::check(subscription_authority)?;
        WritableAccount::check(delegator_ata)?;
        WritableAccount::check(receiver_ata)?;
        SignerAccount::check(caller)?;
        TokenProgramInterface::check(token_program)?;
        MintInterface::check_with_program(token_mint, token_program)?;
        TokenAccountInterface::check_accounts_with_program(token_program, &[delegator_ata, receiver_ata])?;

        Ok(Self {
            subscription_pda,
            plan_pda,
            subscription_authority,
            delegator_ata,
            receiver_ata,
            caller,
            token_mint,
            token_program,
            event_authority,
            self_program,
            remaining,
        })
    }
}

/// Generation- and billing-snapshot-bound transfer for a migrated v0.5.0
/// SubscriptionDelegation. The original Subscription PDA and its period
/// accounting remain unchanged; the permanent Authority Registry gates every
/// collection attempt and the old Authority init_id is checked before the
/// legacy transfer core is called.
#[repr(C, packed)]
#[derive(CodamaType, Debug, Clone)]
pub struct LegacySubscriptionTransferV2Data {
    pub amount: u64,
    pub delegator: Address,
    pub mint: Address,
    pub expected_current_period_start_ts: i64,
    pub expected_amount_pulled_in_period: u64,
    pub expected_authority_generation: u64,
    pub not_after_ts: i64,
}

impl LegacySubscriptionTransferV2Data {
    pub const LEN: usize = size_of::<Self>();

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidInstructionData.into());
        }
        Ok(unsafe { &*transmute::<*const u8, *const Self>(data.as_ptr()) })
    }
}

fn project_legacy_period_snapshot(
    current_start_ts: i64,
    amount_pulled: u64,
    period_length_s: u64,
    expiry_ts: i64,
    now_ts: i64,
) -> Result<(i64, u64), ProgramError> {
    // Keep this projection identical to validate_recurring_transfer's legacy
    // period catch-up, including the final in-bounds period before a finite
    // Plan expiry. This function predicts the pre-transfer snapshot only.
    let period_length = i64::try_from(period_length_s).map_err(|_| SubscriptionsError::InvalidPeriodLength)?;
    if period_length == 0 {
        return Err(SubscriptionsError::InvalidPeriodLength.into());
    }
    if now_ts < current_start_ts {
        return Err(SubscriptionsError::DelegationNotStarted.into());
    }

    let mut projected_start = current_start_ts;
    let mut projected_amount = amount_pulled;
    let elapsed = now_ts.saturating_sub(projected_start);
    if elapsed >= period_length {
        let periods_elapsed = elapsed.checked_div(period_length).ok_or(SubscriptionsError::InvalidPeriodLength)?;
        let increment = periods_elapsed.checked_mul(period_length).ok_or(SubscriptionsError::ArithmeticOverflow)?;
        let candidate_start = projected_start.checked_add(increment).ok_or(SubscriptionsError::ArithmeticOverflow)?;

        if expiry_ts == 0 || candidate_start < expiry_ts {
            projected_start = candidate_start;
            projected_amount = 0;
        } else {
            let last_billable = expiry_ts.checked_sub(1).ok_or(SubscriptionsError::ArithmeticUnderflow)?;
            if last_billable >= projected_start {
                let span = last_billable
                    .checked_sub(projected_start)
                    .ok_or(SubscriptionsError::ArithmeticUnderflow)?;
                let periods_in_bounds = span.checked_div(period_length).ok_or(SubscriptionsError::InvalidPeriodLength)?;
                let increment = periods_in_bounds.checked_mul(period_length).ok_or(SubscriptionsError::ArithmeticOverflow)?;
                let last_in_bounds_start =
                    projected_start.checked_add(increment).ok_or(SubscriptionsError::ArithmeticOverflow)?;
                if last_in_bounds_start > projected_start {
                    projected_start = last_in_bounds_start;
                    projected_amount = 0;
                }
            }
        }
    }

    Ok((projected_start, projected_amount))
}

/// New discriminator path for existing legacy subscriptions after their
/// Authority has been lazily migrated to the persistent generation Registry.
///
/// Account order is the legacy TransferSubscription account list (10 accounts),
/// then the read-only AuthorityConsentRegistry, followed by any transfer-hook
/// remaining accounts. The Registry is removed before delegating to the old
/// transfer core, so all legacy Plan, Subscription and event semantics remain
/// unchanged.
pub fn process_legacy_vnext_v2(accounts: &mut [AccountView], data: &LegacySubscriptionTransferV2Data) -> ProgramResult {
    let [subscription_pda, plan_pda, authority_pda, source_token_account, _receiver_ata, _caller, token_mint, token_program, _event_authority, _self_program, registry, _remaining @ ..] =
        accounts
    else {
        return Err(SubscriptionsError::NotEnoughAccountKeys.into());
    };

    let amount = data.amount;
    let delegator = data.delegator;
    let mint = data.mint;
    let expected_period_start = data.expected_current_period_start_ts;
    let expected_amount_pulled = data.expected_amount_pulled_in_period;
    let expected_generation = data.expected_authority_generation;
    let not_after_ts = data.not_after_ts;

    if *token_mint.address() != mint {
        return Err(SubscriptionsError::MintMismatch.into());
    }
    TokenProgramInterface::check(token_program)?;
    MintInterface::check_with_program(token_mint, token_program)?;
    TokenAccountInterface::check_with_program(source_token_account, token_program)?;
    let expected_ata = Address::find_program_address(
        &[delegator.as_ref(), token_program.address().as_ref(), mint.as_ref()],
        &pinocchio_associated_token_account::ID,
    )
    .0;
    if expected_ata != *source_token_account.address() {
        return Err(SubscriptionsError::InvalidAssociatedTokenAccountDerivedAddress.into());
    }

    let now_ts = Clock::get()?.unix_timestamp;
    AuthorityConsentRegistry::validate_action_deadline(now_ts, not_after_ts)?;

    ProgramAccount::check(plan_pda)?;
    let plan_end_ts = {
        let plan_bytes = plan_pda.try_borrow()?;
        let plan = Plan::load(&plan_bytes)?;
        if plan.data.mint != mint {
            return Err(SubscriptionsError::MintMismatch.into());
        }
        let end_ts = plan.data.end_ts;
        if end_ts != 0 && now_ts > end_ts {
            return Err(SubscriptionsError::PlanExpired.into());
        }
        end_ts
    };

    let expected_registry = AuthorityConsentRegistry::find_pda(&delegator, &mint, source_token_account.address()).0;
    if expected_registry != *registry.address() {
        return Err(SubscriptionsError::AuthorityConsentRegistryInvalidPda.into());
    }
    ProgramAccount::check(registry)?;
    {
        let bytes = registry.try_borrow()?;
        let consent = AuthorityConsentRegistry::load(&bytes)?;
        consent.validate_identity(
            registry.address(),
            &delegator,
            &mint,
            source_token_account.address(),
            token_program.address(),
        )?;
        if consent.status != AUTHORITY_REGISTRY_ACTIVE || consent.authority_generation != expected_generation {
            return Err(SubscriptionsError::StaleAuthorityGeneration.into());
        }
    }

    let (expected_authority, _) = SubscriptionAuthority::find_pda(&delegator, &mint);
    if expected_authority != *authority_pda.address() {
        return Err(SubscriptionsError::InvalidSubscriptionAuthorityPda.into());
    }
    ProgramAccount::check(authority_pda)?;
    {
        let bytes = authority_pda.try_borrow()?;
        let authority = SubscriptionAuthority::load(&bytes)?;
        authority.check_owner(&delegator)?;
        if authority.token_mint != mint {
            return Err(SubscriptionsError::MintMismatch.into());
        }
        let bump = authority.bump;
        if SubscriptionAuthority::verify_pda(&delegator, &mint, bump)? != expected_authority {
            return Err(SubscriptionsError::InvalidSubscriptionAuthorityPda.into());
        }

        let sub_bytes = subscription_pda.try_borrow()?;
        let subscription = SubscriptionDelegation::load_for_revoke(&sub_bytes)?;
        if subscription.header.delegator != delegator
            || subscription.header.delegatee != *plan_pda.address()
            || subscription.header.init_id != authority.init_id
        {
            return Err(SubscriptionsError::StaleSubscriptionAuthority.into());
        }

        let period_length = subscription.terms.period_length_secs()?;
        let projected = project_legacy_period_snapshot(
            subscription.current_period_start_ts,
            subscription.amount_pulled_in_period,
            period_length,
            plan_end_ts,
            now_ts,
        )?;
        if projected.0 != expected_period_start || projected.1 != expected_amount_pulled {
            return Err(SubscriptionsError::StaleSubscriptionTransferSnapshot.into());
        }
    }

    let transfer = TransferData { amount, delegator, mint };
    let mut legacy_accounts: alloc::vec::Vec<AccountView> = accounts
        .iter()
        .enumerate()
        .filter_map(|(index, account)| if index == 10 { None } else { Some(*account) })
        .collect();

    process(&mut legacy_accounts, &transfer)
}
