use codama::CodamaType;
use core::mem::{size_of, transmute};
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_token_2022::instructions::TransferChecked;

use crate::{
    check_token_account_mint, check_token_account_owner,
    constants::MINT_DECIMALS_OFFSET,
    event_engine::{self, EventSerialize},
    events::{
        SubscriptionCancelledEvent, SubscriptionCreatedEvent, SubscriptionResumedEvent, SubscriptionTransferEvent,
    },
    get_token_account_delegate, get_token_account_owner,
    helpers::{invoke_transfer_checked_with_hook, mint_transfer_hook_program_id, validate_recurring_transfer},
    state::{
        common::PlanStatus, AuthorityConsentRegistry, PlanRevisionRegistry, SubscriptionLifecycleRegistry, VNextPlan,
        VNextSubscription, VNextSubscriptionAuthority, AUTHORITY_REGISTRY_ACTIVE,
    },
    AccountCheck, MintInterface, ProgramAccount, ProgramAccountInit, SignerAccount, SubscriptionsError, SystemAccount,
    TokenAccountInterface, TokenProgramInterface, WritableAccount,
};

pub const SUBSCRIBE_DISCRIMINATOR: &u8 = &22;
pub const CANCEL_DISCRIMINATOR: &u8 = &23;
pub const CANCEL_NOW_DISCRIMINATOR: &u8 = &24;
pub const RESUME_DISCRIMINATOR: &u8 = &25;
pub const TRANSFER_DISCRIMINATOR: &u8 = &26;

/// Exact expected state and deadline for one Subscription lifecycle action.
#[repr(C, packed)]
#[derive(CodamaType, Debug, Clone)]
pub struct RevisionActionData {
    pub expected_revision: u64,
    pub expected_nonce: u64,
    pub not_after_ts: i64,
}

impl RevisionActionData {
    pub const LEN: usize = size_of::<Self>();

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidInstructionData.into());
        }
        Ok(unsafe { &*transmute::<*const u8, *const Self>(data.as_ptr()) })
    }
}

/// Customer-signed Subscribe consent. The plan revision and action nonce bind
/// the instruction to the exact Plan lineage, while Lifecycle Registry values
/// make a held Subscribe stale after any later cancel/close/re-subscribe action.
#[repr(C, packed)]
#[derive(CodamaType, Debug, Clone)]
pub struct VNextSubscribeData {
    pub plan_id: u64,
    pub plan_bump: u8,
    pub expected_plan_revision: u64,
    pub expected_plan_nonce: u64,
    pub expected_lifecycle_revision: u64,
    pub expected_lifecycle_nonce: u64,
    pub expected_authority_generation: u64,
    pub not_after_ts: i64,
    pub expected_mint: Address,
    pub expected_amount: u64,
    pub expected_period_hours: u64,
    pub expected_created_at: i64,
}

impl VNextSubscribeData {
    pub const LEN: usize = size_of::<Self>();

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidInstructionData.into());
        }
        Ok(unsafe { &*transmute::<*const u8, *const Self>(data.as_ptr()) })
    }
}

fn validate_plan_revision(
    plan_account: &AccountView,
    revision_account: &AccountView,
) -> Result<(Address, u64, u64), ProgramError> {
    ProgramAccount::check(plan_account)?;
    ProgramAccount::check(revision_account)?;
    let (owner, plan_revision) = {
        let bytes = plan_account.try_borrow()?;
        let plan = VNextPlan::load(&bytes)?;
        let owner = plan.owner;
        plan.validate_identity(plan_account.address(), &owner)?;
        (owner, plan.revision)
    };
    let (revision, nonce) = {
        let bytes = revision_account.try_borrow()?;
        let registry = PlanRevisionRegistry::load(&bytes)?;
        registry.validate_identity(revision_account.address(), &owner, plan_account.address())?;
        if registry.revision != plan_revision {
            return Err(SubscriptionsError::StalePlanRevision.into());
        }
        (registry.revision, registry.action_nonce)
    };
    Ok((owner, revision, nonce))
}

fn validate_vnext_authority(
    subscriber: &Address,
    mint: &AccountView,
    source: &AccountView,
    token_program: &AccountView,
    consent_account: &AccountView,
    authority_account: &AccountView,
) -> Result<u64, ProgramError> {
    ProgramAccount::check(consent_account)?;
    ProgramAccount::check(authority_account)?;
    TokenProgramInterface::check(token_program)?;
    MintInterface::check_with_program(mint, token_program)?;
    TokenAccountInterface::check_with_program(source, token_program)?;

    let (generation, registry_status) = {
        let bytes = consent_account.try_borrow()?;
        let registry = AuthorityConsentRegistry::load(&bytes)?;
        registry.validate_identity(
            consent_account.address(),
            subscriber,
            mint.address(),
            source.address(),
            token_program.address(),
        )?;
        (registry.authority_generation, registry.status)
    };
    if registry_status != AUTHORITY_REGISTRY_ACTIVE {
        return Err(SubscriptionsError::Unauthorized.into());
    }

    {
        let bytes = authority_account.try_borrow()?;
        let authority = VNextSubscriptionAuthority::load(&bytes)?;
        authority.validate_identity(
            authority_account.address(),
            subscriber,
            mint.address(),
            source.address(),
            consent_account.address(),
            token_program.address(),
            generation,
        )?;
    }

    {
        let source_data = source.try_borrow()?;
        check_token_account_owner(&source_data, subscriber)?;
        check_token_account_mint(&source_data, mint.address())?;
        let delegate = get_token_account_delegate(&source_data)?;
        if delegate != Some(*authority_account.address()) {
            return Err(SubscriptionsError::Unauthorized.into());
        }
    }

    let expected_ata = Address::find_program_address(
        &[subscriber.as_ref(), token_program.address().as_ref(), mint.address().as_ref()],
        &pinocchio_associated_token_account::ID,
    )
    .0;
    if expected_ata == *source.address() {
        return Err(SubscriptionsError::NonAssociatedSourceAccountRequired.into());
    }

    Ok(generation)
}

fn validate_lifecycle_registry(
    registry_account: &mut AccountView,
    plan: &Address,
    subscriber: &Address,
    source: &Address,
) -> ProgramResult {
    ProgramAccount::check(registry_account)?;
    let bytes = registry_account.try_borrow()?;
    SubscriptionLifecycleRegistry::load(&bytes)?.validate_identity(registry_account.address(), plan, subscriber, source)
}

fn advance_lifecycle(
    registry_account: &AccountView,
    plan: &Address,
    subscriber: &Address,
    source: &Address,
    expected_revision: u64,
    expected_nonce: u64,
) -> Result<u64, ProgramError> {
    validate_lifecycle_registry(registry_account, plan, subscriber, source)?;
    let mut bytes = registry_account.try_borrow_mut()?;
    SubscriptionLifecycleRegistry::load_mut(&mut bytes)?.advance(expected_revision, expected_nonce)
}

fn transfer_with_vnext_delegate(
    amount: u64,
    subscriber: &Address,
    mint: &AccountView,
    source: &AccountView,
    destination: &AccountView,
    authority: &AccountView,
    token_program: &AccountView,
    remaining: &[AccountView],
) -> ProgramResult {
    let bump = {
        let bytes = authority.try_borrow()?;
        VNextSubscriptionAuthority::load(&bytes)?.bump
    };
    let decimals_and_hook = {
        let bytes = mint.try_borrow()?;
        let decimals = *bytes.get(MINT_DECIMALS_OFFSET).ok_or(SubscriptionsError::InvalidAccountData)?;
        let hook = mint_transfer_hook_program_id(&bytes)?;
        (decimals, hook)
    };

    {
        let source_data = source.try_borrow()?;
        check_token_account_owner(&source_data, subscriber)?;
        check_token_account_mint(&source_data, mint.address())?;
    }
    {
        let destination_data = destination.try_borrow()?;
        check_token_account_mint(&destination_data, mint.address())?;
    }

    let bump_bytes = [bump];
    let seeds = [
        Seed::from(VNextSubscriptionAuthority::SEED),
        Seed::from(subscriber.as_ref()),
        Seed::from(mint.address().as_ref()),
        Seed::from(source.address().as_ref()),
        Seed::from(&bump_bytes),
    ];
    let signers = [Signer::from(&seeds)];

    if decimals_and_hook.1.is_some() {
        return invoke_transfer_checked_with_hook(
            token_program.address(),
            source,
            mint,
            destination,
            authority,
            remaining,
            amount,
            decimals_and_hook.0,
            &signers,
        );
    }

    TransferChecked {
        from: source,
        mint,
        to: destination,
        authority,
        amount,
        decimals: decimals_and_hook.0,
        token_program: token_program.address(),
    }
    .invoke_signed(&signers)?;

    Ok(())
}

/// Creates a VNext Subscription against a non-ATA source and the exact active
/// Authority consent lineage. No legacy SubscriptionDelegation is touched.
pub fn process_subscribe(accounts: &mut [AccountView], data: &VNextSubscribeData) -> ProgramResult {
    let [subscriber, merchant, plan_account, plan_revision_account, subscription_account, lifecycle_registry_account, consent_account, authority_account, mint, source, system_program, token_program, event_authority, self_program] =
        accounts
    else {
        return Err(SubscriptionsError::NotEnoughAccountKeys.into());
    };

    SignerAccount::check(subscriber)?;
    WritableAccount::check(subscriber)?;
    WritableAccount::check(subscription_account)?;
    WritableAccount::check(lifecycle_registry_account)?;
    WritableAccount::check(source)?;
    SystemAccount::check(system_program)?;

    let now = Clock::get()?.unix_timestamp;
    AuthorityConsentRegistry::validate_action_deadline(now, data.not_after_ts)?;

    let (expected_plan, expected_bump) = VNextPlan::find_pda(merchant.address(), data.plan_id);
    if expected_plan != *plan_account.address() || expected_bump != data.plan_bump {
        return Err(SubscriptionsError::InvalidPlanPda.into());
    }

    let (plan_owner, plan_revision, plan_nonce) = validate_plan_revision(plan_account, plan_revision_account)?;
    if plan_owner != *merchant.address()
        || plan_revision != data.expected_plan_revision
        || plan_nonce != data.expected_plan_nonce
    {
        return Err(SubscriptionsError::StalePlanRevision.into());
    }

    let (plan_mint, plan_amount, plan_period, plan_created_at, plan_status, plan_end_ts, plan_terms) = {
        let bytes = plan_account.try_borrow()?;
        let plan = VNextPlan::load(&bytes)?;
        (
            plan.data.mint,
            plan.data.terms.amount,
            plan.data.terms.period_hours,
            plan.data.terms.created_at,
            plan.status,
            plan.data.end_ts,
            plan.data.terms,
        )
    };
    if plan_status != PlanStatus::Active as u8 {
        return Err(SubscriptionsError::PlanSunset.into());
    }
    if plan_end_ts != 0 {
        return Err(SubscriptionsError::InvalidEndTs.into());
    }
    if plan_mint != data.expected_mint
        || plan_mint != *mint.address()
        || plan_amount != data.expected_amount
        || plan_period != data.expected_period_hours
        || plan_created_at != data.expected_created_at
    {
        return Err(SubscriptionsError::PlanTermsMismatch.into());
    }

    let (expected_subscription, subscription_bump) =
        VNextSubscription::find_pda(plan_account.address(), subscriber.address(), source.address());
    if expected_subscription != *subscription_account.address() {
        return Err(SubscriptionsError::InvalidSubscriptionPda.into());
    }
    let (expected_lifecycle, lifecycle_bump) =
        SubscriptionLifecycleRegistry::find_pda(plan_account.address(), subscriber.address(), source.address());
    if expected_lifecycle != *lifecycle_registry_account.address() {
        return Err(SubscriptionsError::SubscriptionLifecycleRegistryInvalidPda.into());
    }

    let generation = validate_vnext_authority(
        subscriber.address(),
        mint,
        source,
        token_program,
        consent_account,
        authority_account,
    )?;
    if generation != data.expected_authority_generation {
        return Err(SubscriptionsError::VNextAuthorityIdentityMismatch.into());
    }

    if lifecycle_registry_account.data_len() == 0 {
        if lifecycle_registry_account.owned_by(&crate::ID) || subscription_account.data_len() > 0 {
            return Err(SubscriptionsError::LifecycleRegistryIdentityMismatch.into());
        }
        if data.expected_lifecycle_revision != 0 || data.expected_lifecycle_nonce != 0 {
            return Err(SubscriptionsError::StaleSubscriptionLifecycleRevision.into());
        }
        let bump_bytes = [lifecycle_bump];
        let seeds = [
            Seed::from(SubscriptionLifecycleRegistry::SEED),
            Seed::from(plan_account.address().as_ref()),
            Seed::from(subscriber.address().as_ref()),
            Seed::from(source.address().as_ref()),
            Seed::from(&bump_bytes),
        ];
        ProgramAccount::init::<SubscriptionLifecycleRegistry>(
            subscriber,
            lifecycle_registry_account,
            &seeds,
            SubscriptionLifecycleRegistry::LEN,
        )?;
        let mut bytes = lifecycle_registry_account.try_borrow_mut()?;
        SubscriptionLifecycleRegistry::init(
            &mut bytes,
            plan_account.address(),
            subscriber.address(),
            source.address(),
            subscriber.address(),
            lifecycle_bump,
        )?;
    } else {
        validate_lifecycle_registry(
            lifecycle_registry_account,
            plan_account.address(),
            subscriber.address(),
            source.address(),
        )?;
    }

    // A re-subscribe can reuse this VNext Subscription PDA only after the previous
    // cancellation window has ended. The permanent Registry revision is never reset.
    if subscription_account.data_len() > 0 {
        ProgramAccount::check(subscription_account)?;
        let bytes = subscription_account.try_borrow()?;
        let existing = VNextSubscription::load(&bytes)?;
        existing.validate_identity(
            subscription_account.address(),
            plan_account.address(),
            subscriber.address(),
            source.address(),
        )?;
        if existing.expires_at_ts == 0 || now < existing.expires_at_ts {
            return Err(SubscriptionsError::AlreadySubscribed.into());
        }
    } else if subscription_account.owned_by(&crate::ID) {
        return Err(SubscriptionsError::InvalidAccountData.into());
    }

    let new_lifecycle_revision = advance_lifecycle(
        lifecycle_registry_account,
        plan_account.address(),
        subscriber.address(),
        source.address(),
        data.expected_lifecycle_revision,
        data.expected_lifecycle_nonce,
    )?;

    if subscription_account.data_len() == 0 {
        let bump_bytes = [subscription_bump];
        let seeds = [
            Seed::from(VNextSubscription::SEED),
            Seed::from(plan_account.address().as_ref()),
            Seed::from(subscriber.address().as_ref()),
            Seed::from(source.address().as_ref()),
            Seed::from(&bump_bytes),
        ];
        ProgramAccount::init::<VNextSubscription>(subscriber, subscription_account, &seeds, VNextSubscription::LEN)?;
    }

    {
        let mut bytes = subscription_account.try_borrow_mut()?;
        VNextSubscription::init(
            &mut bytes,
            plan_account.address(),
            subscriber.address(),
            source.address(),
            mint.address(),
            token_program.address(),
            subscriber.address(),
            &plan_terms,
            now,
            new_lifecycle_revision,
            generation,
            subscription_bump,
        )?;
    }

    let event = SubscriptionCreatedEvent::new(
        *plan_account.address(),
        *subscriber.address(),
        *mint.address(),
        now,
        *subscriber.address(),
    );
    let event_data = event.to_bytes();
    event_engine::emit_event(&crate::ID, event_authority, self_program, &event_data)?;

    Ok(())
}

/// Regular cancellation allows pulls only through the current on-chain period boundary.
pub fn process_cancel(accounts: &mut [AccountView], data: &RevisionActionData) -> ProgramResult {
    let [subscriber, plan_account, plan_revision_account, subscription_account, lifecycle_registry_account, event_authority, self_program] =
        accounts
    else {
        return Err(SubscriptionsError::NotEnoughAccountKeys.into());
    };

    SignerAccount::check(subscriber)?;
    WritableAccount::check(subscription_account)?;
    WritableAccount::check(lifecycle_registry_account)?;
    let now = Clock::get()?.unix_timestamp;
    AuthorityConsentRegistry::validate_action_deadline(now, data.not_after_ts)?;
    validate_plan_revision(plan_account, plan_revision_account)?;

    let (source, expires_at, current_start, period_hours) = {
        let bytes = subscription_account.try_borrow()?;
        let sub = VNextSubscription::load(&bytes)?;
        let source_account = sub.source_token_account;
        sub.validate_identity(
            subscription_account.address(),
            plan_account.address(),
            subscriber.address(),
            &source_account,
        )?;
        (sub.source_token_account, sub.expires_at_ts, sub.current_period_start_ts, sub.terms.period_hours)
    };
    if expires_at != 0 {
        return Err(SubscriptionsError::SubscriptionAlreadyCancelled.into());
    }
    let period_secs =
        period_hours.checked_mul(crate::constants::SECS_PER_HOUR).ok_or(SubscriptionsError::ArithmeticOverflow)?;
    let period_secs_i64 = i64::try_from(period_secs).map_err(|_| SubscriptionsError::InvalidPeriodLength)?;
    if period_secs_i64 == 0 || now < current_start {
        return Err(SubscriptionsError::DelegationNotStarted.into());
    }
    let elapsed = now.checked_sub(current_start).ok_or(SubscriptionsError::ArithmeticUnderflow)?;
    let elapsed_periods = elapsed / period_secs_i64;
    let next_period = elapsed_periods.checked_add(1).ok_or(SubscriptionsError::ArithmeticOverflow)?;
    let offset = next_period.checked_mul(period_secs_i64).ok_or(SubscriptionsError::ArithmeticOverflow)?;
    let expiry = current_start.checked_add(offset).ok_or(SubscriptionsError::ArithmeticOverflow)?;

    let new_revision = advance_lifecycle(
        lifecycle_registry_account,
        plan_account.address(),
        subscriber.address(),
        &source,
        data.expected_revision,
        data.expected_nonce,
    )?;
    {
        let mut bytes = subscription_account.try_borrow_mut()?;
        let sub = VNextSubscription::load_mut(&mut bytes)?;
        sub.expires_at_ts = expiry;
        sub.lifecycle_revision = new_revision;
    }

    let event = SubscriptionCancelledEvent::new(*plan_account.address(), *subscriber.address(), expiry);
    let event_data = event.to_bytes();
    event_engine::emit_event(&crate::ID, event_authority, self_program, &event_data)?;
    Ok(())
}

/// Immediate cancellation requires the current Plan owner and the subscriber to sign.
pub fn process_cancel_now(accounts: &mut [AccountView], data: &RevisionActionData) -> ProgramResult {
    let [subscriber, merchant, plan_account, plan_revision_account, subscription_account, lifecycle_registry_account, event_authority, self_program] =
        accounts
    else {
        return Err(SubscriptionsError::NotEnoughAccountKeys.into());
    };

    SignerAccount::check(subscriber)?;
    SignerAccount::check(merchant)?;
    WritableAccount::check(subscription_account)?;
    WritableAccount::check(lifecycle_registry_account)?;
    let now = Clock::get()?.unix_timestamp;
    AuthorityConsentRegistry::validate_action_deadline(now, data.not_after_ts)?;

    let (owner, _, _) = validate_plan_revision(plan_account, plan_revision_account)?;
    if owner != *merchant.address() {
        return Err(SubscriptionsError::NotPlanOwner.into());
    }

    let source = {
        let bytes = subscription_account.try_borrow()?;
        let sub = VNextSubscription::load(&bytes)?;
        let source_account = sub.source_token_account;
        sub.validate_identity(
            subscription_account.address(),
            plan_account.address(),
            subscriber.address(),
            &source_account,
        )?;
        if sub.expires_at_ts != 0 && now >= sub.expires_at_ts {
            return Err(SubscriptionsError::SubscriptionCancelled.into());
        }
        sub.source_token_account
    };

    let new_revision = advance_lifecycle(
        lifecycle_registry_account,
        plan_account.address(),
        subscriber.address(),
        &source,
        data.expected_revision,
        data.expected_nonce,
    )?;
    {
        let mut bytes = subscription_account.try_borrow_mut()?;
        let sub = VNextSubscription::load_mut(&mut bytes)?;
        sub.expires_at_ts = now;
        sub.lifecycle_revision = new_revision;
    }

    let event = SubscriptionCancelledEvent::new(*plan_account.address(), *subscriber.address(), now);
    let event_data = event.to_bytes();
    event_engine::emit_event(&crate::ID, event_authority, self_program, &event_data)?;
    Ok(())
}

/// Resume is allowed only before the prior cancellation boundary and only while
/// the exact source-account consent generation remains active.
pub fn process_resume(accounts: &mut [AccountView], data: &RevisionActionData) -> ProgramResult {
    let [subscriber, plan_account, plan_revision_account, subscription_account, lifecycle_registry_account, consent_account, authority_account, mint, source, token_program, event_authority, self_program] =
        accounts
    else {
        return Err(SubscriptionsError::NotEnoughAccountKeys.into());
    };

    SignerAccount::check(subscriber)?;
    WritableAccount::check(subscription_account)?;
    WritableAccount::check(lifecycle_registry_account)?;
    let now = Clock::get()?.unix_timestamp;
    AuthorityConsentRegistry::validate_action_deadline(now, data.not_after_ts)?;
    validate_plan_revision(plan_account, plan_revision_account)?;

    let generation = validate_vnext_authority(
        subscriber.address(),
        mint,
        source,
        token_program,
        consent_account,
        authority_account,
    )?;
    let (stored_source, stored_mint, stored_program, expires_at) = {
        let bytes = subscription_account.try_borrow()?;
        let sub = VNextSubscription::load(&bytes)?;
        sub.validate_identity(
            subscription_account.address(),
            plan_account.address(),
            subscriber.address(),
            source.address(),
        )?;
        (sub.source_token_account, sub.mint, sub.token_program, sub.expires_at_ts)
    };
    if stored_source != *source.address()
        || stored_mint != *mint.address()
        || stored_program != *token_program.address()
    {
        return Err(SubscriptionsError::LifecycleRegistryIdentityMismatch.into());
    }
    if expires_at == 0 {
        return Err(SubscriptionsError::SubscriptionNotCancelled.into());
    }
    if now >= expires_at {
        return Err(SubscriptionsError::SubscriptionCancelled.into());
    }
    {
        let bytes = subscription_account.try_borrow()?;
        if VNextSubscription::load(&bytes)?.authority_generation != generation {
            return Err(SubscriptionsError::VNextAuthorityIdentityMismatch.into());
        }
    }

    let new_revision = advance_lifecycle(
        lifecycle_registry_account,
        plan_account.address(),
        subscriber.address(),
        source.address(),
        data.expected_revision,
        data.expected_nonce,
    )?;
    {
        let mut bytes = subscription_account.try_borrow_mut()?;
        let sub = VNextSubscription::load_mut(&mut bytes)?;
        sub.expires_at_ts = 0;
        sub.lifecycle_revision = new_revision;
    }

    let event = SubscriptionResumedEvent::new(*plan_account.address(), *subscriber.address(), now);
    let event_data = event.to_bytes();
    event_engine::emit_event(&crate::ID, event_authority, self_program, &event_data)?;
    Ok(())
}

/// Every VNext pull revalidates the permanent Plan/Subscription revisions,
/// consent generation, Authority tuple, source delegate, caller, and destination.
pub fn process_transfer(accounts: &mut [AccountView], transfer_data: &crate::TransferData) -> ProgramResult {
    let [subscription_account, plan_account, plan_revision_account, lifecycle_registry_account, consent_account, authority_account, source, destination, caller, mint, token_program, event_authority, self_program, remaining @ ..] =
        accounts
    else {
        return Err(SubscriptionsError::NotEnoughAccountKeys.into());
    };

    ProgramAccount::check(subscription_account)?;
    ProgramAccount::check(plan_account)?;
    WritableAccount::check(subscription_account)?;
    WritableAccount::check(source)?;
    WritableAccount::check(destination)?;
    SignerAccount::check(caller)?;
    TokenProgramInterface::check(token_program)?;
    MintInterface::check_with_program(mint, token_program)?;
    TokenAccountInterface::check_accounts_with_program(token_program, &[source, destination])?;

    let now = Clock::get()?.unix_timestamp;
    let (_, _, _) = validate_plan_revision(plan_account, plan_revision_account)?;
    let (
        stored_plan,
        subscriber,
        stored_source,
        stored_mint,
        stored_token_program,
        terms,
        authority_generation,
        mut period_start,
        mut amount_pulled,
        expires_at,
        lifecycle_revision,
    ) = {
        let bytes = subscription_account.try_borrow()?;
        let sub = VNextSubscription::load(&bytes)?;
        (
            sub.plan,
            sub.subscriber,
            sub.source_token_account,
            sub.mint,
            sub.token_program,
            sub.terms,
            sub.authority_generation,
            sub.current_period_start_ts,
            sub.amount_pulled_in_period,
            sub.expires_at_ts,
            sub.lifecycle_revision,
        )
    };

    let (expected_subscription, _) = VNextSubscription::find_pda(&stored_plan, &subscriber, &stored_source);
    if expected_subscription != *subscription_account.address() || stored_plan != *plan_account.address() {
        return Err(SubscriptionsError::InvalidSubscriptionPda.into());
    }

    if stored_source != *source.address()
        || stored_mint != *mint.address()
        || stored_token_program != *token_program.address()
        || transfer_data.delegator != subscriber
        || transfer_data.mint != stored_mint
    {
        return Err(SubscriptionsError::LifecycleRegistryIdentityMismatch.into());
    }

    let (plan_status, plan_mint, plan_terms, plan_end_ts) = {
        let bytes = plan_account.try_borrow()?;
        let plan = VNextPlan::load(&bytes)?;
        PlanStatus::try_from(plan.status)?;
        plan.can_pull(caller.address())?;
        (plan.status, plan.data.mint, plan.data.terms, plan.data.end_ts)
    };
    if plan_end_ts != 0 {
        return Err(SubscriptionsError::InvalidEndTs.into());
    }
    if plan_mint != stored_mint
        || plan_terms.amount != terms.amount
        || plan_terms.period_hours != terms.period_hours
        || plan_terms.created_at != terms.created_at
    {
        return Err(SubscriptionsError::PlanTermsMismatch.into());
    }
    if expires_at != 0 && now >= expires_at {
        return Err(SubscriptionsError::SubscriptionCancelled.into());
    }

    validate_lifecycle_registry(lifecycle_registry_account, plan_account.address(), &subscriber, &stored_source)?;
    {
        let bytes = lifecycle_registry_account.try_borrow()?;
        let registry = SubscriptionLifecycleRegistry::load(&bytes)?;
        if registry.revision != lifecycle_revision {
            return Err(SubscriptionsError::StaleSubscriptionLifecycleRevision.into());
        }
    }

    let generation =
        validate_vnext_authority(&subscriber, mint, source, token_program, consent_account, authority_account)?;
    if generation != authority_generation {
        return Err(SubscriptionsError::VNextAuthorityIdentityMismatch.into());
    }

    let receiver_owner = {
        let bytes = destination.try_borrow()?;
        check_token_account_mint(&bytes, mint.address())?;
        get_token_account_owner(&bytes)?
    };
    {
        let bytes = plan_account.try_borrow()?;
        VNextPlan::load(&bytes)?.check_destination(&receiver_owner)?;
    }

    let period_length = terms.period_length_secs()?;
    validate_recurring_transfer(
        transfer_data.amount,
        terms.amount,
        period_length,
        &mut period_start,
        &mut amount_pulled,
        0,
        now,
    )?;

    {
        let mut bytes = subscription_account.try_borrow_mut()?;
        let sub = VNextSubscription::load_mut(&mut bytes)?;
        sub.current_period_start_ts = period_start;
        sub.amount_pulled_in_period = amount_pulled;
    }

    transfer_with_vnext_delegate(
        transfer_data.amount,
        &subscriber,
        mint,
        source,
        destination,
        authority_account,
        token_program,
        remaining,
    )?;

    let period_length_i64 = i64::try_from(period_length).map_err(|_| SubscriptionsError::InvalidPeriodLength)?;
    let period_end = period_start.checked_add(period_length_i64).ok_or(SubscriptionsError::ArithmeticOverflow)?;
    let event = SubscriptionTransferEvent::new(
        *subscription_account.address(),
        *plan_account.address(),
        subscriber,
        *mint.address(),
        transfer_data.amount,
        period_start,
        period_end,
        amount_pulled,
        receiver_owner,
        *destination.address(),
        *caller.address(),
    );
    let event_data = event.to_bytes();
    event_engine::emit_event(&crate::ID, event_authority, self_program, &event_data)?;
    let _ = plan_status;
    Ok(())
}
