use codama::CodamaType;
use core::mem::{size_of, transmute};
use pinocchio::{
    cpi::Seed,
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};

use crate::{
    event_engine::{self, EventSerialize},
    events::PlanUpdatedEvent,
    instructions::create_plan::{PlanData, MAX_PLAN_PERIOD_HOURS},
    state::{
        common::{AccountDiscriminator, PlanStatus},
        AuthorityConsentRegistry, PlanRevisionRegistry, VNextPlan,
    },
    AccountCheck, MintInterface, ProgramAccount, ProgramAccountInit, SignerAccount, SubscriptionsError, SystemAccount,
    TokenProgramInterface, WritableAccount,
};

pub const CREATE_DISCRIMINATOR: &u8 = &20;
pub const UPDATE_DISCRIMINATOR: &u8 = &21;

/// Customer-signed Plan creation envelope. The deadline bounds delayed first execution.
#[repr(C, packed)]
#[derive(CodamaType, Debug, Clone)]
pub struct VNextCreatePlanData {
    pub not_after_ts: i64,
    pub plan_data: PlanData,
}

impl VNextCreatePlanData {
    pub const LEN: usize = size_of::<Self>();

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidInstructionData.into());
        }
        Ok(unsafe { &*transmute::<*const u8, *const Self>(data.as_ptr()) })
    }
}

/// Exact monotonic Plan action identity and on-chain deadline.
#[repr(C, packed)]
#[derive(CodamaType, Debug, Clone)]
pub struct PlanRevisionActionData {
    pub expected_revision: u64,
    pub expected_nonce: u64,
    pub not_after_ts: i64,
}

impl PlanRevisionActionData {
    pub const LEN: usize = size_of::<Self>();

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidInstructionData.into());
        }
        Ok(unsafe { &*transmute::<*const u8, *const Self>(data.as_ptr()) })
    }
}

/// VNext mutable Plan fields. Immutable billing terms are intentionally absent.
#[repr(C, packed)]
#[derive(CodamaType, Debug, Clone)]
pub struct VNextPlanUpdateData {
    pub expected_revision: u64,
    pub expected_nonce: u64,
    pub not_after_ts: i64,
    pub expected_status: u8,
    pub status: u8,
    pub expected_pullers: [Address; 4],
    pub pullers: [Address; 4],
    #[codama(type = fixed_size(string(utf8), 128))]
    pub expected_metadata_uri: [u8; 128],
    #[codama(type = fixed_size(string(utf8), 128))]
    pub metadata_uri: [u8; 128],
}

impl VNextPlanUpdateData {
    pub const LEN: usize = size_of::<Self>();

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidInstructionData.into());
        }
        Ok(unsafe { &*transmute::<*const u8, *const Self>(data.as_ptr()) })
    }
}

/// Creates a VNext Plan and its permanent monotonic revision Registry.
/// Finite Plans are rejected in VNext v1: a full billing period must always fit.
pub fn process_create(accounts: &mut [AccountView], data: &VNextCreatePlanData) -> ProgramResult {
    let [merchant, plan_pda, revision_registry, token_mint, system_program, token_program] = accounts else {
        return Err(SubscriptionsError::NotEnoughAccountKeys.into());
    };

    SignerAccount::check(merchant)?;
    WritableAccount::check(merchant)?;
    WritableAccount::check(plan_pda)?;
    WritableAccount::check(revision_registry)?;
    SystemAccount::check(system_program)?;
    TokenProgramInterface::check(token_program)?;
    MintInterface::check_with_program(token_mint, token_program)?;

    let now = Clock::get()?.unix_timestamp;
    AuthorityConsentRegistry::validate_action_deadline(now, data.not_after_ts)?;
    let plan_data = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(data.plan_data)) };
    plan_data.validate(now)?;
    if plan_data.end_ts != 0 {
        return Err(SubscriptionsError::InvalidEndTs.into());
    }
    if plan_data.terms.period_hours == 0 || plan_data.terms.period_hours > MAX_PLAN_PERIOD_HOURS {
        return Err(SubscriptionsError::InvalidPeriodLength.into());
    }
    let supplied_mint = plan_data.mint;
    if token_mint.address() != &supplied_mint {
        return Err(SubscriptionsError::MintMismatch.into());
    }

    let (expected_plan, plan_bump) = VNextPlan::find_pda(merchant.address(), plan_data.plan_id);
    if expected_plan != *plan_pda.address() {
        return Err(SubscriptionsError::InvalidPlanPda.into());
    }
    let (expected_registry, registry_bump) = PlanRevisionRegistry::find_pda(merchant.address(), plan_pda.address());
    if expected_registry != *revision_registry.address() {
        return Err(SubscriptionsError::PlanRevisionRegistryInvalidPda.into());
    }

    // A Plan or its persistent Registry may never be silently reset or recreated.
    if plan_pda.data_len() != 0 || plan_pda.owned_by(&crate::ID) {
        return Err(SubscriptionsError::PlanAlreadyExists.into());
    }
    if revision_registry.data_len() != 0 || revision_registry.owned_by(&crate::ID) {
        return Err(SubscriptionsError::StalePlanRevision.into());
    }

    let plan_id_bytes = plan_data.plan_id.to_le_bytes();
    let plan_bump_bytes = [plan_bump];
    let plan_seeds = [
        Seed::from(VNextPlan::SEED),
        Seed::from(merchant.address().as_ref()),
        Seed::from(&plan_id_bytes),
        Seed::from(&plan_bump_bytes),
    ];
    ProgramAccount::init::<VNextPlan>(merchant, plan_pda, &plan_seeds, VNextPlan::LEN)?;

    let registry_bump_bytes = [registry_bump];
    let registry_seeds = [
        Seed::from(PlanRevisionRegistry::SEED),
        Seed::from(merchant.address().as_ref()),
        Seed::from(plan_pda.address().as_ref()),
        Seed::from(&registry_bump_bytes),
    ];
    ProgramAccount::init::<PlanRevisionRegistry>(
        merchant,
        revision_registry,
        &registry_seeds,
        PlanRevisionRegistry::LEN,
    )?;

    let revision = {
        let mut bytes = revision_registry.try_borrow_mut()?;
        PlanRevisionRegistry::init(
            &mut bytes,
            plan_pda.address(),
            merchant.address(),
            merchant.address(),
            registry_bump,
        )?;
        PlanRevisionRegistry::load_mut(&mut bytes)?.advance(0, 0)?
    };

    {
        let mut bytes = plan_pda.try_borrow_mut()?;
        VNextPlan::init(&mut bytes, merchant.address(), plan_bump, PlanStatus::Active as u8, revision, &plan_data)?;
        let plan = VNextPlan::load_mut(&mut bytes)?;
        plan.data.terms.created_at = now;
    }

    Ok(())
}

/// Applies a revision- and deadline-bound update. Plan terms, mint, and end_ts
/// cannot be changed. Sunset is one-way; after sunset, only puller removals remain.
pub fn process_update(accounts: &mut [AccountView], data: &VNextPlanUpdateData) -> ProgramResult {
    let [merchant, plan_pda, revision_registry, event_authority, self_program] = accounts else {
        return Err(SubscriptionsError::NotEnoughAccountKeys.into());
    };

    SignerAccount::check(merchant)?;
    WritableAccount::check(plan_pda)?;
    WritableAccount::check(revision_registry)?;
    ProgramAccount::check(plan_pda)?;
    ProgramAccount::check(revision_registry)?;

    let now = Clock::get()?.unix_timestamp;
    AuthorityConsentRegistry::validate_action_deadline(now, data.not_after_ts)?;

    let (owner, plan_revision, current_status, current_pullers, current_metadata, plan_id) = {
        let bytes = plan_pda.try_borrow()?;
        let plan = VNextPlan::load(&bytes)?;
        (plan.owner, plan.revision, plan.status, plan.data.pullers, plan.data.metadata_uri, plan.data.plan_id)
    };

    if owner != *merchant.address() {
        return Err(SubscriptionsError::NotPlanOwner.into());
    }
    let (expected_plan, _) = VNextPlan::find_pda(merchant.address(), plan_id);
    if expected_plan != *plan_pda.address() {
        return Err(SubscriptionsError::InvalidPlanPda.into());
    }

    {
        let bytes = revision_registry.try_borrow()?;
        PlanRevisionRegistry::load(&bytes)?.validate_identity(
            revision_registry.address(),
            merchant.address(),
            plan_pda.address(),
        )?;
        let registry = PlanRevisionRegistry::load(&bytes)?;
        if registry.revision != plan_revision || registry.revision != data.expected_revision {
            return Err(SubscriptionsError::StalePlanRevision.into());
        }
        if registry.action_nonce != data.expected_nonce {
            return Err(SubscriptionsError::StaleLifecycleActionNonce.into());
        }
    }

    if current_status != data.expected_status
        || current_pullers != data.expected_pullers
        || current_metadata != data.expected_metadata_uri
    {
        return Err(SubscriptionsError::StalePlanApproval.into());
    }
    PlanStatus::try_from(data.status).map_err(|_| SubscriptionsError::InvalidPlanStatus)?;

    let zero = Address::default();
    if current_status == PlanStatus::Sunset as u8 {
        if data.status != PlanStatus::Sunset as u8 || data.metadata_uri != current_metadata {
            return Err(SubscriptionsError::PlanImmutableAfterSunset.into());
        }
        let requested_pullers = data.pullers;
        for candidate in requested_pullers.iter() {
            if *candidate != zero && !current_pullers.iter().any(|current| current == candidate) {
                return Err(SubscriptionsError::PlanImmutableAfterSunset.into());
            }
        }
    }

    let new_revision = {
        let mut bytes = revision_registry.try_borrow_mut()?;
        PlanRevisionRegistry::load_mut(&mut bytes)?.advance(data.expected_revision, data.expected_nonce)?
    };

    {
        let mut bytes = plan_pda.try_borrow_mut()?;
        let plan = VNextPlan::load_mut(&mut bytes)?;
        plan.status = data.status;
        plan.revision = new_revision;
        plan.data.pullers = data.pullers;
        plan.data.metadata_uri = data.metadata_uri;
    }

    let event = PlanUpdatedEvent::new(*plan_pda.address(), *merchant.address(), data.status, 0, data.pullers);
    let event_data = event.to_bytes();
    event_engine::emit_event(&crate::ID, event_authority, self_program, &event_data)?;

    Ok(())
}
