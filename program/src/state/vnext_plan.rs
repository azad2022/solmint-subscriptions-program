//! Versioned VNext Plan namespace. The legacy Plan account and its ABI remain unchanged.

use codama::CodamaAccount;
use core::mem::{size_of, transmute};
use pinocchio::{error::ProgramError, Address};

use crate::{
    instructions::create_plan::PlanData,
    state::common::{AccountDiscriminator, PlanStatus},
    SubscriptionsError,
};

/// PDA seeds: [planVNext, merchant, plan_id_le].
#[repr(C, packed)]
#[derive(CodamaAccount)]
#[codama(seed(type = string(utf8), value = "planVNext"))]
#[codama(seed(name = "merchant", type = public_key))]
#[codama(seed(name = "planId", type = number(u64)))]
pub struct VNextPlan {
    pub discriminator: u8,
    pub version: u8,
    pub bump: u8,
    pub status: u8,
    pub owner: Address,
    pub revision: u64,
    pub data: PlanData,
}

impl VNextPlan {
    pub const LEN: usize = size_of::<Self>();
    pub const V1_LEN: usize = 500;
    pub const VERSION: u8 = 1;
    pub const SEED: &'static [u8] = b"planVNext";

    pub fn find_pda(owner: &Address, plan_id: u64) -> (Address, u8) {
        Address::find_program_address(&[Self::SEED, owner.as_ref(), &plan_id.to_le_bytes()], &crate::ID)
    }

    pub fn verify_pda(owner: &Address, plan_id: u64, bump: u8) -> Result<Address, ProgramError> {
        Address::create_program_address(
            &[Self::SEED, owner.as_ref(), &plan_id.to_le_bytes(), &[bump]],
            &crate::ID,
        )
        .map_err(|_| SubscriptionsError::InvalidPlanPda.into())
    }

    pub fn init(
        bytes: &mut [u8],
        owner: &Address,
        bump: u8,
        status: u8,
        revision: u64,
        data: &PlanData,
    ) -> Result<(), ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        let account = unsafe { &mut *transmute::<*mut u8, *mut Self>(bytes.as_mut_ptr()) };
        account.discriminator = AccountDiscriminator::VNextPlan.into();
        account.version = Self::VERSION;
        account.bump = bump;
        account.status = status;
        account.owner = *owner;
        account.revision = revision;
        unsafe {
            core::ptr::copy_nonoverlapping(
                data as *const PlanData as *const u8,
                core::ptr::addr_of_mut!((*account).data) as *mut u8,
                PlanData::LEN,
            );
        }
        Ok(())
    }

    pub fn load(bytes: &[u8]) -> Result<&Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        if bytes[0] != AccountDiscriminator::VNextPlan as u8 {
            return Err(SubscriptionsError::InvalidAccountDiscriminator.into());
        }
        if bytes[1] != Self::VERSION {
            return Err(SubscriptionsError::MigrationRequired.into());
        }
        let status = bytes[3];
        PlanStatus::try_from(status).map_err(|_| SubscriptionsError::InvalidPlanStatus)?;
        Ok(unsafe { &*transmute::<*const u8, *const Self>(bytes.as_ptr()) })
    }

    pub fn load_mut(bytes: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        if bytes[0] != AccountDiscriminator::VNextPlan as u8 {
            return Err(SubscriptionsError::InvalidAccountDiscriminator.into());
        }
        if bytes[1] != Self::VERSION {
            return Err(SubscriptionsError::MigrationRequired.into());
        }
        let status = bytes[3];
        PlanStatus::try_from(status).map_err(|_| SubscriptionsError::InvalidPlanStatus)?;
        Ok(unsafe { &mut *transmute::<*mut u8, *mut Self>(bytes.as_mut_ptr()) })
    }

    pub fn validate_identity(&self, account: &Address, owner: &Address) -> Result<(), ProgramError> {
        if self.owner != *owner {
            return Err(SubscriptionsError::NotPlanOwner.into());
        }
        let plan_id = self.data.plan_id;
        let expected = Self::verify_pda(owner, plan_id, self.bump)?;
        if expected != *account {
            return Err(SubscriptionsError::InvalidPlanPda.into());
        }
        Ok(())
    }

    pub fn can_pull(&self, caller: &Address) -> Result<(), ProgramError> {
        if *caller == self.owner {
            return Ok(());
        }
        let pullers = self.data.pullers;
        let zero = Address::default();
        if pullers.iter().any(|puller| *puller != zero && puller == caller) {
            return Ok(());
        }
        Err(SubscriptionsError::Unauthorized.into())
    }

    pub fn check_destination(&self, receiver_owner: &Address) -> Result<(), ProgramError> {
        let destinations = self.data.destinations;
        let zero = Address::default();
        let mut has_configured = false;
        for destination in destinations.iter() {
            if *destination == zero {
                continue;
            }
            if destination == receiver_owner {
                return Ok(());
            }
            has_configured = true;
        }
        if has_configured {
            return Err(SubscriptionsError::UnauthorizedDestination.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(seed: u8) -> Address {
        Address::from([seed; 32])
    }

    #[test]
    fn v1_layout_is_frozen_at_500_bytes() {
        assert_eq!(VNextPlan::LEN, VNextPlan::V1_LEN);
        assert_eq!(core::mem::offset_of!(VNextPlan, owner), 4);
        assert_eq!(core::mem::offset_of!(VNextPlan, revision), 36);
        assert_eq!(core::mem::offset_of!(VNextPlan, data), 44);
    }

    #[test]
    fn plan_pda_binds_merchant_and_plan_id() {
        let first = VNextPlan::find_pda(&addr(1), 7).0;
        let other_owner = VNextPlan::find_pda(&addr(2), 7).0;
        let other_id = VNextPlan::find_pda(&addr(1), 8).0;
        assert_ne!(first, other_owner);
        assert_ne!(first, other_id);
    }
}
