//! Persistent Plan administration revision state.
//!
//! The Plan PDA can be deleted and recreated at the same address. This registry
//! is a separate non-closeable lineage so an old owner signature cannot become
//! valid again after value changes, ABA restoration, or Plan recreation.

use codama::CodamaAccount;
use core::mem::{size_of, transmute};
use pinocchio::{error::ProgramError, Address};

use crate::{state::common::AccountDiscriminator, SubscriptionsError};

/// Persistent revision registry for one Plan PDA and its merchant.
///
/// PDA seeds: ["planRevision", merchant, plan_pda].
///
/// Layout (little-endian):
/// - 0 discriminator, 1 version, 2 bump, 3 reserved
/// - 4..36 Plan PDA
/// - 36..68 merchant
/// - 68..100 original rent payer
/// - 100..108 revision (u64)
/// - 108..116 action nonce (u64)
#[repr(C, packed)]
#[derive(CodamaAccount)]
#[codama(seed(type = string(utf8), value = "planRevision"))]
#[codama(seed(name = "merchant", type = public_key))]
#[codama(seed(name = "plan", type = public_key))]
pub struct PlanRevisionRegistry {
    /// Account discriminator.
    pub discriminator: u8,
    /// Schema version.
    pub version: u8,
    /// PDA bump.
    pub bump: u8,
    /// Reserved; must remain zero in v1.
    pub reserved: u8,
    /// Exact Plan PDA whose administration revision is tracked.
    pub plan: Address,
    /// Merchant/Plan owner.
    pub merchant: Address,
    /// Original account rent payer.
    pub rent_payer: Address,
    /// Monotonic Plan revision.
    pub revision: u64,
    /// Monotonic nonce consumed by every Plan state mutation.
    pub action_nonce: u64,
}

impl PlanRevisionRegistry {
    /// Exact v1 account length.
    pub const LEN: usize = size_of::<Self>();
    pub const V1_LEN: usize = 116;
    pub const VERSION: u8 = 1;
    pub const SEED: &'static [u8] = b"planRevision";

    /// Initializes a fresh Plan revision lineage.
    pub fn init(
        bytes: &mut [u8],
        plan: &Address,
        merchant: &Address,
        rent_payer: &Address,
        bump: u8,
    ) -> Result<(), ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        let account = unsafe { &mut *transmute::<*mut u8, *mut Self>(bytes.as_mut_ptr()) };
        account.discriminator = AccountDiscriminator::PlanRevisionRegistry.into();
        account.version = Self::VERSION;
        account.bump = bump;
        account.reserved = 0;
        account.plan = *plan;
        account.merchant = *merchant;
        account.rent_payer = *rent_payer;
        account.revision = 0;
        account.action_nonce = 0;
        Ok(())
    }

    /// Loads and validates a v1 Plan revision registry.
    pub fn load(bytes: &[u8]) -> Result<&Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        if bytes[0] != AccountDiscriminator::PlanRevisionRegistry as u8 {
            return Err(SubscriptionsError::InvalidAccountDiscriminator.into());
        }
        if bytes[1] != Self::VERSION {
            return Err(SubscriptionsError::MigrationRequired.into());
        }
        if bytes[3] != 0 {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        Ok(unsafe { &*transmute::<*const u8, *const Self>(bytes.as_ptr()) })
    }

    /// Loads a mutable v1 Plan revision registry.
    pub fn load_mut(bytes: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        if bytes[0] != AccountDiscriminator::PlanRevisionRegistry as u8 {
            return Err(SubscriptionsError::InvalidAccountDiscriminator.into());
        }
        if bytes[1] != Self::VERSION || bytes[3] != 0 {
            return Err(SubscriptionsError::MigrationRequired.into());
        }
        Ok(unsafe { &mut *transmute::<*mut u8, *mut Self>(bytes.as_mut_ptr()) })
    }

    /// Finds the canonical Plan revision Registry PDA.
    pub fn find_pda(merchant: &Address, plan: &Address) -> (Address, u8) {
        Address::find_program_address(&[Self::SEED, merchant.as_ref(), plan.as_ref()], &crate::ID)
    }

    /// Verifies a supplied PDA and bump.
    pub fn verify_pda(merchant: &Address, plan: &Address, bump: u8) -> Result<Address, ProgramError> {
        Address::create_program_address(&[Self::SEED, merchant.as_ref(), plan.as_ref(), &[bump]], &crate::ID)
            .map_err(|_| SubscriptionsError::PlanRevisionRegistryInvalidPda.into())
    }

    /// Confirms the stored Plan and merchant match the supplied accounts.
    pub fn validate_identity(
        &self,
        registry_address: &Address,
        merchant: &Address,
        plan: &Address,
    ) -> Result<(), ProgramError> {
        if self.plan != *plan || self.merchant != *merchant {
            return Err(SubscriptionsError::LifecycleRegistryIdentityMismatch.into());
        }
        let expected = Self::verify_pda(merchant, plan, self.bump)?;
        if expected != *registry_address {
            return Err(SubscriptionsError::PlanRevisionRegistryInvalidPda.into());
        }
        Ok(())
    }

    /// Consumes one monotonic Plan administration revision.
    ///
    /// Call this in the same transaction as CreatePlan, UpdatePlan, sunset,
    /// Puller changes, DeletePlan, or recreation at the same Plan PDA.
    pub fn advance(&mut self, expected_revision: u64, expected_nonce: u64) -> Result<u64, ProgramError> {
        if self.revision != expected_revision {
            return Err(SubscriptionsError::StalePlanRevision.into());
        }
        if self.action_nonce != expected_nonce {
            return Err(SubscriptionsError::StaleLifecycleActionNonce.into());
        }

        let next_revision = self.revision.checked_add(1).ok_or(SubscriptionsError::ArithmeticOverflow)?;
        let next_nonce = self.action_nonce.checked_add(1).ok_or(SubscriptionsError::ArithmeticOverflow)?;

        self.revision = next_revision;
        self.action_nonce = next_nonce;
        Ok(next_revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(seed: u8) -> Address {
        Address::from([seed; 32])
    }

    fn initialized() -> PlanRevisionRegistry {
        let mut bytes = [0u8; PlanRevisionRegistry::LEN];
        PlanRevisionRegistry::init(&mut bytes, &addr(1), &addr(2), &addr(3), 11).unwrap();
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const PlanRevisionRegistry) }
    }

    #[test]
    fn v1_layout_is_frozen_at_116_bytes() {
        assert_eq!(PlanRevisionRegistry::LEN, PlanRevisionRegistry::V1_LEN);
        assert_eq!(core::mem::offset_of!(PlanRevisionRegistry, revision), 100);
        assert_eq!(core::mem::offset_of!(PlanRevisionRegistry, action_nonce), 108);
    }

    #[test]
    fn pda_binds_merchant_and_plan() {
        let p1 = PlanRevisionRegistry::find_pda(&addr(1), &addr(3)).0;
        let p2 = PlanRevisionRegistry::find_pda(&addr(2), &addr(3)).0;
        let p3 = PlanRevisionRegistry::find_pda(&addr(1), &addr(4)).0;
        assert_ne!(p1, p2);
        assert_ne!(p1, p3);
    }

    #[test]
    fn plan_updates_consume_revision_even_when_values_are_restored() {
        let mut registry = initialized();
        registry.advance(0, 0).unwrap(); // update A -> B
        registry.advance(1, 1).unwrap(); // update B -> A (ABA)
        assert!(registry.advance(0, 0).is_err()); // stale approval for original A
        assert_eq!(registry.revision, 2);
        assert_eq!(registry.action_nonce, 2);
    }

    #[test]
    fn delete_and_recreate_at_same_pda_keeps_advancing_revision() {
        let mut registry = initialized();
        registry.advance(0, 0).unwrap(); // CreatePlan
        registry.advance(1, 1).unwrap(); // DeletePlan
        registry.advance(2, 2).unwrap(); // CreatePlan at the same deterministic PDA
        assert!(registry.advance(0, 0).is_err()); // old CreatePlan approval
        assert_eq!(registry.revision, 3);
    }

    #[test]
    fn revision_and_nonce_overflow_fail_without_partial_write() {
        let mut registry = initialized();
        registry.revision = u64::MAX;
        assert!(registry.advance(u64::MAX, 0).is_err());
        assert_eq!(registry.action_nonce, 0);

        registry.revision = 0;
        registry.action_nonce = u64::MAX;
        assert!(registry.advance(0, u64::MAX).is_err());
        assert_eq!(registry.revision, 0);
    }
}
