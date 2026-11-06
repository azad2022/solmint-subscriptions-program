//! Persistent Subscription incarnation and action-revision state.
//!
//! The Subscription PDA itself is closable and reusable. This registry is not.
//! Every lifecycle mutation advances its revision and action nonce before/with
//! the corresponding Subscription account mutation in the same transaction.

use codama::CodamaAccount;
use core::mem::{size_of, transmute};
use pinocchio::{error::ProgramError, Address};

use crate::{state::common::AccountDiscriminator, SubscriptionsError};

/// Persistent lifecycle registry for one exact (Plan PDA, subscriber) identity.
///
/// PDA seeds: ["subscriptionLifecycle", plan_pda, subscriber, source_token_account].
///
/// Layout (little-endian):
/// - 0 discriminator, 1 version, 2 bump, 3 reserved
/// - 4..36 Plan PDA
/// - 36..68 subscriber
/// - 68..100 exact source token account
/// - 100..132 original rent payer
/// - 132..140 revision (u64)
/// - 140..148 action nonce (u64)
#[repr(C, packed)]
#[derive(CodamaAccount)]
#[codama(seed(type = string(utf8), value = "subscriptionLifecycle"))]
#[codama(seed(name = "plan", type = public_key))]
#[codama(seed(name = "subscriber", type = public_key))]
#[codama(seed(name = "sourceTokenAccount", type = public_key))]
pub struct SubscriptionLifecycleRegistry {
    /// Account discriminator.
    pub discriminator: u8,
    /// Schema version.
    pub version: u8,
    /// PDA bump.
    pub bump: u8,
    /// Reserved; must remain zero in v1.
    pub reserved: u8,
    /// Exact Plan PDA for this logical Subscription.
    pub plan: Address,
    /// Subscriber wallet.
    pub subscriber: Address,
    /// Exact source token account for this subscription consent lineage.
    pub source_token_account: Address,
    /// Original account rent payer.
    pub rent_payer: Address,
    /// Monotonic lifecycle incarnation revision.
    pub revision: u64,
    /// Monotonic nonce consumed by every lifecycle mutation.
    pub action_nonce: u64,
}

impl SubscriptionLifecycleRegistry {
    /// Exact v1 account length.
    pub const LEN: usize = size_of::<Self>();
    pub const V1_LEN: usize = 148;
    pub const VERSION: u8 = 1;
    pub const SEED: &'static [u8] = b"subscriptionLifecycle";

    /// Initializes a fresh persistent lifecycle lineage at revision/nonce zero.
    pub fn init(
        bytes: &mut [u8],
        plan: &Address,
        subscriber: &Address,
        source_token_account: &Address,
        rent_payer: &Address,
        bump: u8,
    ) -> Result<(), ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        let account = unsafe { &mut *transmute::<*mut u8, *mut Self>(bytes.as_mut_ptr()) };
        account.discriminator = AccountDiscriminator::SubscriptionLifecycleRegistry.into();
        account.version = Self::VERSION;
        account.bump = bump;
        account.reserved = 0;
        account.plan = *plan;
        account.subscriber = *subscriber;
        account.source_token_account = *source_token_account;
        account.rent_payer = *rent_payer;
        account.revision = 0;
        account.action_nonce = 0;
        Ok(())
    }

    /// Loads and validates a v1 lifecycle registry.
    pub fn load(bytes: &[u8]) -> Result<&Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        if bytes[0] != AccountDiscriminator::SubscriptionLifecycleRegistry as u8 {
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

    /// Loads a mutable v1 lifecycle registry.
    pub fn load_mut(bytes: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        if bytes[0] != AccountDiscriminator::SubscriptionLifecycleRegistry as u8 {
            return Err(SubscriptionsError::InvalidAccountDiscriminator.into());
        }
        if bytes[1] != Self::VERSION || bytes[3] != 0 {
            return Err(SubscriptionsError::MigrationRequired.into());
        }
        Ok(unsafe { &mut *transmute::<*mut u8, *mut Self>(bytes.as_mut_ptr()) })
    }

    /// Finds the canonical lifecycle Registry PDA.
    pub fn find_pda(plan: &Address, subscriber: &Address, source_token_account: &Address) -> (Address, u8) {
        Address::find_program_address(
            &[Self::SEED, plan.as_ref(), subscriber.as_ref(), source_token_account.as_ref()],
            &crate::ID,
        )
    }

    /// Verifies a supplied PDA and bump.
    pub fn verify_pda(
        plan: &Address,
        subscriber: &Address,
        source_token_account: &Address,
        bump: u8,
    ) -> Result<Address, ProgramError> {
        Address::create_program_address(
            &[Self::SEED, plan.as_ref(), subscriber.as_ref(), source_token_account.as_ref(), &[bump]],
            &crate::ID,
        )
            .map_err(|_| SubscriptionsError::SubscriptionLifecycleRegistryInvalidPda.into())
    }

    /// Confirms that the stored Plan/subscriber identity matches all supplied accounts.
    pub fn validate_identity(
        &self,
        registry_address: &Address,
        plan: &Address,
        subscriber: &Address,
        source_token_account: &Address,
    ) -> Result<(), ProgramError> {
        if self.plan != *plan || self.subscriber != *subscriber || self.source_token_account != *source_token_account {
            return Err(SubscriptionsError::LifecycleRegistryIdentityMismatch.into());
        }
        let expected = Self::verify_pda(plan, subscriber, source_token_account, self.bump)?;
        if expected != *registry_address {
            return Err(SubscriptionsError::SubscriptionLifecycleRegistryInvalidPda.into());
        }
        Ok(())
    }

    /// Advances the logical Subscription incarnation for a lifecycle mutation.
    ///
    /// Call this in the same transaction as Subscribe, cancellation, CancelNow,
    /// Resume, terminal close/revoke, or re-subscription. It must not be called
    /// for a token transfer within an already authorized billing period.
    pub fn advance(&mut self, expected_revision: u64, expected_nonce: u64) -> Result<u64, ProgramError> {
        if self.revision != expected_revision {
            return Err(SubscriptionsError::StaleSubscriptionLifecycleRevision.into());
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

    fn initialized() -> SubscriptionLifecycleRegistry {
        let mut bytes = [0u8; SubscriptionLifecycleRegistry::LEN];
        SubscriptionLifecycleRegistry::init(&mut bytes, &addr(1), &addr(2), &addr(3), &addr(4), 9).unwrap();
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const SubscriptionLifecycleRegistry) }
    }

    #[test]
    fn v1_layout_is_frozen_at_116_bytes() {
        assert_eq!(SubscriptionLifecycleRegistry::LEN, SubscriptionLifecycleRegistry::V1_LEN);
        assert_eq!(core::mem::offset_of!(SubscriptionLifecycleRegistry, source_token_account), 68);
        assert_eq!(core::mem::offset_of!(SubscriptionLifecycleRegistry, revision), 132);
        assert_eq!(core::mem::offset_of!(SubscriptionLifecycleRegistry, action_nonce), 140);
    }

    #[test]
    fn pda_binds_plan_subscriber_and_source_account() {
        let p1 = SubscriptionLifecycleRegistry::find_pda(&addr(1), &addr(2), &addr(3)).0;
        let p2 = SubscriptionLifecycleRegistry::find_pda(&addr(4), &addr(2), &addr(3)).0;
        let p3 = SubscriptionLifecycleRegistry::find_pda(&addr(1), &addr(5), &addr(3)).0;
        let p4 = SubscriptionLifecycleRegistry::find_pda(&addr(1), &addr(2), &addr(6)).0;
        assert_ne!(p1, p2);
        assert_ne!(p1, p3);
        assert_ne!(p1, p4);
    }

    #[test]
    fn every_lifecycle_action_consumes_revision_and_nonce() {
        let mut registry = initialized();
        assert_eq!(registry.advance(0, 0).unwrap(), 1);
        assert_eq!(registry.advance(1, 1).unwrap(), 2);
        { let actual = registry.revision; assert_eq!(actual, 2); }
        { let actual = registry.action_nonce; assert_eq!(actual, 2); }
    }

    #[test]
    fn stale_approval_cannot_survive_close_and_recreate() {
        let mut registry = initialized();
        registry.advance(0, 0).unwrap(); // first Subscribe
        registry.advance(1, 1).unwrap(); // terminal close
        registry.advance(2, 2).unwrap(); // a new Subscribe at the same logical PDA
        assert!(registry.advance(1, 1).is_err()); // old CancelNow/Resume approval
        { let actual = registry.revision; assert_eq!(actual, 3); }
    }

    #[test]
    fn revision_and_nonce_overflow_fail_without_partial_write() {
        let mut registry = initialized();
        registry.revision = u64::MAX;
        assert!(registry.advance(u64::MAX, 0).is_err());
        { let actual = registry.action_nonce; assert_eq!(actual, 0); }

        registry.revision = 0;
        registry.action_nonce = u64::MAX;
        assert!(registry.advance(0, u64::MAX).is_err());
        { let actual = registry.revision; assert_eq!(actual, 0); }
    }
}
