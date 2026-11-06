//! VNext Subscription state, keyed by the exact source token account.

use codama::CodamaAccount;
use core::mem::{size_of, transmute};
use pinocchio::{error::ProgramError, Address};

use crate::{instructions::create_plan::PlanTerms, state::common::AccountDiscriminator, SubscriptionsError};

/// PDA seeds: [subscriptionVNext, plan, subscriber, source_token_account].
#[repr(C, packed)]
#[derive(CodamaAccount)]
#[codama(seed(type = string(utf8), value = "subscriptionVNext"))]
#[codama(seed(name = "plan", type = public_key))]
#[codama(seed(name = "subscriber", type = public_key))]
#[codama(seed(name = "sourceTokenAccount", type = public_key))]
pub struct VNextSubscription {
    pub discriminator: u8,
    pub version: u8,
    pub bump: u8,
    pub reserved: u8,
    pub plan: Address,
    pub subscriber: Address,
    pub source_token_account: Address,
    pub mint: Address,
    pub token_program: Address,
    pub rent_payer: Address,
    pub terms: PlanTerms,
    pub amount_pulled_in_period: u64,
    pub current_period_start_ts: i64,
    /// Zero means active; non-zero is the inclusive stop timestamp.
    pub expires_at_ts: i64,
    /// Snapshot of the persistent SubscriptionLifecycleRegistry revision.
    pub lifecycle_revision: u64,
    /// Authority generation approved by the subscriber for this source account.
    pub authority_generation: u64,
}

impl VNextSubscription {
    pub const LEN: usize = size_of::<Self>();
    pub const V1_LEN: usize = 260;
    pub const VERSION: u8 = 1;
    pub const SEED: &'static [u8] = b"subscriptionVNext";

    pub fn find_pda(plan: &Address, subscriber: &Address, source_token_account: &Address) -> (Address, u8) {
        Address::find_program_address(
            &[Self::SEED, plan.as_ref(), subscriber.as_ref(), source_token_account.as_ref()],
            &crate::ID,
        )
    }

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
        .map_err(|_| SubscriptionsError::InvalidSubscriptionPda.into())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn init(
        bytes: &mut [u8],
        plan: &Address,
        subscriber: &Address,
        source_token_account: &Address,
        mint: &Address,
        token_program: &Address,
        rent_payer: &Address,
        terms: &PlanTerms,
        current_period_start_ts: i64,
        lifecycle_revision: u64,
        authority_generation: u64,
        bump: u8,
    ) -> Result<(), ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        let account = unsafe { &mut *transmute::<*mut u8, *mut Self>(bytes.as_mut_ptr()) };
        account.discriminator = AccountDiscriminator::VNextSubscription.into();
        account.version = Self::VERSION;
        account.bump = bump;
        account.reserved = 0;
        account.plan = *plan;
        account.subscriber = *subscriber;
        account.source_token_account = *source_token_account;
        account.mint = *mint;
        account.token_program = *token_program;
        account.rent_payer = *rent_payer;
        account.terms = *terms;
        account.amount_pulled_in_period = 0;
        account.current_period_start_ts = current_period_start_ts;
        account.expires_at_ts = 0;
        account.lifecycle_revision = lifecycle_revision;
        account.authority_generation = authority_generation;
        Ok(())
    }

    pub fn load(bytes: &[u8]) -> Result<&Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        if bytes[0] != AccountDiscriminator::VNextSubscription as u8 {
            return Err(SubscriptionsError::InvalidAccountDiscriminator.into());
        }
        if bytes[1] != Self::VERSION || bytes[3] != 0 {
            return Err(SubscriptionsError::MigrationRequired.into());
        }
        Ok(unsafe { &*transmute::<*const u8, *const Self>(bytes.as_ptr()) })
    }

    pub fn load_mut(bytes: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        if bytes[0] != AccountDiscriminator::VNextSubscription as u8 {
            return Err(SubscriptionsError::InvalidAccountDiscriminator.into());
        }
        if bytes[1] != Self::VERSION || bytes[3] != 0 {
            return Err(SubscriptionsError::MigrationRequired.into());
        }
        Ok(unsafe { &mut *transmute::<*mut u8, *mut Self>(bytes.as_mut_ptr()) })
    }

    pub fn validate_identity(
        &self,
        account: &Address,
        plan: &Address,
        subscriber: &Address,
        source_token_account: &Address,
    ) -> Result<(), ProgramError> {
        if self.plan != *plan || self.subscriber != *subscriber || self.source_token_account != *source_token_account {
            return Err(SubscriptionsError::LifecycleRegistryIdentityMismatch.into());
        }
        let expected = Self::verify_pda(plan, subscriber, source_token_account, self.bump)?;
        if expected != *account {
            return Err(SubscriptionsError::InvalidSubscriptionPda.into());
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
    fn v1_layout_is_frozen_at_260_bytes() {
        assert_eq!(VNextSubscription::LEN, VNextSubscription::V1_LEN);
        assert_eq!(core::mem::offset_of!(VNextSubscription, plan), 4);
        assert_eq!(core::mem::offset_of!(VNextSubscription, terms), 196);
        assert_eq!(core::mem::offset_of!(VNextSubscription, lifecycle_revision), 244);
        assert_eq!(core::mem::offset_of!(VNextSubscription, authority_generation), 252);
    }

    #[test]
    fn subscription_pda_binds_all_three_identity_fields() {
        let plan = addr(1);
        let subscriber = addr(2);
        let source = addr(3);
        let base = VNextSubscription::find_pda(&plan, &subscriber, &source).0;
        assert_ne!(base, VNextSubscription::find_pda(&addr(4), &subscriber, &source).0);
        assert_ne!(base, VNextSubscription::find_pda(&plan, &addr(5), &source).0);
        assert_ne!(base, VNextSubscription::find_pda(&plan, &subscriber, &addr(6)).0);
    }
}
