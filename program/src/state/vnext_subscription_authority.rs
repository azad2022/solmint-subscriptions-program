//! Versioned token-delegate Authority for an exact non-ATA source account.
//!
//! Unlike the legacy Authority PDA, this account is scoped to the full
//! (subscriber, mint, source_token_account) tuple. Its lifetime is subordinate
//! to the persistent AuthorityConsentRegistry generation.

use codama::CodamaAccount;
use core::mem::{size_of, transmute};
use pinocchio::{error::ProgramError, Address};

use crate::{state::common::AccountDiscriminator, SubscriptionsError};

/// VNext token delegate Authority.
///
/// PDA seeds: ["SubscriptionAuthorityVNext", subscriber, mint, source_token_account].
///
/// Layout (little-endian):
/// - 0 discriminator, 1 version, 2 bump, 3 reserved
/// - 4..36 subscriber
/// - 36..68 mint
/// - 68..100 source token account
/// - 100..132 Registry PDA
/// - 132..164 token program
/// - 164..196 rent payer
/// - 196..204 authority generation
#[repr(C, packed)]
#[derive(CodamaAccount)]
#[codama(seed(type = string(utf8), value = "SubscriptionAuthorityVNext"))]
#[codama(seed(name = "subscriber", type = public_key))]
#[codama(seed(name = "mint", type = public_key))]
#[codama(seed(name = "sourceTokenAccount", type = public_key))]
pub struct VNextSubscriptionAuthority {
    /// Account discriminator.
    pub discriminator: u8,
    /// Schema version.
    pub version: u8,
    /// PDA bump.
    pub bump: u8,
    /// Reserved; must remain zero.
    pub reserved: u8,
    /// Subscriber wallet.
    pub subscriber: Address,
    /// Token mint.
    pub mint: Address,
    /// Exact non-ATA source token account.
    pub source_token_account: Address,
    /// Canonical Authority Consent Registry PDA.
    pub registry: Address,
    /// SPL Token or Token-2022 program.
    pub token_program: Address,
    /// Rent payer for this closeable Authority account.
    pub rent_payer: Address,
    /// Authority generation to which this token delegate was approved.
    pub authority_generation: u64,
}

impl VNextSubscriptionAuthority {
    /// Exact v1 account size.
    pub const LEN: usize = size_of::<Self>();
    pub const V1_LEN: usize = 204;
    pub const VERSION: u8 = 1;
    pub const SEED: &'static [u8] = b"SubscriptionAuthorityVNext";

    /// Initializes a freshly allocated VNext Authority.
    #[allow(clippy::too_many_arguments)]
    pub fn init(
        bytes: &mut [u8],
        subscriber: &Address,
        mint: &Address,
        source_token_account: &Address,
        registry: &Address,
        token_program: &Address,
        rent_payer: &Address,
        authority_generation: u64,
        bump: u8,
    ) -> Result<(), ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        let account = unsafe { &mut *transmute::<*mut u8, *mut Self>(bytes.as_mut_ptr()) };
        account.discriminator = AccountDiscriminator::VNextSubscriptionAuthority.into();
        account.version = Self::VERSION;
        account.bump = bump;
        account.reserved = 0;
        account.subscriber = *subscriber;
        account.mint = *mint;
        account.source_token_account = *source_token_account;
        account.registry = *registry;
        account.token_program = *token_program;
        account.rent_payer = *rent_payer;
        account.authority_generation = authority_generation;
        Ok(())
    }

    /// Loads a validated immutable VNext Authority.
    pub fn load(bytes: &[u8]) -> Result<&Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        if bytes[0] != AccountDiscriminator::VNextSubscriptionAuthority as u8 {
            return Err(SubscriptionsError::InvalidAccountDiscriminator.into());
        }
        if bytes[1] != Self::VERSION || bytes[3] != 0 {
            return Err(SubscriptionsError::MigrationRequired.into());
        }
        Ok(unsafe { &*transmute::<*const u8, *const Self>(bytes.as_ptr()) })
    }

    /// Finds the Authority PDA for the exact non-ATA source account lineage.
    pub fn find_pda(
        subscriber: &Address,
        mint: &Address,
        source_token_account: &Address,
    ) -> (Address, u8) {
        Address::find_program_address(
            &[Self::SEED, subscriber.as_ref(), mint.as_ref(), source_token_account.as_ref()],
            &crate::ID,
        )
    }

    /// Verifies the supplied Authority PDA and bump.
    pub fn verify_pda(
        subscriber: &Address,
        mint: &Address,
        source_token_account: &Address,
        bump: u8,
    ) -> Result<Address, ProgramError> {
        Address::create_program_address(
            &[Self::SEED, subscriber.as_ref(), mint.as_ref(), source_token_account.as_ref(), &[bump]],
            &crate::ID,
        )
        .map_err(|_| SubscriptionsError::VNextAuthorityInvalidPda.into())
    }

    /// Validates the exact Registry/source token-account tuple.
    pub fn validate_identity(
        &self,
        authority_address: &Address,
        subscriber: &Address,
        mint: &Address,
        source_token_account: &Address,
        registry: &Address,
        token_program: &Address,
        expected_generation: u64,
    ) -> Result<(), ProgramError> {
        if self.subscriber != *subscriber
            || self.mint != *mint
            || self.source_token_account != *source_token_account
            || self.registry != *registry
            || self.token_program != *token_program
            || self.authority_generation != expected_generation
        {
            return Err(SubscriptionsError::VNextAuthorityIdentityMismatch.into());
        }
        let expected = Self::verify_pda(subscriber, mint, source_token_account, self.bump)?;
        if expected != *authority_address {
            return Err(SubscriptionsError::VNextAuthorityInvalidPda.into());
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
    fn v1_layout_is_frozen_at_204_bytes() {
        assert_eq!(VNextSubscriptionAuthority::LEN, VNextSubscriptionAuthority::V1_LEN);
        assert_eq!(core::mem::offset_of!(VNextSubscriptionAuthority, authority_generation), 196);
    }

    #[test]
    fn authority_pda_is_bound_to_exact_source_account() {
        let subscriber = addr(1);
        let mint = addr(2);
        let source_a = addr(3);
        let source_b = addr(4);
        assert_ne!(
            VNextSubscriptionAuthority::find_pda(&subscriber, &mint, &source_a).0,
            VNextSubscriptionAuthority::find_pda(&subscriber, &mint, &source_b).0
        );
    }
}
