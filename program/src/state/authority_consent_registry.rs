//! Persistent consent lineage for a subscriber/mint/source-token-account tuple.
//!
//! This account is intentionally not closeable by ordinary protocol instructions.
//! Its generation survives authority close/recreate and its independent action
//! counters allow a signed invalidation to race safely with one pending authorize.

use codama::CodamaAccount;
use core::mem::{size_of, transmute};
use pinocchio::{error::ProgramError, Address};

use crate::{state::common::AccountDiscriminator, SubscriptionsError};

/// On-chain maximum lifetime for a signed Authority lifecycle action (24 hours).
///
/// This bounds durable-nonce and delayed smart-wallet execution. It is a protocol
/// constant and must be changed only through a versioned protocol review.
pub const MAX_AUTHORITY_ACTION_LIFETIME_SECS: i64 = 86_400;

/// Registry status byte: no live token delegate is authorized by this lineage.
pub const AUTHORITY_REGISTRY_REVOKED: u8 = 0;
/// Registry status byte: a VNext Authority is authorized for this lineage.
pub const AUTHORITY_REGISTRY_ACTIVE: u8 = 1;

/// Persistent Authority Consent Registry.
///
/// PDA seeds: ["authorityConsent", subscriber, mint, source_token_account].
///
/// The source token account is part of the authority identity. One subscriber/mint
/// pair can have multiple independent consent lineages, one for each source account.
///
/// Layout (little-endian for integers):
/// - 0: discriminator (u8)
/// - 1: schema version (u8)
/// - 2: status (u8)
/// - 3: PDA bump (u8)
/// - 4..36: subscriber
/// - 36..68: mint
/// - 68..100: source token account
/// - 100..132: token program
/// - 132..164: original rent payer
/// - 164..172: Authority generation (u64)
/// - 172..180: next authorize nonce (u64)
/// - 180..188: next revoke nonce (u64)
#[repr(C, packed)]
#[derive(CodamaAccount)]
#[codama(seed(type = string(utf8), value = "authorityConsent"))]
#[codama(seed(name = "subscriber", type = public_key))]
#[codama(seed(name = "mint", type = public_key))]
#[codama(seed(name = "sourceTokenAccount", type = public_key))]
pub struct AuthorityConsentRegistry {
    /// Account discriminator.
    pub discriminator: u8,
    /// Version of this account layout.
    pub version: u8,
    /// Current consent state.
    pub status: u8,
    /// PDA bump.
    pub bump: u8,
    /// Subscriber wallet.
    pub subscriber: Address,
    /// Token mint.
    pub mint: Address,
    /// Exact token account authorized by this consent lineage.
    pub source_token_account: Address,
    /// SPL Token or Token-2022 program owning the mint and token account.
    pub token_program: Address,
    /// Account that funded the permanent Registry rent.
    pub rent_payer: Address,
    /// Monotonic authority generation. Never reset or caller-selected.
    pub authority_generation: u64,
    /// Monotonic nonce for successful authorize/reauthorize actions.
    pub authorize_nonce: u64,
    /// Independent monotonic nonce for revoke/invalidate actions.
    pub revoke_nonce: u64,
}

impl AuthorityConsentRegistry {
    /// Current serialized size.
    pub const LEN: usize = size_of::<Self>();
    /// Frozen v1 layout length. Future versions must append fields or use a new
    /// account discriminator; they must not reinterpret these offsets.
    pub const V1_LEN: usize = 188;
    /// Registry PDA seed prefix.
    pub const SEED: &'static [u8] = b"authorityConsent";
    /// Current schema version.
    pub const VERSION: u8 = 1;

    /// Initializes a newly allocated Registry as revoked at generation zero.
    ///
    /// An ordinary authorize instruction must then consume the generation-zero
    /// state. A revoke instruction can instead create a generation-two tombstone
    /// that invalidates an already-signed first authorization.
    pub fn init(
        bytes: &mut [u8],
        subscriber: &Address,
        mint: &Address,
        source_token_account: &Address,
        token_program: &Address,
        rent_payer: &Address,
        bump: u8,
    ) -> Result<(), ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }

        let account = unsafe { &mut *transmute::<*mut u8, *mut Self>(bytes.as_mut_ptr()) };
        account.discriminator = AccountDiscriminator::AuthorityConsentRegistry.into();
        account.version = Self::VERSION;
        account.status = AUTHORITY_REGISTRY_REVOKED;
        account.bump = bump;
        account.subscriber = *subscriber;
        account.mint = *mint;
        account.source_token_account = *source_token_account;
        account.token_program = *token_program;
        account.rent_payer = *rent_payer;
        account.authority_generation = 0;
        account.authorize_nonce = 0;
        account.revoke_nonce = 0;
        Ok(())
    }

    /// Loads an immutable Registry after validating its fixed v1 encoding.
    pub fn load(bytes: &[u8]) -> Result<&Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        if bytes[0] != AccountDiscriminator::AuthorityConsentRegistry as u8 {
            return Err(SubscriptionsError::InvalidAccountDiscriminator.into());
        }
        if bytes[1] != Self::VERSION {
            return Err(SubscriptionsError::MigrationRequired.into());
        }
        let status = bytes[2];
        if status != AUTHORITY_REGISTRY_REVOKED && status != AUTHORITY_REGISTRY_ACTIVE {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        Ok(unsafe { &*transmute::<*const u8, *const Self>(bytes.as_ptr()) })
    }

    /// Loads a mutable Registry after validating its fixed v1 encoding.
    pub fn load_mut(bytes: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        if bytes[0] != AccountDiscriminator::AuthorityConsentRegistry as u8 {
            return Err(SubscriptionsError::InvalidAccountDiscriminator.into());
        }
        if bytes[1] != Self::VERSION {
            return Err(SubscriptionsError::MigrationRequired.into());
        }
        let status = bytes[2];
        if status != AUTHORITY_REGISTRY_REVOKED && status != AUTHORITY_REGISTRY_ACTIVE {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        Ok(unsafe { &mut *transmute::<*mut u8, *mut Self>(bytes.as_mut_ptr()) })
    }

    /// Finds the canonical Registry PDA and bump for the complete consent tuple.
    pub fn find_pda(subscriber: &Address, mint: &Address, source_token_account: &Address) -> (Address, u8) {
        Address::find_program_address(
            &[Self::SEED, subscriber.as_ref(), mint.as_ref(), source_token_account.as_ref()],
            &crate::ID,
        )
    }

    /// Verifies a supplied PDA and bump against the complete consent tuple.
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
        .map_err(|_| SubscriptionsError::AuthorityConsentRegistryInvalidPda.into())
    }

    /// Confirms the stored tuple and bump match the supplied accounts.
    pub fn validate_identity(
        &self,
        registry_address: &Address,
        subscriber: &Address,
        mint: &Address,
        source_token_account: &Address,
        token_program: &Address,
    ) -> Result<(), ProgramError> {
        if self.subscriber != *subscriber
            || self.mint != *mint
            || self.source_token_account != *source_token_account
            || self.token_program != *token_program
        {
            return Err(SubscriptionsError::AuthorityConsentRegistryIdentityMismatch.into());
        }

        let bump = self.bump;
        let expected = Self::verify_pda(subscriber, mint, source_token_account, bump)?;
        if expected != *registry_address {
            return Err(SubscriptionsError::AuthorityConsentRegistryInvalidPda.into());
        }
        Ok(())
    }

    /// Consumes a fresh explicit authorization and opens a new Authority generation.
    ///
    /// expected_generation identifies the Registry state observed by the signer.
    /// expected_nonce is scoped only to authorization operations. A replay after
    /// revocation or reauthorization cannot restore an earlier generation.
    pub fn authorize(
        &mut self,
        expected_generation: u64,
        expected_nonce: u64,
        now_ts: i64,
        not_after_ts: i64,
    ) -> Result<u64, ProgramError> {
        Self::validate_action_deadline(now_ts, not_after_ts)?;
        if self.status == AUTHORITY_REGISTRY_ACTIVE {
            return Err(SubscriptionsError::AuthorityAlreadyActive.into());
        }
        if self.authority_generation != expected_generation {
            return Err(SubscriptionsError::StaleAuthorityGeneration.into());
        }
        if self.authorize_nonce != expected_nonce {
            return Err(SubscriptionsError::StaleAuthorityActionNonce.into());
        }

        let next_generation = self.authority_generation.checked_add(1).ok_or(SubscriptionsError::ArithmeticOverflow)?;
        let next_nonce = self.authorize_nonce.checked_add(1).ok_or(SubscriptionsError::ArithmeticOverflow)?;

        self.authority_generation = next_generation;
        self.authorize_nonce = next_nonce;
        self.status = AUTHORITY_REGISTRY_ACTIVE;
        Ok(next_generation)
    }

    /// Advances the generation and revokes or pre-empts one authorization.
    ///
    /// expected_authority_generation is the generation being invalidated. The
    /// operation accepts either:
    /// - that generation is currently active; or
    /// - the Registry is revoked at the immediately preceding generation, meaning
    ///   the signed authorization for the next generation has not landed yet.
    ///
    /// This two-sided rule makes the same subscriber-signed invalidation safe in
    /// either transaction order. The independent revoke nonce prevents replay.
    pub fn revoke(
        &mut self,
        expected_authority_generation: u64,
        expected_nonce: u64,
        now_ts: i64,
        not_after_ts: i64,
    ) -> Result<u64, ProgramError> {
        Self::validate_action_deadline(now_ts, not_after_ts)?;
        if self.revoke_nonce != expected_nonce {
            return Err(SubscriptionsError::StaleAuthorityActionNonce.into());
        }

        let current_generation = self.authority_generation;
        let expected_next = current_generation.checked_add(1).ok_or(SubscriptionsError::ArithmeticOverflow)?;

        let target_matches = if self.status == AUTHORITY_REGISTRY_ACTIVE {
            current_generation == expected_authority_generation
        } else {
            expected_next == expected_authority_generation
        };

        if !target_matches {
            return Err(SubscriptionsError::StaleAuthorityGeneration.into());
        }

        let next_generation =
            expected_authority_generation.checked_add(1).ok_or(SubscriptionsError::ArithmeticOverflow)?;
        let next_nonce = self.revoke_nonce.checked_add(1).ok_or(SubscriptionsError::ArithmeticOverflow)?;

        self.authority_generation = next_generation;
        self.revoke_nonce = next_nonce;
        self.status = AUTHORITY_REGISTRY_REVOKED;
        Ok(next_generation)
    }

    /// Validates an on-chain action deadline.
    ///
    /// not_after_ts is inclusive at equality and is bounded to 24 hours from
    /// execution time. This applies even when the transaction uses a durable nonce.
    pub fn validate_action_deadline(now_ts: i64, not_after_ts: i64) -> Result<(), ProgramError> {
        if not_after_ts < now_ts {
            return Err(SubscriptionsError::AuthorityActionExpired.into());
        }
        let maximum =
            now_ts.checked_add(MAX_AUTHORITY_ACTION_LIFETIME_SECS).ok_or(SubscriptionsError::ArithmeticOverflow)?;
        if not_after_ts > maximum {
            return Err(SubscriptionsError::AuthorityActionDeadlineTooFar.into());
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

    fn initialized() -> AuthorityConsentRegistry {
        let mut bytes = [0u8; AuthorityConsentRegistry::LEN];
        AuthorityConsentRegistry::init(&mut bytes, &addr(1), &addr(2), &addr(3), &addr(4), &addr(5), 7).unwrap();
        let mut copy = [0u8; AuthorityConsentRegistry::LEN];
        copy.copy_from_slice(&bytes);
        unsafe { core::ptr::read_unaligned(copy.as_ptr() as *const AuthorityConsentRegistry) }
    }

    #[test]
    fn v1_layout_is_frozen_at_188_bytes() {
        assert_eq!(AuthorityConsentRegistry::LEN, AuthorityConsentRegistry::V1_LEN);
        assert_eq!(core::mem::offset_of!(AuthorityConsentRegistry, authority_generation), 164);
        assert_eq!(core::mem::offset_of!(AuthorityConsentRegistry, authorize_nonce), 172);
        assert_eq!(core::mem::offset_of!(AuthorityConsentRegistry, revoke_nonce), 180);
    }

    #[test]
    fn pda_binds_subscriber_mint_and_exact_source_account() {
        let a = addr(1);
        let b = addr(2);
        let mint = addr(3);
        let source_a = addr(4);
        let source_b = addr(5);
        let pda_a = AuthorityConsentRegistry::find_pda(&a, &mint, &source_a).0;
        let pda_b = AuthorityConsentRegistry::find_pda(&b, &mint, &source_a).0;
        let pda_c = AuthorityConsentRegistry::find_pda(&a, &mint, &source_b).0;
        assert_ne!(pda_a, pda_b);
        assert_ne!(pda_a, pda_c);
    }

    #[test]
    fn authorize_increments_generation_and_its_own_nonce() {
        let mut registry = initialized();
        assert_eq!(registry.authority_generation, 0);
        assert_eq!(registry.authorize(0, 0, 1_000, 1_900).unwrap(), 1);
        assert_eq!(registry.authority_generation, 1);
        assert_eq!(registry.authorize_nonce, 1);
        assert_eq!(registry.status, AUTHORITY_REGISTRY_ACTIVE);
    }

    #[test]
    fn duplicate_authorize_never_reapproves_an_active_generation() {
        let mut registry = initialized();
        registry.authorize(0, 0, 1_000, 1_900).unwrap();
        let result = registry.authorize(0, 0, 1_000, 1_900);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(SubscriptionsError::AuthorityAlreadyActive as u32));
        assert_eq!(registry.authority_generation, 1);
        assert_eq!(registry.authorize_nonce, 1);
    }

    #[test]
    fn revoke_after_authorize_invalidates_the_active_generation() {
        let mut registry = initialized();
        registry.authorize(0, 0, 1_000, 1_900).unwrap();
        assert_eq!(registry.revoke(1, 0, 1_000, 1_900).unwrap(), 2);
        assert_eq!(registry.status, AUTHORITY_REGISTRY_REVOKED);
        assert_eq!(registry.authority_generation, 2);
        assert_eq!(registry.revoke_nonce, 1);
        assert!(registry.authorize(1, 1, 1_000, 1_900).is_err());
    }

    #[test]
    fn revoke_tombstone_preempts_a_signed_first_authorize() {
        let mut registry = initialized();
        // The invalidation is submitted before the older authorization.
        assert_eq!(registry.revoke(1, 0, 1_000, 1_900).unwrap(), 2);
        assert!(registry.authorize(0, 0, 1_000, 1_900).is_err());
        assert_eq!(registry.status, AUTHORITY_REGISTRY_REVOKED);
        assert_eq!(registry.authority_generation, 2);
    }

    #[test]
    fn signed_revoke_is_valid_if_the_authorize_lands_first() {
        let mut registry = initialized();
        // Both signatures were made against the initial empty Registry state.
        registry.authorize(0, 0, 1_000, 1_900).unwrap();
        assert_eq!(registry.revoke(1, 0, 1_000, 1_900).unwrap(), 2);
        assert_eq!(registry.status, AUTHORITY_REGISTRY_REVOKED);
    }

    #[test]
    fn revoke_can_preempt_a_pending_reauthorization() {
        let mut registry = initialized();
        registry.authorize(0, 0, 1_000, 1_900).unwrap();
        registry.revoke(1, 0, 1_000, 1_900).unwrap();
        // The next authorize would create generation 3 from Registry generation 2.
        assert_eq!(registry.revoke(3, 1, 1_000, 1_900).unwrap(), 4);
        assert!(registry.authorize(2, 1, 1_000, 1_900).is_err());
    }

    #[test]
    fn stale_revoke_cannot_revoke_a_later_authority_generation() {
        let mut registry = initialized();
        registry.authorize(0, 0, 1_000, 1_900).unwrap();
        registry.revoke(1, 0, 1_000, 1_900).unwrap();
        registry.authorize(2, 1, 1_000, 1_900).unwrap();
        assert!(registry.revoke(1, 1, 1_000, 1_900).is_err());
        assert_eq!(registry.status, AUTHORITY_REGISTRY_ACTIVE);
        assert_eq!(registry.authority_generation, 3);
    }

    #[test]
    fn generation_and_nonce_overflow_fail_without_partial_state_change() {
        let mut registry = initialized();
        registry.authority_generation = u64::MAX;
        assert!(registry.authorize(u64::MAX, 0, 1_000, 1_900).is_err());
        assert_eq!(registry.authority_generation, u64::MAX);
        assert_eq!(registry.status, AUTHORITY_REGISTRY_REVOKED);

        registry.authority_generation = 0;
        registry.authorize_nonce = u64::MAX;
        assert!(registry.authorize(0, u64::MAX, 1_000, 1_900).is_err());
        assert_eq!(registry.authority_generation, 0);

        registry.authorize_nonce = 0;
        registry.revoke_nonce = u64::MAX;
        assert!(registry.revoke(1, u64::MAX, 1_000, 1_900).is_err());
        assert_eq!(registry.authority_generation, 0);
    }

    #[test]
    fn expired_or_overlong_actions_do_not_consume_registry_state() {
        let mut registry = initialized();
        assert!(registry.authorize(0, 0, 1_000, 999).is_err());
        assert_eq!(registry.authority_generation, 0);
        assert_eq!(registry.authorize_nonce, 0);

        assert!(registry.authorize(0, 0, 1_000, 87_401).is_err());
        assert_eq!(registry.authority_generation, 0);
        assert_eq!(registry.authorize_nonce, 0);

        registry.authorize(0, 0, 1_000, 1_900).unwrap();
        assert!(registry.revoke(1, 0, 1_000, 999).is_err());
        assert_eq!(registry.authority_generation, 1);
        assert_eq!(registry.revoke_nonce, 0);
        assert_eq!(registry.status, AUTHORITY_REGISTRY_ACTIVE);
    }

    #[test]
    fn action_deadline_accepts_now_and_maximum_boundary() {
        assert!(AuthorityConsentRegistry::validate_action_deadline(1_000, 1_000).is_ok());
        assert!(AuthorityConsentRegistry::validate_action_deadline(1_000, 87_400).is_ok());
    }

    #[test]
    fn action_deadline_rejects_expired_and_unbounded_delayed_actions() {
        assert!(AuthorityConsentRegistry::validate_action_deadline(1_000, 999).is_err());
        assert!(AuthorityConsentRegistry::validate_action_deadline(1_000, 87_401).is_err());
    }
}
