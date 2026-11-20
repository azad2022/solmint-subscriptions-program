//! Internal lifecycle state machine for VNext Fixed and Recurring permissions.
//!
//! This is deliberately a transition model, not an on-chain account codec. It
//! captures the generation/revision invariants before a persistent PDA layout,
//! instruction discriminator, account order, or rent policy is frozen. Do not
//! serialize this Rust struct directly or enable a dispatcher route from it.
//!
//! The eventual persistent record must be customer-funded, non-closeable, and
//! keyed to the exact logical delegation. This model mirrors those invariants:
//! a permission is bound to its original Authority generation, each successful
//! transfer consumes one revision, and terminal revoke can never be reversed.

use pinocchio::{error::ProgramError, Address};

use super::authority_consent_registry::AuthorityConsentRegistry;
use crate::SubscriptionsError;

/// Exact permission kind. Kind is part of the stored identity, not an
/// interchangeable attribute of a closed Fixed/Recurring delegation PDA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum FixedRecurringKind {
    Fixed = 1,
    Recurring = 2,
}

/// A delegation may be active or permanently terminal. Terminal is monotonic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum FixedRecurringStatus {
    Active = 1,
    Terminal = 2,
}

/// Immutable identity captured when a VNext Fixed/Recurring permission is
/// created. The exact source account and Authority Registry are mandatory.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FixedRecurringIdentity {
    pub kind: FixedRecurringKind,
    pub delegation: Address,
    pub subscriber: Address,
    pub delegatee: Address,
    pub mint: Address,
    pub source_token_account: Address,
    pub authority_registry: Address,
    pub authority_generation: u64,
}

/// Pure transition model for the future persistent delegation lifecycle PDA.
///
/// Revision starts at zero. Every successful transfer or terminal revoke
/// advances it with checked arithmetic. A retry signed against the previous
/// revision is therefore stale even when submitted with a fresh blockhash.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FixedRecurringLifecycle {
    pub identity: FixedRecurringIdentity,
    pub revision: u64,
    pub status: FixedRecurringStatus,
}

impl FixedRecurringLifecycle {
    /// Creates the in-memory model for a new logical permission.
    ///
    /// The caller must separately create the permanent PDA exactly once and
    /// atomically create the associated delegation account. A non-zero
    /// Authority generation and canonical Authority Registry are mandatory.
    pub fn new(identity: FixedRecurringIdentity) -> Result<Self, ProgramError> {
        if identity.authority_generation == 0 {
            return Err(SubscriptionsError::StaleAuthorityGeneration.into());
        }

        let (expected_registry, _) = AuthorityConsentRegistry::find_pda(
            &identity.subscriber,
            &identity.mint,
            &identity.source_token_account,
        );
        if expected_registry != identity.authority_registry {
            return Err(SubscriptionsError::LifecycleRegistryIdentityMismatch.into());
        }

        Ok(Self { identity, revision: 0, status: FixedRecurringStatus::Active })
    }

    /// Rejects substitution of any component of the original permission tuple.
    pub fn validate_identity(&self, expected: &FixedRecurringIdentity) -> Result<(), ProgramError> {
        let actual = self.identity;
        if actual.kind != expected.kind
            || actual.delegation != expected.delegation
            || actual.subscriber != expected.subscriber
            || actual.delegatee != expected.delegatee
            || actual.mint != expected.mint
            || actual.source_token_account != expected.source_token_account
            || actual.authority_registry != expected.authority_registry
            || actual.authority_generation != expected.authority_generation
        {
            return Err(SubscriptionsError::LifecycleRegistryIdentityMismatch.into());
        }
        Ok(())
    }

    /// Verifies that a signed operation targets the currently active
    /// delegation, exact Authority generation, and unconsumed lifecycle revision.
    fn validate_action(&self, expected_generation: u64, expected_revision: u64) -> Result<(), ProgramError> {
        if self.status != FixedRecurringStatus::Active {
            return Err(SubscriptionsError::Unauthorized.into());
        }
        if self.identity.authority_generation != expected_generation {
            return Err(SubscriptionsError::StaleAuthorityGeneration.into());
        }
        if self.revision != expected_revision {
            return Err(SubscriptionsError::StaleSubscriptionLifecycleRevision.into());
        }
        Ok(())
    }

    /// Commits one successful transfer to the logical permission lineage.
    ///
    /// The production handler must call this in the same transaction as the
    /// token CPI and delegation allowance update. Solana transaction atomicity
    /// must roll back all three on CPI failure.
    pub fn consume_transfer(
        &mut self,
        expected_generation: u64,
        expected_revision: u64,
    ) -> Result<u64, ProgramError> {
        self.validate_action(expected_generation, expected_revision)?;
        let next_revision = self.revision.checked_add(1).ok_or(SubscriptionsError::ArithmeticOverflow)?;
        self.revision = next_revision;
        Ok(next_revision)
    }

    /// Permanently terminalizes a permission and consumes its current revision.
    ///
    /// The production V2 revoke handler must commit this transition atomically
    /// with closing/refunding the separate delegation account. The lifecycle
    /// record itself must never be closed or reset.
    pub fn terminalize(
        &mut self,
        expected_generation: u64,
        expected_revision: u64,
    ) -> Result<u64, ProgramError> {
        self.validate_action(expected_generation, expected_revision)?;
        let next_revision = self.revision.checked_add(1).ok_or(SubscriptionsError::ArithmeticOverflow)?;
        self.revision = next_revision;
        self.status = FixedRecurringStatus::Terminal;
        Ok(next_revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(seed: u8) -> Address {
        Address::from([seed; 32])
    }

    fn identity() -> FixedRecurringIdentity {
        let subscriber = addr(1);
        let mint = addr(2);
        let source = addr(3);
        let authority_registry = AuthorityConsentRegistry::find_pda(&subscriber, &mint, &source).0;

        FixedRecurringIdentity {
            kind: FixedRecurringKind::Fixed,
            delegation: addr(4),
            subscriber,
            delegatee: addr(5),
            mint,
            source_token_account: source,
            authority_registry,
            authority_generation: 1,
        }
    }

    fn initialized() -> FixedRecurringLifecycle {
        FixedRecurringLifecycle::new(identity()).unwrap()
    }

    #[test]
    fn identity_requires_the_canonical_authority_registry_and_live_generation() {
        let mut wrong_registry = identity();
        wrong_registry.authority_registry = addr(9);
        assert!(FixedRecurringLifecycle::new(wrong_registry).is_err());

        let mut zero_generation = identity();
        zero_generation.authority_generation = 0;
        assert!(FixedRecurringLifecycle::new(zero_generation).is_err());
    }

    #[test]
    fn identity_rejects_substitution_of_each_permission_component() {
        let state = initialized();
        let original = identity();

        let mut variants = [original; 8];
        variants[0].kind = FixedRecurringKind::Recurring;
        variants[1].delegation = addr(10);
        variants[2].subscriber = addr(11);
        variants[3].delegatee = addr(12);
        variants[4].mint = addr(13);
        variants[5].source_token_account = addr(14);
        variants[6].authority_registry = addr(15);
        variants[7].authority_generation = 2;

        for candidate in variants {
            assert!(state.validate_identity(&candidate).is_err());
        }
        assert!(state.validate_identity(&original).is_ok());
    }

    #[test]
    fn each_successful_transfer_consumes_a_one_shot_revision() {
        let mut state = initialized();

        assert_eq!(state.consume_transfer(1, 0).unwrap(), 1);
        assert!(state.consume_transfer(1, 0).is_err());
        assert_eq!(state.revision, 1);

        assert_eq!(state.consume_transfer(1, 1).unwrap(), 2);
        assert_eq!(state.revision, 2);
    }

    #[test]
    fn authority_reauthorization_does_not_revive_an_old_permission() {
        let mut state = initialized();

        assert!(state.consume_transfer(2, 0).is_err());
        assert_eq!(state.revision, 0);
        assert_eq!(state.status, FixedRecurringStatus::Active);
    }

    #[test]
    fn terminal_revoke_is_monotonic_and_blocks_transfer_or_revoke_replay() {
        let mut state = initialized();

        assert_eq!(state.terminalize(1, 0).unwrap(), 1);
        assert_eq!(state.status, FixedRecurringStatus::Terminal);
        assert!(state.consume_transfer(1, 1).is_err());
        assert!(state.terminalize(1, 1).is_err());
        assert_eq!(state.revision, 1);
        assert_eq!(state.status, FixedRecurringStatus::Terminal);
    }

    #[test]
    fn revision_overflow_does_not_partially_commit_a_transition() {
        let mut state = initialized();
        state.revision = u64::MAX;

        assert!(state.consume_transfer(1, u64::MAX).is_err());
        assert_eq!(state.revision, u64::MAX);
        assert_eq!(state.status, FixedRecurringStatus::Active);

        assert!(state.terminalize(1, u64::MAX).is_err());
        assert_eq!(state.revision, u64::MAX);
        assert_eq!(state.status, FixedRecurringStatus::Active);
    }
}
