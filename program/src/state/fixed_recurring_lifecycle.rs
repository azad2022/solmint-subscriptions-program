//! Internal lifecycle state machine for VNext Fixed and Recurring permissions.
//!
//! This is deliberately a transition model, not an on-chain account codec. It
//! captures the generation/revision invariants before a persistent PDA layout,
//! instruction discriminator, account order, or rent policy is frozen. Do not
//! serialize this Rust struct directly or enable a dispatcher route from it.
//!
//! The eventual persistent record must be non-closeable and keyed to the exact
//! logical delegation. Its rent payer/sponsor/recovery policy remains unresolved.
//! Every operation must revalidate the live Authority Consent Registry, its exact
//! token-program identity, active status and current generation.

use pinocchio::{error::ProgramError, Address};

use super::authority_consent_registry::{AuthorityConsentRegistry, AUTHORITY_REGISTRY_ACTIVE};
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
/// created. The exact source account, token program and Authority Registry are mandatory.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FixedRecurringIdentity {
    pub kind: FixedRecurringKind,
    pub delegation: Address,
    pub subscriber: Address,
    pub delegatee: Address,
    pub mint: Address,
    pub source_token_account: Address,
    pub token_program: Address,
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
    /// Authority generation and canonical, ACTIVE Authority Registry are mandatory.
    /// The live Registry is checked here and again before every subsequent action.
    pub fn new(
        identity: FixedRecurringIdentity,
        registry_address: &Address,
        registry: &AuthorityConsentRegistry,
    ) -> Result<Self, ProgramError> {
        if identity.authority_generation == 0 {
            return Err(SubscriptionsError::StaleAuthorityGeneration.into());
        }

        let (expected_registry, _) =
            AuthorityConsentRegistry::find_pda(&identity.subscriber, &identity.mint, &identity.source_token_account);
        if expected_registry != identity.authority_registry {
            return Err(SubscriptionsError::LifecycleRegistryIdentityMismatch.into());
        }

        Self::validate_live_authority_registry(&identity, registry_address, registry, identity.authority_generation)?;

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
            || actual.token_program != expected.token_program
            || actual.authority_registry != expected.authority_registry
            || actual.authority_generation != expected.authority_generation
        {
            return Err(SubscriptionsError::LifecycleRegistryIdentityMismatch.into());
        }
        Ok(())
    }

    /// Revalidates the actual Authority Registry account supplied by the caller.
    ///
    /// The handler must pass the live Program-owned Registry account after
    /// checking account ownership. This prevents a signed payload or a stale
    /// cached generation from substituting for current customer consent.
    fn validate_live_authority_registry(
        identity: &FixedRecurringIdentity,
        registry_address: &Address,
        registry: &AuthorityConsentRegistry,
        expected_generation: u64,
    ) -> Result<(), ProgramError> {
        registry.validate_identity(
            registry_address,
            &identity.subscriber,
            &identity.mint,
            &identity.source_token_account,
            &identity.token_program,
        )?;

        let status = registry.status;
        let current_generation = registry.authority_generation;
        if status != AUTHORITY_REGISTRY_ACTIVE
            || current_generation != identity.authority_generation
            || current_generation != expected_generation
        {
            return Err(SubscriptionsError::StaleAuthorityGeneration.into());
        }
        Ok(())
    }

    /// Verifies that a signed operation targets the current active Authority
    /// generation and unconsumed lifecycle revision.
    fn validate_action(
        &self,
        registry_address: &Address,
        registry: &AuthorityConsentRegistry,
        expected_generation: u64,
        expected_revision: u64,
    ) -> Result<(), ProgramError> {
        Self::validate_live_authority_registry(&self.identity, registry_address, registry, expected_generation)?;
        if self.status != FixedRecurringStatus::Active {
            return Err(SubscriptionsError::Unauthorized.into());
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
        registry_address: &Address,
        registry: &AuthorityConsentRegistry,
        expected_generation: u64,
        expected_revision: u64,
    ) -> Result<u64, ProgramError> {
        self.validate_action(registry_address, registry, expected_generation, expected_revision)?;
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
        registry_address: &Address,
        registry: &AuthorityConsentRegistry,
        expected_generation: u64,
        expected_revision: u64,
    ) -> Result<u64, ProgramError> {
        self.validate_action(registry_address, registry, expected_generation, expected_revision)?;
        let next_revision = self.revision.checked_add(1).ok_or(SubscriptionsError::ArithmeticOverflow)?;
        self.revision = next_revision;
        self.status = FixedRecurringStatus::Terminal;
        Ok(next_revision)
    }
}

/// Draft payload layouts from protocol-design §8.4. These types are deliberately
/// crate-private and are not registered with Codama or the dispatcher. Their
/// lengths/offsets remain candidate review material until the Program identity,
/// persistent Registry account and V2 account-meta contract are frozen.

fn load_exact<T>(data: &[u8]) -> Result<&T, ProgramError> {
    if data.len() != core::mem::size_of::<T>() {
        return Err(SubscriptionsError::InvalidInstructionData.into());
    }
    Ok(unsafe { &*core::mem::transmute::<*const u8, *const T>(data.as_ptr()) })
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct DraftFixedCreateV2Data {
    pub nonce: u64,
    pub amount: u64,
    pub expiry_ts: i64,
    pub expected_authority_generation: u64,
    pub not_after_ts: i64,
}

impl DraftFixedCreateV2Data {
    pub const LEN: usize = core::mem::size_of::<Self>();
    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        load_exact(data)
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct DraftRecurringCreateV2Data {
    pub nonce: u64,
    pub amount_per_period: u64,
    pub period_length_s: u64,
    pub start_ts: i64,
    pub expiry_ts: i64,
    pub expected_authority_generation: u64,
    pub not_after_ts: i64,
}

impl DraftRecurringCreateV2Data {
    pub const LEN: usize = core::mem::size_of::<Self>();
    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        load_exact(data)
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct DraftFixedTransferV2Data {
    pub amount: u64,
    pub delegator: Address,
    pub mint: Address,
    pub expected_remaining_amount: u64,
    pub expected_authority_generation: u64,
    pub expected_lifecycle_revision: u64,
    pub not_after_ts: i64,
}

impl DraftFixedTransferV2Data {
    pub const LEN: usize = core::mem::size_of::<Self>();
    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        load_exact(data)
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct DraftRecurringTransferV2Data {
    pub amount: u64,
    pub delegator: Address,
    pub mint: Address,
    pub expected_period_start_ts: i64,
    pub expected_amount_pulled_in_period: u64,
    pub expected_authority_generation: u64,
    pub expected_lifecycle_revision: u64,
    pub not_after_ts: i64,
}

impl DraftRecurringTransferV2Data {
    pub const LEN: usize = core::mem::size_of::<Self>();
    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        load_exact(data)
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct DraftDelegationRevokeV2Data {
    pub expected_lifecycle_revision: u64,
    pub not_after_ts: i64,
}

impl DraftDelegationRevokeV2Data {
    pub const LEN: usize = core::mem::size_of::<Self>();
    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        load_exact(data)
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
        let token_program = addr(6);
        let authority_registry = AuthorityConsentRegistry::find_pda(&subscriber, &mint, &source).0;

        FixedRecurringIdentity {
            kind: FixedRecurringKind::Fixed,
            delegation: addr(4),
            subscriber,
            delegatee: addr(5),
            mint,
            source_token_account: source,
            token_program,
            authority_registry,
            authority_generation: 1,
        }
    }

    /// mode 0 = active generation 1; mode 1 = revoked generation 2;
    /// mode 2 = active generation 3 after revoke + explicit reauthorization.
    fn authority_registry_bytes(identity: &FixedRecurringIdentity, mode: u8) -> [u8; AuthorityConsentRegistry::LEN] {
        let (registry_address, bump) =
            AuthorityConsentRegistry::find_pda(&identity.subscriber, &identity.mint, &identity.source_token_account);
        assert_eq!(registry_address, identity.authority_registry);

        let mut bytes = [0u8; AuthorityConsentRegistry::LEN];
        AuthorityConsentRegistry::init(
            &mut bytes,
            &identity.subscriber,
            &identity.mint,
            &identity.source_token_account,
            &identity.token_program,
            &identity.subscriber,
            bump,
        )
        .unwrap();

        {
            let registry = AuthorityConsentRegistry::load_mut(&mut bytes).unwrap();
            registry.authorize(0, 0, 1_000, 1_900).unwrap();
            if mode >= 1 {
                registry.revoke(1, 0, 1_000, 1_900).unwrap();
            }
            if mode >= 2 {
                registry.authorize(2, 1, 1_000, 1_900).unwrap();
            }
        }

        bytes
    }

    fn initialized() -> FixedRecurringLifecycle {
        let identity = identity();
        let registry_bytes = authority_registry_bytes(&identity, 0);
        let registry = AuthorityConsentRegistry::load(&registry_bytes).unwrap();
        FixedRecurringLifecycle::new(identity, &identity.authority_registry, registry).unwrap()
    }

    #[test]
    fn identity_requires_the_canonical_authority_registry_and_nonzero_generation() {
        let original = identity();
        let registry_bytes = authority_registry_bytes(&original, 0);
        let registry = AuthorityConsentRegistry::load(&registry_bytes).unwrap();

        let mut wrong_registry = original;
        wrong_registry.authority_registry = addr(9);
        assert!(FixedRecurringLifecycle::new(wrong_registry, &original.authority_registry, registry).is_err());

        let mut zero_generation = original;
        zero_generation.authority_generation = 0;
        assert!(FixedRecurringLifecycle::new(zero_generation, &original.authority_registry, registry).is_err());

        let revoked_bytes = authority_registry_bytes(&original, 1);
        let revoked = AuthorityConsentRegistry::load(&revoked_bytes).unwrap();
        assert!(FixedRecurringLifecycle::new(original, &original.authority_registry, revoked).is_err());
    }

    #[test]
    fn identity_rejects_substitution_of_each_permission_component() {
        let state = initialized();
        let original = identity();

        let mut variants = [original; 9];
        variants[0].kind = FixedRecurringKind::Recurring;
        variants[1].delegation = addr(10);
        variants[2].subscriber = addr(11);
        variants[3].delegatee = addr(12);
        variants[4].mint = addr(13);
        variants[5].source_token_account = addr(14);
        variants[6].token_program = addr(15);
        variants[7].authority_registry = addr(16);
        variants[8].authority_generation = 2;

        for candidate in variants {
            assert!(state.validate_identity(&candidate).is_err());
        }
        assert!(state.validate_identity(&original).is_ok());
    }

    #[test]
    fn live_authority_registry_must_match_exact_token_program() {
        let mut substituted_identity = identity();
        substituted_identity.token_program = addr(7);
        let registry_bytes = authority_registry_bytes(&identity(), 0);
        let registry = AuthorityConsentRegistry::load(&registry_bytes).unwrap();

        assert!(FixedRecurringLifecycle::new(substituted_identity, &substituted_identity.authority_registry, registry)
            .is_err());
    }

    #[test]
    fn each_successful_transfer_consumes_a_one_shot_revision() {
        let mut state = initialized();
        let identity = identity();
        let registry_bytes = authority_registry_bytes(&identity, 0);
        let registry = AuthorityConsentRegistry::load(&registry_bytes).unwrap();

        assert_eq!(state.consume_transfer(&identity.authority_registry, registry, 1, 0).unwrap(), 1);
        assert!(state.consume_transfer(&identity.authority_registry, registry, 1, 0).is_err());
        assert_eq!(state.revision, 1);

        assert_eq!(state.consume_transfer(&identity.authority_registry, registry, 1, 1).unwrap(), 2);
        assert_eq!(state.revision, 2);
    }

    #[test]
    fn authority_reauthorization_does_not_revive_an_old_permission() {
        let mut state = initialized();
        let identity = identity();
        let registry_bytes = authority_registry_bytes(&identity, 2);
        let registry = AuthorityConsentRegistry::load(&registry_bytes).unwrap();

        assert!(state.consume_transfer(&identity.authority_registry, registry, 3, 0).is_err());
        assert_eq!(state.revision, 0);
        assert_eq!(state.status, FixedRecurringStatus::Active);
    }

    #[test]
    fn revoked_authority_registry_invalidates_existing_permission_actions() {
        let mut state = initialized();
        let identity = identity();
        let registry_bytes = authority_registry_bytes(&identity, 1);
        let registry = AuthorityConsentRegistry::load(&registry_bytes).unwrap();

        assert!(state.consume_transfer(&identity.authority_registry, registry, 1, 0).is_err());
        assert!(state.terminalize(&identity.authority_registry, registry, 1, 0).is_err());
        assert_eq!(state.revision, 0);
        assert_eq!(state.status, FixedRecurringStatus::Active);
    }

    #[test]
    fn terminal_revoke_is_monotonic_and_blocks_transfer_or_revoke_replay() {
        let mut state = initialized();
        let identity = identity();
        let registry_bytes = authority_registry_bytes(&identity, 0);
        let registry = AuthorityConsentRegistry::load(&registry_bytes).unwrap();

        assert_eq!(state.terminalize(&identity.authority_registry, registry, 1, 0).unwrap(), 1);
        assert_eq!(state.status, FixedRecurringStatus::Terminal);
        assert!(state.consume_transfer(&identity.authority_registry, registry, 1, 1).is_err());
        assert!(state.terminalize(&identity.authority_registry, registry, 1, 1).is_err());
        assert_eq!(state.revision, 1);
        assert_eq!(state.status, FixedRecurringStatus::Terminal);
    }

    #[test]
    fn revision_overflow_does_not_partially_commit_a_transition() {
        let mut state = initialized();
        state.revision = u64::MAX;
        let identity = identity();
        let registry_bytes = authority_registry_bytes(&identity, 0);
        let registry = AuthorityConsentRegistry::load(&registry_bytes).unwrap();

        assert!(state.consume_transfer(&identity.authority_registry, registry, 1, u64::MAX).is_err());
        assert_eq!(state.revision, u64::MAX);
        assert_eq!(state.status, FixedRecurringStatus::Active);

        assert!(state.terminalize(&identity.authority_registry, registry, 1, u64::MAX).is_err());
        assert_eq!(state.revision, u64::MAX);
        assert_eq!(state.status, FixedRecurringStatus::Active);
    }

    #[test]
    fn draft_v2_payload_layouts_match_protocol_design_candidates() {
        assert_eq!(DraftFixedCreateV2Data::LEN, 40);
        assert_eq!(core::mem::offset_of!(DraftFixedCreateV2Data, nonce), 0);
        assert_eq!(core::mem::offset_of!(DraftFixedCreateV2Data, amount), 8);
        assert_eq!(core::mem::offset_of!(DraftFixedCreateV2Data, expiry_ts), 16);
        assert_eq!(core::mem::offset_of!(DraftFixedCreateV2Data, expected_authority_generation), 24);
        assert_eq!(core::mem::offset_of!(DraftFixedCreateV2Data, not_after_ts), 32);

        assert_eq!(DraftRecurringCreateV2Data::LEN, 56);
        assert_eq!(core::mem::offset_of!(DraftRecurringCreateV2Data, nonce), 0);
        assert_eq!(core::mem::offset_of!(DraftRecurringCreateV2Data, amount_per_period), 8);
        assert_eq!(core::mem::offset_of!(DraftRecurringCreateV2Data, period_length_s), 16);
        assert_eq!(core::mem::offset_of!(DraftRecurringCreateV2Data, start_ts), 24);
        assert_eq!(core::mem::offset_of!(DraftRecurringCreateV2Data, expiry_ts), 32);
        assert_eq!(core::mem::offset_of!(DraftRecurringCreateV2Data, expected_authority_generation), 40);
        assert_eq!(core::mem::offset_of!(DraftRecurringCreateV2Data, not_after_ts), 48);

        assert_eq!(DraftFixedTransferV2Data::LEN, 104);
        assert_eq!(core::mem::offset_of!(DraftFixedTransferV2Data, amount), 0);
        assert_eq!(core::mem::offset_of!(DraftFixedTransferV2Data, delegator), 8);
        assert_eq!(core::mem::offset_of!(DraftFixedTransferV2Data, mint), 40);
        assert_eq!(core::mem::offset_of!(DraftFixedTransferV2Data, expected_remaining_amount), 72);
        assert_eq!(core::mem::offset_of!(DraftFixedTransferV2Data, expected_authority_generation), 80);
        assert_eq!(core::mem::offset_of!(DraftFixedTransferV2Data, expected_lifecycle_revision), 88);
        assert_eq!(core::mem::offset_of!(DraftFixedTransferV2Data, not_after_ts), 96);

        assert_eq!(DraftRecurringTransferV2Data::LEN, 112);
        assert_eq!(core::mem::offset_of!(DraftRecurringTransferV2Data, amount), 0);
        assert_eq!(core::mem::offset_of!(DraftRecurringTransferV2Data, delegator), 8);
        assert_eq!(core::mem::offset_of!(DraftRecurringTransferV2Data, mint), 40);
        assert_eq!(core::mem::offset_of!(DraftRecurringTransferV2Data, expected_period_start_ts), 72);
        assert_eq!(core::mem::offset_of!(DraftRecurringTransferV2Data, expected_amount_pulled_in_period), 80);
        assert_eq!(core::mem::offset_of!(DraftRecurringTransferV2Data, expected_authority_generation), 88);
        assert_eq!(core::mem::offset_of!(DraftRecurringTransferV2Data, expected_lifecycle_revision), 96);
        assert_eq!(core::mem::offset_of!(DraftRecurringTransferV2Data, not_after_ts), 104);

        assert_eq!(DraftDelegationRevokeV2Data::LEN, 16);
        assert_eq!(core::mem::offset_of!(DraftDelegationRevokeV2Data, expected_lifecycle_revision), 0);
        assert_eq!(core::mem::offset_of!(DraftDelegationRevokeV2Data, not_after_ts), 8);
    }

    #[test]
    fn draft_v2_payload_parsers_reject_truncation_and_trailing_bytes() {
        macro_rules! assert_strict_payload {
            ($payload:ty) => {{
                let valid = vec![0u8; <$payload>::LEN];
                assert!(<$payload>::load(&valid).is_ok());

                let truncated = vec![0u8; <$payload>::LEN - 1];
                assert!(<$payload>::load(&truncated).is_err());

                let mut trailing = vec![0u8; <$payload>::LEN];
                trailing.push(0);
                assert!(<$payload>::load(&trailing).is_err());
            }};
        }

        assert_strict_payload!(DraftFixedCreateV2Data);
        assert_strict_payload!(DraftRecurringCreateV2Data);
        assert_strict_payload!(DraftFixedTransferV2Data);
        assert_strict_payload!(DraftRecurringTransferV2Data);
        assert_strict_payload!(DraftDelegationRevokeV2Data);
    }
}
