use pinocchio::{
    cpi::Seed,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_token::instructions::{Approve as ApproveSpl, Revoke as RevokeSpl};
use pinocchio_token_2022::instructions::{Approve as Approve2022, Revoke as Revoke2022};

use crate::{
    check_token_account_mint, check_token_account_owner,
    constants::TOKEN_2022_PROGRAM_ID,
    get_token_account_delegate,
    helpers::system::resolve_optional_payer,
    state::{
        AuthorityConsentRegistry, SubscriptionAuthority, AUTHORITY_REGISTRY_ACTIVE, AUTHORITY_REGISTRY_REVOKED,
    },
    AccountCheck, AccountClose, MintInterface, ProgramAccount, ProgramAccountInit, SignerAccount, SubscriptionsError,
    SystemAccount, TokenAccountInterface, TokenProgramInterface, WritableAccount,
};

use super::authority_consent::AuthorityActionData;

/// Discriminator for a generation-bound Legacy Authority authorization.
pub const AUTHORIZE_DISCRIMINATOR: &u8 = &28;
/// Discriminator for a generation-bound Legacy Authority invalidation.
pub const REVOKE_DISCRIMINATOR: &u8 = &29;

/// Maps a Registry generation into a negative, non-sentinel legacy init_id.
/// Legacy v0.5.0 init_ids are non-negative clock slots, so a post-revocation
/// Authority incarnation can never match an old delegation header, including
/// when close/recreate happens in the same slot.
fn generation_init_id(generation: u64) -> Result<i64, SubscriptionsError> {
    let value = i64::try_from(generation).map_err(|_| SubscriptionsError::ArithmeticOverflow)?;
    if value == 0 {
        return Err(SubscriptionsError::ArithmeticOverflow);
    }
    i64::MIN.checked_add(value).ok_or(SubscriptionsError::ArithmeticOverflow)
}

fn validate_legacy_authority(
    authority: &AccountView,
    subscriber: &Address,
    mint: &Address,
) -> Result<Option<Address>, pinocchio::error::ProgramError> {
    if authority.data_len() == 0 {
        if authority.owned_by(&crate::ID) {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        return Ok(None);
    }

    ProgramAccount::check(authority)?;
    let data = authority.try_borrow()?;
    let state = SubscriptionAuthority::load(&data)?;
    state.check_owner(subscriber)?;
    if state.token_mint != *mint {
        return Err(SubscriptionsError::MintMismatch.into());
    }
    let bump = state.bump;
    if SubscriptionAuthority::verify_pda(subscriber, mint, bump)? != *authority.address() {
        return Err(SubscriptionsError::InvalidSubscriptionAuthorityPda.into());
    }
    Ok(Some(state.payer))
}

fn validate_source(
    subscriber: &AccountView,
    mint: &AccountView,
    source: &AccountView,
    token_program: &AccountView,
    allow_missing: bool,
) -> Result<Option<Address>, pinocchio::error::ProgramError> {
    let expected_ata = Address::find_program_address(
        &[subscriber.address().as_ref(), token_program.address().as_ref(), mint.address().as_ref()],
        &pinocchio_associated_token_account::ID,
    )
    .0;
    if expected_ata != *source.address() {
        return Err(SubscriptionsError::InvalidAssociatedTokenAccountDerivedAddress.into());
    }

    if source.data_len() == 0 {
        if allow_missing {
            return Ok(None);
        }
        return Err(SubscriptionsError::InvalidAccountData.into());
    }

    TokenAccountInterface::check_with_program(source, token_program)?;
    let bytes = source.try_borrow()?;
    check_token_account_owner(&bytes, subscriber.address())?;
    check_token_account_mint(&bytes, mint.address())?;
    get_token_account_delegate(&bytes).map_err(Into::into)
}

fn initialize_registry(
    subscriber: &AccountView,
    registry: &AccountView,
    mint: &AccountView,
    source: &AccountView,
    token_program: &AccountView,
    initial_generation: u64,
    status: u8,
    authorize_nonce: u64,
) -> ProgramResult {
    if registry.data_len() != 0 || registry.owned_by(&crate::ID) {
        return Err(SubscriptionsError::InvalidAccountData.into());
    }
    let (expected, bump) = AuthorityConsentRegistry::find_pda(
        subscriber.address(),
        mint.address(),
        source.address(),
    );
    if expected != *registry.address() {
        return Err(SubscriptionsError::AuthorityConsentRegistryInvalidPda.into());
    }

    let bump_bytes = [bump];
    let seeds = [
        Seed::from(AuthorityConsentRegistry::SEED),
        Seed::from(subscriber.address().as_ref()),
        Seed::from(mint.address().as_ref()),
        Seed::from(source.address().as_ref()),
        Seed::from(&bump_bytes),
    ];
    // The subscriber funds the permanent Registry. An optional rent sponsor
    // may fund only the closeable legacy Authority account.
    ProgramAccount::init::<AuthorityConsentRegistry>(
        subscriber,
        registry,
        &seeds,
        AuthorityConsentRegistry::LEN,
    )?;

    let mut bytes = registry.try_borrow_mut()?;
    AuthorityConsentRegistry::init(
        &mut bytes,
        subscriber.address(),
        mint.address(),
        source.address(),
        token_program.address(),
        subscriber.address(),
        bump,
    )?;
    let state = AuthorityConsentRegistry::load_mut(&mut bytes)?;
    state.authority_generation = initial_generation;
    state.status = status;
    state.authorize_nonce = authorize_nonce;
    Ok(())
}

fn validate_registry(
    registry: &AccountView,
    subscriber: &AccountView,
    mint: &AccountView,
    source: &AccountView,
    token_program: &AccountView,
) -> Result<u8, pinocchio::error::ProgramError> {
    ProgramAccount::check(registry)?;
    let bytes = registry.try_borrow()?;
    let state = AuthorityConsentRegistry::load(&bytes)?;
    state.validate_identity(
        registry.address(),
        subscriber.address(),
        mint.address(),
        source.address(),
        token_program.address(),
    )?;
    Ok(state.status)
}

fn create_or_reauthorize_legacy_authority(
    subscriber: &AccountView,
    authority: &AccountView,
    mint: &AccountView,
    payer: &AccountView,
    generation: u64,
) -> ProgramResult {
    if authority.data_len() != 0 || authority.owned_by(&crate::ID) {
        return Err(SubscriptionsError::AuthorityConsentRegistryIdentityMismatch.into());
    }
    let (expected, bump) = SubscriptionAuthority::find_pda(subscriber.address(), mint.address());
    if expected != *authority.address() {
        return Err(SubscriptionsError::InvalidSubscriptionAuthorityPda.into());
    }

    let init_id = generation_init_id(generation)?;
    let bump_bytes = [bump];
    let seeds = [
        Seed::from(SubscriptionAuthority::SEED),
        Seed::from(subscriber.address().as_ref()),
        Seed::from(mint.address().as_ref()),
        Seed::from(&bump_bytes),
    ];
    ProgramAccount::init::<SubscriptionAuthority>(
        payer,
        authority,
        &seeds,
        SubscriptionAuthority::LEN,
    )?;
    let mut bytes = authority.try_borrow_mut()?;
    SubscriptionAuthority::init(
        &mut bytes,
        subscriber.address(),
        mint.address(),
        payer.address(),
        bump,
        init_id,
    )?;
    Ok(())
}

/// Generation-bound replacement for the unversioned legacy Init instruction.
///
/// On first use with an existing, currently delegated v0.5.0 Authority, this
/// lazily bootstraps Registry generation 1 without changing Authority.init_id
/// or re-approving the token delegate. Existing SubscriptionDelegation records
/// therefore remain collectible through the versioned transfer route until
/// the customer explicitly revokes the Authority.
pub fn process_authorize(accounts: &mut [AccountView], data: &AuthorityActionData) -> ProgramResult {
    let [subscriber, registry, authority, mint, source, system_program, token_program, rem @ ..] = accounts else {
        return Err(SubscriptionsError::NotEnoughAccountKeys.into());
    };

    SignerAccount::check(subscriber)?;
    WritableAccount::check(subscriber)?;
    WritableAccount::check(registry)?;
    WritableAccount::check(authority)?;
    WritableAccount::check(source)?;
    SystemAccount::check(system_program)?;
    TokenProgramInterface::check(token_program)?;
    MintInterface::check_with_program(mint, token_program)?;
    TokenAccountInterface::check_with_program(source, token_program)?;

    if rem.len() > 1 {
        return Err(SubscriptionsError::InvalidInstructionData.into());
    }
    let authority_payer = resolve_optional_payer(subscriber, rem)?;

    let now = Clock::get()?.unix_timestamp;
    AuthorityConsentRegistry::validate_action_deadline(now, data.not_after_ts)?;

    let (expected_authority, _) = SubscriptionAuthority::find_pda(subscriber.address(), mint.address());
    if expected_authority != *authority.address() {
        return Err(SubscriptionsError::InvalidSubscriptionAuthorityPda.into());
    }
    let existing_payer = validate_legacy_authority(authority, subscriber.address(), mint.address())?;
    let delegate = validate_source(subscriber, mint, source, token_program, false)?;

    if let Some(current_delegate) = delegate {
        if current_delegate != expected_authority {
            return Err(SubscriptionsError::ForeignTokenDelegatePresent.into());
        }
    }

    if registry.data_len() == 0 {
        if let Some(_stored_payer) = existing_payer {
            // The only safe no-Registry migration is a live legacy delegate.
            // The old Authority is preserved byte-for-byte; its existing
            // Subscription headers continue to match until a later V2 revoke.
            if delegate != Some(expected_authority) || data.expected_generation != 0 || data.expected_nonce != 0 {
                return Err(SubscriptionsError::AuthorityConsentRegistryIdentityMismatch.into());
            }
            initialize_registry(
                subscriber,
                registry,
                mint,
                source,
                token_program,
                1,
                AUTHORITY_REGISTRY_ACTIVE,
                1,
            )?;
            return Ok(());
        }

        initialize_registry(
            subscriber,
            registry,
            mint,
            source,
            token_program,
            0,
            AUTHORITY_REGISTRY_REVOKED,
            0,
        )?;
    } else {
        let status = validate_registry(registry, subscriber, mint, source, token_program)?;
        if status == AUTHORITY_REGISTRY_ACTIVE {
            return Err(SubscriptionsError::AuthorityAlreadyActive.into());
        }
        if status != AUTHORITY_REGISTRY_REVOKED {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }
        if delegate.is_some() {
            // A revoked Registry plus a still-present delegate is inconsistent.
            // Require the explicit revoke path to reconcile it before reapproval.
            return Err(SubscriptionsError::AuthorityConsentRegistryIdentityMismatch.into());
        }
        if existing_payer.is_some() {
            // A completed V2 revoke closes the old Authority atomically. An
            // open Authority beside a revoked Registry is not a valid state.
            return Err(SubscriptionsError::AuthorityConsentRegistryIdentityMismatch.into());
        }
    }

    let generation = {
        let mut bytes = registry.try_borrow_mut()?;
        let state = AuthorityConsentRegistry::load_mut(&mut bytes)?;
        state.authorize(
            data.expected_generation,
            data.expected_nonce,
            now,
            data.not_after_ts,
        )?
    };

    create_or_reauthorize_legacy_authority(
        subscriber,
        authority,
        mint,
        authority_payer,
        generation,
    )?;

    // The new Authority PDA and Registry generation are committed only if the
    // token Approve CPI succeeds. The user must sign this explicit action.
    if token_program.address() == &TOKEN_2022_PROGRAM_ID {
        Approve2022 {
            token_program: token_program.address(),
            source,
            delegate: authority,
            authority: subscriber,
            amount: u64::MAX,
        }
        .invoke()?;
    } else {
        ApproveSpl::new(source, authority, subscriber, u64::MAX).invoke()?;
    }

    Ok(())
}

/// Generation-bound replacement for legacy Revoke/Close.
///
/// Revoke advances the permanent Registry, revokes only this Program's legacy
/// delegate, and closes the old Authority in one atomic transaction. The old
/// Subscription/Delegation PDAs are intentionally retained as historical state;
/// their old init_id can never match the negative generation-derived init_id
/// written by a later reauthorization.
pub fn process_revoke(accounts: &mut [AccountView], data: &AuthorityActionData) -> ProgramResult {
    let [subscriber, registry, authority, mint, source, system_program, token_program, rem @ ..] = accounts else {
        return Err(SubscriptionsError::NotEnoughAccountKeys.into());
    };

    SignerAccount::check(subscriber)?;
    WritableAccount::check(subscriber)?;
    WritableAccount::check(registry)?;
    WritableAccount::check(authority)?;
    SystemAccount::check(system_program)?;
    TokenProgramInterface::check(token_program)?;
    MintInterface::check_with_program(mint, token_program)?;

    if rem.len() > 1 {
        return Err(SubscriptionsError::InvalidInstructionData.into());
    }
    let now = Clock::get()?.unix_timestamp;
    AuthorityConsentRegistry::validate_action_deadline(now, data.not_after_ts)?;

    let (expected_authority, _) = SubscriptionAuthority::find_pda(subscriber.address(), mint.address());
    if expected_authority != *authority.address() {
        return Err(SubscriptionsError::InvalidSubscriptionAuthorityPda.into());
    }
    let stored_payer = validate_legacy_authority(authority, subscriber.address(), mint.address())?;

    let delegate = validate_source(subscriber, mint, source, token_program, true)?;

    if registry.data_len() == 0 {
        if stored_payer.is_some() {
            // Treat a pre-Registry legacy Authority as generation 1. This makes
            // the first V2 invalidation race-safe against an already-signed V2
            // authorization that expected the empty generation-0 Registry.
            initialize_registry(
                subscriber,
                registry,
                mint,
                source,
                token_program,
                1,
                AUTHORITY_REGISTRY_ACTIVE,
                1,
            )?;
        } else {
            // No Authority: create a generation-0 tombstone base; revoke(1)
            // advances it to generation 2 and preempts a pending first authorize.
            initialize_registry(
                subscriber,
                registry,
                mint,
                source,
                token_program,
                0,
                AUTHORITY_REGISTRY_REVOKED,
                0,
            )?;
        }
    } else {
        validate_registry(registry, subscriber, mint, source, token_program)?;
    }

    {
        let mut bytes = registry.try_borrow_mut()?;
        let state = AuthorityConsentRegistry::load_mut(&mut bytes)?;
        state.revoke(
            data.expected_generation,
            data.expected_nonce,
            now,
            data.not_after_ts,
        )?;
    }

    if delegate == Some(expected_authority) {
        if token_program.address() == &TOKEN_2022_PROGRAM_ID {
            Revoke2022 {
                source,
                authority: subscriber,
                token_program: token_program.address(),
            }
            .invoke()?;
        } else {
            RevokeSpl::new(source, subscriber).invoke()?;
        }
    }

    if let Some(payer) = stored_payer {
        if payer == *subscriber.address() {
            if !rem.is_empty() {
                return Err(SubscriptionsError::InvalidInstructionData.into());
            }
            ProgramAccount::close(authority, subscriber)?;
        } else {
            let receiver = rem.first().ok_or(SubscriptionsError::NotEnoughAccountKeys)?;
            WritableAccount::check(receiver)?;
            if *receiver.address() != payer {
                return Err(SubscriptionsError::Unauthorized.into());
            }
            ProgramAccount::close(authority, receiver)?;
        }
    } else if !rem.is_empty() {
        return Err(SubscriptionsError::InvalidInstructionData.into());
    }

    Ok(())
}
