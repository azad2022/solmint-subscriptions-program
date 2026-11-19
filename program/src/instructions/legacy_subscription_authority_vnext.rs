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
    state::{
        AuthorityConsentRegistry, SubscriptionAuthority, AUTHORITY_REGISTRY_ACTIVE, AUTHORITY_REGISTRY_REVOKED,
    },
    AccountCheck, AccountClose, MintInterface, ProgramAccount, ProgramAccountInit, SignerAccount, SubscriptionsError,
    SystemAccount, TokenAccountInterface, TokenProgramInterface, WritableAccount,
};

use super::authority_consent::AuthorityActionData;

/// Generation-bound replacement for the old InitSubscriptionAuthority route.
pub const AUTHORIZE_DISCRIMINATOR: &u8 = &28;
/// Generation-bound replacement for the old Revoke/Close Authority routes.
pub const REVOKE_DISCRIMINATOR: &u8 = &29;

fn validate_legacy_authority(
    authority: &AccountView,
    subscriber: &Address,
    mint: &Address,
) -> Result<Option<Address>, pinocchio::error::ProgramError> {
    // ProgramAccount::close zeroes account data. A closed PDA may be recreated
    // at the same address; persistent Registry state prevents generation reset.
    if authority.data_len() == 0 {
        return Ok(None);
    }

    ProgramAccount::check(authority)?;
    let bytes = authority.try_borrow()?;
    let state = SubscriptionAuthority::load(&bytes)?;
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

    let (expected, bump) =
        AuthorityConsentRegistry::find_pda(subscriber.address(), mint.address(), source.address());
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
    // The permanent Registry is always customer-funded. Any optional sponsor
    // may fund only a closeable Authority account.
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

/// First call for a live v0.5.0 Authority lazily bootstraps the Registry at
/// generation 1 without changing Authority bytes or re-approving the delegate.
/// That leaves existing active SubscriptionDelegation accounts collectable.
/// An absent Authority uses the ordinary genesis-generation authorization path.
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

    if !rem.is_empty() {
        return Err(SubscriptionsError::InvalidInstructionData.into());
    }
    let now = Clock::get()?.unix_timestamp;
    AuthorityConsentRegistry::validate_action_deadline(now, data.not_after_ts)?;

    let (expected_authority, _) = SubscriptionAuthority::find_pda(subscriber.address(), mint.address());
    if expected_authority != *authority.address() {
        return Err(SubscriptionsError::InvalidSubscriptionAuthorityPda.into());
    }
    let existing_payer = validate_legacy_authority(authority, subscriber.address(), mint.address())?;
    let delegate = validate_source(subscriber, mint, source, token_program, false)?;

    if existing_payer.is_none() || delegate != Some(expected_authority) {
        // A new or re-created legacy permission is never granted by this
        // compatibility instruction. Fresh consent must use the independent
        // VNext non-ATA Authority route and its own Registry lineage.
        return Err(SubscriptionsError::LegacyInstructionDisabled.into());
    }

    if registry.data_len() != 0 {
        let status = validate_registry(registry, subscriber, mint, source, token_program)?;
        if status == AUTHORITY_REGISTRY_ACTIVE {
            return Err(SubscriptionsError::AuthorityAlreadyActive.into());
        }
        // Consume/check the signed expected generation and nonce before
        // refusing a fresh Legacy reauthorization. An obsolete delayed payload
        // therefore fails specifically as StaleAuthorityGeneration; a fresh
        // action is still rolled back by the deliberate fail-closed error.
        {
            let mut bytes = registry.try_borrow_mut()?;
            let state = AuthorityConsentRegistry::load_mut(&mut bytes)?;
            state.authorize(data.expected_generation, data.expected_nonce, now, data.not_after_ts)?;
        }
        return Err(SubscriptionsError::LegacyInstructionDisabled.into());
    }

    if data.expected_generation != 0 || data.expected_nonce != 0 {
        return Err(SubscriptionsError::AuthorityConsentRegistryIdentityMismatch.into());
    }

    // One-time capability-preserving migration. Do not touch Authority bytes,
    // do not re-Approve u64::MAX, and do not rewrite existing Subscription PDAs.
    initialize_registry(
        subscriber,
        registry,
        mint,
        source,
        token_program,
        1,
        AUTHORITY_REGISTRY_ACTIVE,
        1,
    )
}
 
/// Revokes one Legacy Authority generation atomically with Registry advancement,
/// token delegate revocation and Authority closure. Existing Subscription and
/// Plan PDAs remain intact but cannot collect after this transition; later
/// reauthorization gets a distinct negative init_id and cannot revive them.
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
        state.revoke(data.expected_generation, data.expected_nonce, now, data.not_after_ts)?;
    }

    if delegate == Some(expected_authority) {
        if token_program.address() == &TOKEN_2022_PROGRAM_ID {
            Revoke2022 { source, authority: subscriber, token_program: token_program.address() }.invoke()?;
        } else {
            RevokeSpl::new(source, subscriber).invoke()?;
        }
    } else if delegate.is_some() {
        return Err(SubscriptionsError::ForeignTokenDelegatePresent.into());
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

