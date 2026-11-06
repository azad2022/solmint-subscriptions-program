use pinocchio::{
    cpi::Seed,
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use pinocchio_token::instructions::Revoke as RevokeSpl;
use pinocchio_token_2022::instructions::Revoke as Revoke2022;

use crate::{
    check_token_account_mint, check_token_account_owner,
    constants::TOKEN_2022_PROGRAM_ID,
    get_token_account_delegate,
    state::{AuthorityConsentRegistry, VNextSubscriptionAuthority},
    AccountCheck, AccountClose, MintInterface, ProgramAccount, ProgramAccountInit, SignerAccount, SubscriptionsError,
    SystemAccount,
    TokenAccountInterface, TokenProgramInterface, WritableAccount,
};

/// Discriminator for explicit VNext Authority invalidation.
pub const DISCRIMINATOR: &u8 = &19;

/// Advances the persistent consent generation and revokes the VNext token
/// delegate when it is still present. This also creates a Registry tombstone
/// when no Registry or Authority has landed yet, invalidating a pending Init.
pub fn process(accounts: &mut [AccountView], data: &crate::AuthorityActionData) -> ProgramResult {
    let [subscriber, registry, authority, token_mint, source_token_account, system_program, token_program, rem @ ..] =
        accounts
    else {
        return Err(SubscriptionsError::NotEnoughAccountKeys.into());
    };

    SignerAccount::check(subscriber)?;
    WritableAccount::check(subscriber)?;
    WritableAccount::check(registry)?;
    WritableAccount::check(authority)?;
    WritableAccount::check(source_token_account)?;
    SystemAccount::check(system_program)?;
    TokenProgramInterface::check(token_program)?;
    MintInterface::check_with_program(token_mint, token_program)?;

    if rem.len() > 1 {
        return Err(SubscriptionsError::InvalidInstructionData.into());
    }

    let (registry_address, registry_bump) =
        AuthorityConsentRegistry::find_pda(subscriber.address(), token_mint.address(), source_token_account.address());
    if registry_address != *registry.address() {
        return Err(SubscriptionsError::AuthorityConsentRegistryInvalidPda.into());
    }

    let (authority_address, _) = VNextSubscriptionAuthority::find_pda(
        subscriber.address(),
        token_mint.address(),
        source_token_account.address(),
    );
    if authority_address != *authority.address() {
        return Err(SubscriptionsError::VNextAuthorityInvalidPda.into());
    }

    let expected_ata = pinocchio::Address::find_program_address(
        &[subscriber.address().as_ref(), token_program.address().as_ref(), token_mint.address().as_ref()],
        &pinocchio_associated_token_account::ID,
    )
    .0;
    if expected_ata == *source_token_account.address() {
        return Err(SubscriptionsError::NonAssociatedSourceAccountRequired.into());
    }

    let authority_exists = authority.data_len() > 0;
    if registry.data_len() == 0 {
        // An Authority without its persistent Registry is an impossible state
        // under the atomic VNext creation path. Do not bootstrap or guess its
        // generation; require operator/account recovery instead.
        if authority_exists {
            return Err(SubscriptionsError::AuthorityConsentRegistryIdentityMismatch.into());
        }
        if registry.owned_by(&crate::ID) {
            return Err(SubscriptionsError::InvalidAccountData.into());
        }

        let bump_bytes = [registry_bump];
        let seeds = [
            Seed::from(AuthorityConsentRegistry::SEED),
            Seed::from(subscriber.address().as_ref()),
            Seed::from(token_mint.address().as_ref()),
            Seed::from(source_token_account.address().as_ref()),
            Seed::from(&bump_bytes),
        ];
        ProgramAccount::init::<AuthorityConsentRegistry>(subscriber, registry, &seeds, AuthorityConsentRegistry::LEN)?;

        let mut binding = registry.try_borrow_mut()?;
        AuthorityConsentRegistry::init(
            &mut binding,
            subscriber.address(),
            token_mint.address(),
            source_token_account.address(),
            token_program.address(),
            subscriber.address(),
            registry_bump,
        )?;
    } else {
        ProgramAccount::check(registry)?;
        let binding = registry.try_borrow()?;
        AuthorityConsentRegistry::load(&binding)?.validate_identity(
            registry.address(),
            subscriber.address(),
            token_mint.address(),
            source_token_account.address(),
            token_program.address(),
        )?;
    }

    let authority_rent_payer = if authority_exists {
        ProgramAccount::check(authority)?;
        let binding = authority.try_borrow()?;
        let vnext_authority = VNextSubscriptionAuthority::load(&binding)?;
        vnext_authority.validate_identity(
            authority.address(),
            subscriber.address(),
            token_mint.address(),
            source_token_account.address(),
            registry.address(),
            token_program.address(),
            data.expected_generation,
        )?;
        Some(vnext_authority.rent_payer)
    } else {
        None
    };

    // A missing source token account is acceptable for the tombstone-only path:
    // a closed account cannot be debited, and the Registry identity still binds
    // this exact address. When it exists, verify its owner/mint before a revoke.
    let delegate = if source_token_account.data_len() > 0 {
        TokenAccountInterface::check_with_program(source_token_account, token_program)?;
        let source_data = source_token_account.try_borrow()?;
        check_token_account_owner(&source_data, subscriber.address())?;
        check_token_account_mint(&source_data, token_mint.address())?;
        get_token_account_delegate(&source_data)?
    } else {
        None
    };

    {
        let mut binding = registry.try_borrow_mut()?;
        let consent = AuthorityConsentRegistry::load_mut(&mut binding)?;
        consent.revoke(
            data.expected_generation,
            data.expected_nonce,
            Clock::get()?.unix_timestamp,
            data.not_after_ts,
        )?;
    }

    // Never revoke a foreign delegate. If the VNext delegate remains on the
    // source account even after the Authority PDA was closed, remove it here.
    if delegate == Some(authority_address) {
        if token_program.address().eq(&TOKEN_2022_PROGRAM_ID) {
            Revoke2022 { source: source_token_account, authority: subscriber, token_program: token_program.address() }
                .invoke()?;
        } else {
            RevokeSpl::new(source_token_account, subscriber).invoke()?;
        }
    }

    if let Some(rent_payer) = authority_rent_payer {
        if rent_payer == *subscriber.address() {
            if !rem.is_empty() {
                return Err(SubscriptionsError::InvalidInstructionData.into());
            }
            ProgramAccount::close(authority, subscriber)?;
        } else {
            let receiver = rem.first().ok_or(SubscriptionsError::NotEnoughAccountKeys)?;
            WritableAccount::check(receiver)?;
            if *receiver.address() != rent_payer {
                return Err(SubscriptionsError::Unauthorized.into());
            }
            ProgramAccount::close(authority, receiver)?;
        }
    } else if !rem.is_empty() {
        return Err(SubscriptionsError::InvalidInstructionData.into());
    }

    Ok(())
}
