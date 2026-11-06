use pinocchio::{
    cpi::Seed,
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use pinocchio_token::instructions::Approve as ApproveSpl;
use pinocchio_token_2022::instructions::Approve as Approve2022;

use crate::{
    check_token_account_mint,
    check_token_account_owner,
    constants::TOKEN_2022_PROGRAM_ID,
    get_token_account_delegate,
    helpers::system::resolve_optional_payer,
    state::{
        AuthorityConsentRegistry, VNextSubscriptionAuthority,
    },
    AccountCheck, MintInterface, ProgramAccount, ProgramAccountInit, SignerAccount,
    SubscriptionsError, SystemAccount, TokenAccountInterface, TokenProgramInterface, WritableAccount,
};

/// Discriminator for explicit VNext Authority consent.
pub const DISCRIMINATOR: &u8 = &18;

/// Creates a persistent Registry (customer-funded), advances its generation,
/// creates a tuple-bound Authority, and grants that Authority the SPL delegate.
/// The source account must be a customer-owned non-ATA token account.
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
    TokenAccountInterface::check_with_program(source_token_account, token_program)?;

    if rem.len() > 1 {
        return Err(SubscriptionsError::InvalidInstructionData.into());
    }
    let authority_payer = resolve_optional_payer(subscriber, rem)?;

    let (registry_address, registry_bump) =
        AuthorityConsentRegistry::find_pda(subscriber.address(), token_mint.address(), source_token_account.address());
    if registry_address != *registry.address() {
        return Err(SubscriptionsError::AuthorityConsentRegistryInvalidPda.into());
    }

    let (authority_address, authority_bump) = VNextSubscriptionAuthority::find_pda(
        subscriber.address(),
        token_mint.address(),
        source_token_account.address(),
    );
    if authority_address != *authority.address() {
        return Err(SubscriptionsError::VNextAuthorityInvalidPda.into());
    }

    // VNext deliberately uses a dedicated non-ATA account. The legacy
    // v0.5.0 program derives and accepts only the canonical ATA; this is the
    // first half of the legacy-program isolation boundary.
    let expected_ata = pinocchio::Address::find_program_address(
        &[subscriber.address().as_ref(), token_program.address().as_ref(), token_mint.address().as_ref()],
        &pinocchio_associated_token_account::ID,
    )
    .0;
    if expected_ata == *source_token_account.address() {
        return Err(SubscriptionsError::NonAssociatedSourceAccountRequired.into());
    }

    {
        let source_data = source_token_account.try_borrow()?;
        check_token_account_owner(&source_data, subscriber.address())?;
        check_token_account_mint(&source_data, token_mint.address())?;
        if let Some(delegate) = get_token_account_delegate(&source_data)? {
            if delegate != authority_address {
                return Err(SubscriptionsError::ForeignTokenDelegatePresent.into());
            }
        }
    }

    // The Registry is permanently retained so its generation cannot be reset.
    // The subscriber, not a rent sponsor, funds this tombstone account.
    if registry.data_len() == 0 {
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
    }

    let generation = {
        let mut binding = registry.try_borrow_mut()?;
        let consent = AuthorityConsentRegistry::load_mut(&mut binding)?;
        consent.validate_identity(
            registry.address(),
            subscriber.address(),
            token_mint.address(),
            source_token_account.address(),
            token_program.address(),
        )?;
        consent.authorize(
            data.expected_generation,
            data.expected_nonce,
            Clock::get()?.unix_timestamp,
            data.not_after_ts,
        )?
    };

    // A previous Authority must have been closed by the atomic revoke path.
    // Never treat a non-empty Authority as an idempotent reapproval request.
    if authority.data_len() > 0 || authority.owned_by(&crate::ID) {
        return Err(SubscriptionsError::VNextAuthorityIdentityMismatch.into());
    }

    let authority_bump_bytes = [authority_bump];
    let authority_seeds = [
        Seed::from(VNextSubscriptionAuthority::SEED),
        Seed::from(subscriber.address().as_ref()),
        Seed::from(token_mint.address().as_ref()),
        Seed::from(source_token_account.address().as_ref()),
        Seed::from(&authority_bump_bytes),
    ];
    ProgramAccount::init::<VNextSubscriptionAuthority>(
        authority_payer,
        authority,
        &authority_seeds,
        VNextSubscriptionAuthority::LEN,
    )?;

    {
        let mut binding = authority.try_borrow_mut()?;
        VNextSubscriptionAuthority::init(
            &mut binding,
            subscriber.address(),
            token_mint.address(),
            source_token_account.address(),
            registry.address(),
            token_program.address(),
            authority_payer.address(),
            generation,
            authority_bump,
        )?;
    }

    // All Registry and Authority state changes roll back if this Token CPI fails.
    if token_program.address().eq(&TOKEN_2022_PROGRAM_ID) {
        Approve2022 {
            token_program: token_program.address(),
            source: source_token_account,
            delegate: authority,
            authority: subscriber,
            amount: u64::MAX,
        }
        .invoke()?;
    } else {
        ApproveSpl::new(source_token_account, authority, subscriber, u64::MAX).invoke()?;
    }

    Ok(())
}
