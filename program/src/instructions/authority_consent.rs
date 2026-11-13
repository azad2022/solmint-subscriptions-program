use codama::CodamaType;
use core::mem::{size_of, transmute};
use pinocchio::error::ProgramError;

use crate::SubscriptionsError;

/// Shared signed-action payload for VNext Authority authorize and revoke.
///
/// Integers are serialized little-endian. expected_generation and
/// expected_nonce are checked against the persistent Registry; the deadline is
/// checked against Clock::unix_timestamp by the Program.
#[repr(C, packed)]
#[derive(CodamaType, Debug, Clone)]
pub struct AuthorityActionData {
    /// Registry generation observed by the signer.
    pub expected_generation: u64,
    /// Monotonic nonce for this action class.
    pub expected_nonce: u64,
    /// Inclusive Unix timestamp deadline, bounded by the Program.
    pub not_after_ts: i64,
}

impl AuthorityActionData {
    /// Exact payload size.
    pub const LEN: usize = size_of::<Self>();

    /// Loads exactly one v1 Authority action payload.
    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(SubscriptionsError::InvalidInstructionData.into());
        }
        Ok(unsafe { &*transmute::<*const u8, *const Self>(data.as_ptr()) })
    }
}
