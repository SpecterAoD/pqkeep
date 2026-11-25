//! DE: Parserdescriptor vor Scratch-Reservierung und privater Quellenbindung sperren.
//! EN: Lock parser metadata before scratch reservation and private source binding.

use super::{ApiError, ScratchLock, SecretState};
use serde::de::DeserializeOwned;
use serde_json::{Deserializer, de::ProtectedScratchError, de::SliceRead};

struct Parser<'a>(Deserializer<SliceRead<'a>>);

// DE: Konkreter SliceRead besitzt nur Scratch als privaten Payload: dessen Drop
// wischt die volle Kapazität vor Unlock/Free. SecretState zerstört ihn an Ort
// und wischt danach den gesamten Parser, einschließlich Padding, vor Unlock.
// EN: This concrete parser owns only protected scratch; its destructor wipes
// that payload. SecretState then wipes the full inline allocation before unlock.
impl zeroize::ZeroizeOnDrop for Parser<'_> {}

fn empty<'a>() -> Result<SecretState<Parser<'a>>, ApiError> {
    SecretState::new(Parser(Deserializer::from_slice(&[]))).map_err(|_| ApiError::Busy)
}

pub(super) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    let capacity = bytes
        .len()
        .checked_add(128)
        .ok_or(ApiError::PayloadTooLarge)?;
    let mut state = empty()?;
    state
        .get_mut()
        .0
        .prepare_protected_scratch(capacity, |address, capacity| {
            ScratchLock::new(address, capacity)
                .map(|guard| Box::new(guard) as Box<dyn serde_json::de::ScratchProtection>)
        })
        .map_err(|error| match error {
            ProtectedScratchError::Unsupported => ApiError::BadRequest,
            ProtectedScratchError::Allocation => ApiError::Busy,
            ProtectedScratchError::Protection(error) => error,
        })?;
    state
        .get_mut()
        .0
        .deserialize_protected_slice(bytes)
        .map_err(|_| ApiError::BadRequest)
}

#[cfg(test)]
#[path = "locked_parser_tests.rs"]
mod tests;
