//! DE: Begrenzte Body- und Parserpuffer vor Kopie/Decodierung sperren.
//! EN: Lock bounded body and parser buffers before copying/decoding.

use axum::extract::{FromRequest, Request};
use axum::http::{HeaderMap, header};
use hyper::body::Body as HttpBody;
use serde::de::DeserializeOwned;
use std::{future::poll_fn, pin::Pin};
use zeroize::Zeroize;

use super::{MAX_BODY_BYTES, handlers::ApiError};
use crate::crypto::SecretBytes;
use crate::hardening::memlock::{self, LockedRange};

pub(super) struct LockedJson<T>(pub T);

struct ScratchLock {
    _lock: LockedRange,
}

impl serde_json::de::ScratchProtection for ScratchLock {
    fn wipe(&mut self, scratch: &mut Vec<u8>) {
        // DE: Auch zuvor durch clear/pop unsichtbar gewordene Bytes löschen.
        // EN: Also wipe bytes hidden by earlier clear/pop operations.
        scratch.resize(scratch.capacity(), 0);
        scratch.as_mut_slice().zeroize();
    }
}

#[cfg(test)]
#[path = "locked_json_tests.rs"]
mod tests;

fn content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<mime::Mime>().ok())
        .is_some_and(|mime| {
            mime.type_() == mime::APPLICATION
                && (mime.subtype() == mime::JSON || mime.suffix() == Some(mime::JSON))
        })
}

pub(super) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    let capacity = bytes
        .len()
        .checked_add(128)
        .ok_or(ApiError::PayloadTooLarge)?;
    let mut scratch: Vec<u8> = Vec::new();
    scratch
        .try_reserve_exact(capacity)
        .map_err(|_| ApiError::Busy)?;
    let address = scratch.as_ptr().addr();
    let lock = memlock::lock_range(address, scratch.capacity());
    if !lock.complete(address, scratch.capacity()) {
        return Err(ApiError::Busy);
    }
    let protection = Box::new(ScratchLock { _lock: lock });
    let mut parser =
        serde_json::Deserializer::from_slice_with_protection(bytes, scratch, protection)
            .map_err(|_| ApiError::Internal)?;
    let value = T::deserialize(&mut parser).map_err(|_| ApiError::BadRequest)?;
    parser.end().map_err(|_| ApiError::BadRequest)?;
    Ok(value)
}

impl<S, T> FromRequest<S> for LockedJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, _state: &S) -> Result<Self, Self::Rejection> {
        if !content_type(request.headers()) {
            return Err(ApiError::UnsupportedMediaType);
        }
        let mut bytes = SecretBytes::zeroed(MAX_BODY_BYTES).map_err(|_| ApiError::Busy)?;
        let mut body = request.into_body();
        let mut len = 0usize;
        while let Some(frame) = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
            let frame = frame.map_err(|_| ApiError::BadRequest)?;
            if let Ok(data) = frame.into_data() {
                let end = len
                    .checked_add(data.len())
                    .filter(|n| *n <= MAX_BODY_BYTES)
                    .ok_or(ApiError::PayloadTooLarge)?;
                bytes.expose_mut()[len..end].copy_from_slice(&data);
                len = end;
            }
        }
        decode(&bytes.expose()[..len]).map(Self)
    }
}
