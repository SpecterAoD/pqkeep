//! DE: Privater Base64-Restblock ausschließlich in vorab gesperrten `SecretBytes`.
//! EN: Private Base64 remainder exclusively in prelocked `SecretBytes`.

use base64ct::{Base64UrlUnpadded, Encoding};
use zeroize::Zeroize;

use crate::crypto::SecretBytes;
use crate::{Error, Result};

struct Workspace(SecretBytes);

impl Workspace {
    fn new() -> Result<Self> {
        Ok(Self(SecretBytes::zeroed(7)?))
    }

    fn encode<'a, T: Encoding>(&mut self, src: &[u8], dst: &'a mut [u8]) -> Result<&'a str> {
        let (input, output) = self.0.expose_mut().split_at_mut(3);
        T::encode_with_scratch(
            src,
            dst,
            input.try_into().map_err(|_| Error::Crypto)?,
            output.try_into().map_err(|_| Error::Crypto)?,
        )
        .map_err(|_| Error::Crypto)
    }

    fn wipe(&mut self) {
        self.0.expose_mut().zeroize();
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        self.wipe();
    }
}

pub(super) fn encode<'a>(src: &[u8], dst: &'a mut [u8]) -> Result<&'a str> {
    Workspace::new()?.encode::<Base64UrlUnpadded>(src, dst)
}

#[cfg(test)]
#[path = "token_encoding_tests.rs"]
mod tests;
