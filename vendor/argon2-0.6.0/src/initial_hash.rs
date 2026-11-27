//! DE: Ein gemeinsamer ursprünglicher Framing-Ablauf für gewöhnlichen/geschützten Hash.
//! EN: One shared original framing sequence for ordinary/protected hashing.

use crate::{Argon2, Error};
use blake2::{Blake2b512, Digest};

pub(crate) trait InitialHashSink {
    type Error: From<Error>;
    fn word(&mut self, value: u32) -> Result<(), Self::Error>;
    fn bytes(&mut self, value: &[u8]) -> Result<(), Self::Error>;
}

impl InitialHashSink for Blake2b512 {
    type Error = Error;
    fn word(&mut self, value: u32) -> Result<(), Self::Error> {
        Digest::update(self, value.to_le_bytes());
        Ok(())
    }
    fn bytes(&mut self, value: &[u8]) -> Result<(), Self::Error> {
        Digest::update(self, value);
        Ok(())
    }
}

#[cfg(feature = "protected-workspace")]
impl InitialHashSink for blake2::ProtectedBlake2b {
    type Error = crate::WorkspaceError;
    fn word(&mut self, value: u32) -> Result<(), Self::Error> {
        self.update_u32_le(value).map_err(Into::into)
    }
    fn bytes(&mut self, value: &[u8]) -> Result<(), Self::Error> {
        self.update(value).map_err(Into::into)
    }
}

impl Argon2<'_> {
    pub(crate) fn absorb_initial_hash<H: InitialHashSink>(
        &self,
        password: &[u8],
        salt: &[u8],
        ad: &[u8],
        output_length: usize,
        hash: &mut H,
    ) -> Result<(), H::Error> {
        let output_length = length(output_length)?;
        let password_length = length(password.len())?;
        let salt_length = length(salt.len())?;
        let secret_length = length(self.secret.map_or(0, <[u8]>::len))?;
        let ad_length = length(ad.len())?;
        hash.word(self.params.p_cost())?;
        hash.word(output_length)?;
        hash.word(self.params.m_cost())?;
        hash.word(self.params.t_cost())?;
        hash.word(self.version as u32)?;
        hash.word(self.algorithm as u32)?;
        hash.word(password_length)?;
        hash.bytes(password)?;
        hash.word(salt_length)?;
        hash.bytes(salt)?;
        hash.word(secret_length)?;
        if let Some(secret) = self.secret {
            hash.bytes(secret)?;
        }
        hash.word(ad_length)?;
        hash.bytes(ad)
    }
}

fn length(value: usize) -> Result<u32, Error> {
    u32::try_from(value).map_err(|_| Error::OutputTooLong)
}
