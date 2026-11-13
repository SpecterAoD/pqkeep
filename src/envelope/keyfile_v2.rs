//! DE: Schlüsseldatei Version 2 (`docs/V2_DRAFT.md`): der private Schlüssel ist mit Passphrase
//! **und** Faktordatei geschützt. Version 2 gibt es nur mit Faktordatei (D3); ohne sie bleibt
//! es bei Version 1. Die Faktordatei wird nie stillschweigend ignoriert: eine Datei der
//! Version 1 mit Faktor zu öffnen ist ein Fehler, ebenso Version 2 ohne Faktor.
//!
//! EN: Key file version 2 (`docs/V2_DRAFT.md`): the private key is protected with passphrase
//! **and** factor file. Version 2 only exists with a factor file (D3); without one it stays
//! version 1. The factor file is never silently ignored: opening a version 1 file with a
//! factor is an error, as is version 2 without one.

use super::Metadata;
use super::format::{FORMAT_VERSION, FORMAT_VERSION_V2};
use super::keyfile::{KeyFile, UnlockedKey, new_secret};
use crate::crypto::factor::Factor;
use crate::crypto::kdf::KdfParams;
use crate::crypto::{KeyAlgorithm, protect_v2};
use crate::security::{Passphrase, StrongPassphrase};
use crate::{Error, Result};

impl KeyFile {
    /// DE: Erzeugt einen neuen Schlüssel, geschützt mit Passphrase und Faktordatei (Version 2).
    /// EN: Generates a new key protected with passphrase and factor file (version 2).
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] (Metadaten / metadata), [`Error::KdfParams`], [`Error::Rng`].
    pub fn generate_with_factor(
        passphrase: &StrongPassphrase,
        factor: &Factor,
        algorithm: KeyAlgorithm,
        metadata: &Metadata,
        params: &KdfParams,
    ) -> Result<Self> {
        let (secret, public_key) = new_secret(algorithm)?;
        let secret = secret.expose();
        Self::build(algorithm, secret, &public_key, metadata, true, |header| {
            protect_v2::protect(passphrase, factor, algorithm, secret, params, header)
        })
    }

    /// DE: Schützt vorhandenes Schlüsselmaterial mit Passphrase und Faktordatei (Version 2);
    /// prüft, dass Seed und öffentlicher Schlüssel zusammenpassen.
    /// EN: Protects existing key material with passphrase and factor file (version 2); checks
    /// that seed and public key match.
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`], [`Error::KdfParams`], [`Error::Rng`].
    pub fn create_with_factor(
        passphrase: &StrongPassphrase,
        factor: &Factor,
        algorithm: KeyAlgorithm,
        secret: &[u8],
        public_key: &[u8],
        metadata: &Metadata,
        params: &KdfParams,
    ) -> Result<Self> {
        Self::build(algorithm, secret, public_key, metadata, true, |header| {
            protect_v2::protect(passphrase, factor, algorithm, secret, params, header)
        })
    }

    /// DE: Entsperrt eine Schlüsseldatei der Version 2 mit Passphrase und Faktordatei.
    /// EN: Unlocks a version 2 key file with passphrase and factor file.
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] (`factor_unused`: Version 1 kennt keine Faktordatei; sie
    /// wird nicht stillschweigend ignoriert / version 1 has no factor file; it is not silently
    /// ignored), [`Error::Decrypt`] (falsche Passphrase, falsche Faktordatei, Manipulation /
    /// wrong passphrase, wrong factor file, tampering), [`Error::KdfParams`].
    pub fn unlock_with_factor(
        &self,
        passphrase: &Passphrase,
        factor: &Factor,
    ) -> Result<UnlockedKey> {
        if !self.factor {
            return Err(Error::InvalidInput {
                field: "factor_unused",
            });
        }
        let header = self.header().encode();
        let secret = protect_v2::unprotect(passphrase, factor, &self.protected, &header)?;
        self.finish(secret)
    }

    /// DE: Formatversion: 2 mit Faktordatei, sonst 1. EN: Format version: 2 with factor file, else 1.
    #[must_use]
    pub fn format_version(&self) -> u32 {
        if self.factor {
            FORMAT_VERSION_V2
        } else {
            FORMAT_VERSION
        }
    }

    /// DE: Braucht das Entsperren die Faktordatei? EN: Does unlocking need the factor file?
    #[must_use]
    pub fn needs_factor(&self) -> bool {
        self.factor
    }
}
