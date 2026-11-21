//! DE: Nur Passphrase-Schutz erneuern; Identität und Format bleiben unverändert.
//! EN: Renew only passphrase protection; identity and format stay unchanged.

use super::KeyFile;
use crate::crypto::factor::Factor;
use crate::crypto::kdf::KdfParams;
use crate::crypto::{protect, protect_v2};
use crate::security::{Passphrase, StrongPassphrase};
use crate::{Error, Result};

impl KeyFile {
    /// DE: Authentifiziert den alten Schutz und verpackt dasselbe Geheimnis neu. Faktor und
    /// Format bleiben gleich. `None` erhält KDF-Parameter; `Some` darf keine Komponente senken.
    /// EN: Authenticate old protection and rewrap the same secret. Keep factor and format.
    /// `None` preserves KDF parameters; `Some` must not reduce any component.
    ///
    /// # Errors
    /// DE/EN: [`Error::Decrypt`], [`Error::InvalidInput`] (factor or `kdf_downgrade`),
    /// [`Error::KdfParams`], [`Error::Rng`], [`Error::Crypto`]. No I/O / keine Dateizugriffe.
    pub fn rekey(
        &self,
        old: &Passphrase,
        new: &StrongPassphrase,
        factor: Option<&Factor>,
        params: Option<&KdfParams>,
    ) -> Result<Self> {
        let params = params.copied().unwrap_or(self.kdf_params());
        validate_params(&self.kdf_params(), &params)?;
        let opened = match factor {
            Some(factor) => self.unlock_with_factor(old, factor)?,
            None => self.unlock(old)?,
        };
        let header = self.header().encode();
        let secret = opened.secret().expose();
        let protected = match factor {
            Some(factor) => {
                protect_v2::protect(new, factor, self.algorithm, secret, &params, &header)?
            }
            None => protect::protect(new, self.algorithm, secret, &params, &header)?,
        };
        // DE: Nicht create/build: diese erzeugen Zeit und AES-ID neu.
        // EN: Do not use create/build: they generate a new timestamp and AES ID.
        let mut rewrapped = self.clone();
        rewrapped.protected = protected;
        Ok(rewrapped)
    }
}

fn validate_params(old: &KdfParams, new: &KdfParams) -> Result<()> {
    new.validate()?;
    if new.memory_kib < old.memory_kib
        || new.iterations < old.iterations
        || new.parallelism < old.parallelism
    {
        return Err(Error::InvalidInput {
            field: "kdf_downgrade",
        });
    }
    Ok(())
}
