//! DE: Schlüsselableitung mit Argon2id (RFC 9106). Die Parameter m, t, p und der
//! Salt werden später im Container gespeichert, damit die Entschlüsselung auf
//! anderer Hardware funktioniert. Grenzen schützen vor schwachen Parametern und
//! vor DoS über manipulierte Header.
//!
//! EN: Key derivation with Argon2id (RFC 9106). The parameters m, t, p and the
//! salt are stored in the container later so that decryption works on other
//! hardware. Bounds protect against weak parameters and against DoS via
//! tampered headers.

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};

use crate::crypto::SecretBytes;
use crate::{Error, Result};

#[cfg(test)]
#[path = "kdf_tests.rs"]
mod kdf_tests;

/// DE: Länge des abgeleiteten Schlüssels (AES-256). EN: Derived key length (AES-256).
pub const OUTPUT_LEN: usize = 32;
/// DE: Länge eines neu erzeugten Salts. EN: Length of a newly generated salt.
pub const SALT_LEN: usize = 32;
/// DE: Kleinste zulässige Salt-Länge. EN: Smallest accepted salt length.
pub const MIN_SALT_LEN: usize = 16;
/// DE: Größte zulässige Salt-Länge. EN: Largest accepted salt length.
pub const MAX_SALT_LEN: usize = 64;

/// DE: Untergrenze Speicher: 64 MiB. EN: Memory lower bound: 64 MiB.
pub const MIN_MEMORY_KIB: u32 = 64 * 1024;
/// DE: Obergrenze Speicher: 1 GiB. EN: Memory upper bound: 1 GiB.
pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;
/// DE: Untergrenze Iterationen. EN: Iterations lower bound.
pub const MIN_ITERATIONS: u32 = 3;
/// DE: Obergrenze Iterationen. EN: Iterations upper bound.
pub const MAX_ITERATIONS: u32 = 10;
/// DE: Obergrenze Parallelität beim Lesen. EN: Parallelism upper bound when reading.
pub const MAX_PARALLELISM: u32 = 16;
/// DE: Obergrenze der automatisch gewählten Parallelität. EN: Cap for automatic parallelism.
pub const AUTO_PARALLELISM_CAP: u32 = 8;

/// DE: Argon2id-Parameter. EN: Argon2id parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// DE: Speicher in KiB (m). EN: Memory in KiB (m).
    pub memory_kib: u32,
    /// DE: Iterationen (t). EN: Iterations (t).
    pub iterations: u32,
    /// DE: Parallelität (p). EN: Parallelism (p).
    pub parallelism: u32,
}

/// DE: Vordefinierte Profile. EN: Predefined profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KdfProfile {
    /// DE: 256 MiB, t = 3. EN: 256 MiB, t = 3.
    #[default]
    Standard,
    /// DE: 1 GiB, t = 4. EN: 1 GiB, t = 4.
    Hardened,
}

impl KdfProfile {
    /// DE: Parameter des Profils mit p = verfügbare Kerne (max. 8).
    /// EN: Profile parameters with p = available cores (max. 8).
    #[must_use]
    pub fn params(self) -> KdfParams {
        let (memory_kib, iterations) = match self {
            Self::Standard => (256 * 1024, 3),
            Self::Hardened => (1024 * 1024, 4),
        };
        KdfParams {
            memory_kib,
            iterations,
            parallelism: auto_parallelism(),
        }
    }
}

/// DE: Anzahl verfügbarer Kerne, begrenzt auf 1..=8.
/// EN: Number of available cores, clamped to 1..=8.
#[must_use]
pub fn auto_parallelism() -> u32 {
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    u32::try_from(cores)
        .unwrap_or(AUTO_PARALLELISM_CAP)
        .clamp(1, AUTO_PARALLELISM_CAP)
}

impl KdfParams {
    /// DE: Prüft alle Grenzen. Zu schwache Parameter werden auch beim Lesen
    /// abgelehnt (Downgrade-Schutz), zu hohe verhindern DoS.
    /// EN: Checks all bounds. Too weak parameters are rejected on read as well
    /// (downgrade protection); too high ones prevent DoS.
    ///
    /// # Errors
    /// DE/EN: [`Error::KdfParams`].
    pub fn validate(&self) -> Result<()> {
        let ok = (MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib)
            && (MIN_ITERATIONS..=MAX_ITERATIONS).contains(&self.iterations)
            && (1..=MAX_PARALLELISM).contains(&self.parallelism);
        if ok { Ok(()) } else { Err(Error::KdfParams) }
    }
}

/// DE: Leitet einen 32-Byte-Schlüssel aus Passphrase und Salt ab.
/// EN: Derives a 32-byte key from passphrase and salt.
///
/// # Errors
/// DE/EN: [`Error::KdfParams`], [`Error::InvalidInput`] (Salt/Passphrase), [`Error::Crypto`].
pub fn derive(passphrase: &[u8], salt: &[u8], params: &KdfParams) -> Result<SecretBytes> {
    params.validate()?;
    if !(MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt.len()) {
        return Err(Error::InvalidInput { field: "salt" });
    }
    if passphrase.is_empty() {
        return Err(Error::InvalidInput {
            field: "passphrase",
        });
    }
    let mut key = SecretBytes::new(vec![0u8; OUTPUT_LEN]);
    argon2id(passphrase, salt, params, &[], &[], key.expose_mut())?;
    Ok(key)
}

/// DE: Argon2id-Kern **ohne** Grenzprüfung; nur über [`derive`] aufrufen.
/// `secret` (K) und `ad` (X) nach RFC 9106, leer = nicht verwendet.
/// Getrennt, damit der offizielle RFC-9106-Testvektor (32 KiB) intern prüfbar ist.
/// EN: Argon2id core **without** bounds checks; call only via [`derive`].
/// `secret` (K) and `ad` (X) per RFC 9106, empty = unused.
/// Separate so that the official RFC 9106 test vector (32 KiB) can be checked internally.
pub(crate) fn argon2id(
    passphrase: &[u8],
    salt: &[u8],
    params: &KdfParams,
    secret: &[u8],
    ad: &[u8],
    out: &mut [u8],
) -> Result<()> {
    let mut builder = ParamsBuilder::new();
    builder
        .m_cost(params.memory_kib)
        .t_cost(params.iterations)
        .p_cost(params.parallelism)
        .output_len(out.len());
    if !ad.is_empty() {
        builder.data(AssociatedData::new(ad).map_err(|_| Error::KdfParams)?);
    }
    let argon_params = builder.build().map_err(|_| Error::KdfParams)?;
    let argon = if secret.is_empty() {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
    } else {
        Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, argon_params)
            .map_err(|_| Error::KdfParams)?
    };
    argon
        .hash_password_into(passphrase, salt, out)
        .map_err(|_| Error::Crypto)
}
