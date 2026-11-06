//! DE: Core-Kryptografie: ML-KEM (FIPS 203), ML-DSA (FIPS 204), Argon2id,
//! AES-256-GCM. Nur hier liegt Kryptologik; CLI und API nutzen diese Schnittstelle.
//!
//! EN: Core cryptography: ML-KEM (FIPS 203), ML-DSA (FIPS 204), Argon2id,
//! AES-256-GCM. Cryptographic logic lives only here; CLI and API use this interface.

pub mod aead;
pub mod dsa;
pub mod kdf;
pub mod kem;
pub mod protect;
pub mod rng;
mod secret;

pub use secret::SecretBytes;

use crate::{Error, Result};

/// DE: ML-KEM-Parametersatz (Standard: ML-KEM-768).
/// EN: ML-KEM parameter set (default: ML-KEM-768).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KemAlgorithm {
    /// ML-KEM-512 (NIST-Kategorie 1 / category 1)
    MlKem512,
    /// ML-KEM-768 (NIST-Kategorie 3 / category 3)
    #[default]
    MlKem768,
    /// ML-KEM-1024 (NIST-Kategorie 5 / category 5)
    MlKem1024,
}

/// DE: ML-DSA-Parametersatz (Standard: ML-DSA-65).
/// EN: ML-DSA parameter set (default: ML-DSA-65).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DsaAlgorithm {
    /// ML-DSA-44 (NIST-Kategorie 2 / category 2)
    MlDsa44,
    /// ML-DSA-65 (NIST-Kategorie 3 / category 3)
    #[default]
    MlDsa65,
    /// ML-DSA-87 (NIST-Kategorie 5 / category 5)
    MlDsa87,
}

/// DE: Algorithmus eines geschützten privaten Schlüssels.
/// EN: Algorithm of a protected private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// ML-KEM
    Kem(KemAlgorithm),
    /// ML-DSA
    Dsa(DsaAlgorithm),
    /// DE: Symmetrischer AES-256-Schlüssel. EN: Symmetric AES-256 key.
    Aes256,
}

/// DE: Alle Algorithmen in fester Reihenfolge (für Tests und Hilfe).
/// EN: All algorithms in fixed order (for tests and help).
pub const ALL_ALGORITHMS: [KeyAlgorithm; 7] = [
    KeyAlgorithm::Kem(KemAlgorithm::MlKem512),
    KeyAlgorithm::Kem(KemAlgorithm::MlKem768),
    KeyAlgorithm::Kem(KemAlgorithm::MlKem1024),
    KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa44),
    KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa65),
    KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87),
    KeyAlgorithm::Aes256,
];

impl KeyAlgorithm {
    /// DE: Stabiler Bezeichner (wird mitauthentifiziert, nie ändern).
    /// EN: Stable identifier (authenticated as AAD, never change).
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Kem(KemAlgorithm::MlKem512) => "ML-KEM-512",
            Self::Kem(KemAlgorithm::MlKem768) => "ML-KEM-768",
            Self::Kem(KemAlgorithm::MlKem1024) => "ML-KEM-1024",
            Self::Dsa(DsaAlgorithm::MlDsa44) => "ML-DSA-44",
            Self::Dsa(DsaAlgorithm::MlDsa65) => "ML-DSA-65",
            Self::Dsa(DsaAlgorithm::MlDsa87) => "ML-DSA-87",
            Self::Aes256 => "AES-256",
        }
    }

    /// DE: Gegenstück zu [`KeyAlgorithm::id`].
    /// EN: Inverse of [`KeyAlgorithm::id`].
    ///
    /// # Errors
    /// DE/EN: [`Error::Unsupported`] bei unbekanntem Bezeichner / for unknown identifiers.
    pub fn from_id(id: &str) -> Result<Self> {
        ALL_ALGORITHMS
            .into_iter()
            .find(|a| a.id() == id)
            .ok_or(Error::Unsupported)
    }

    /// DE: Länge des gespeicherten Geheimnisses (Seed bzw. Schlüssel) in Bytes.
    /// EN: Length of the stored secret (seed or key) in bytes.
    #[must_use]
    pub fn secret_len(self) -> usize {
        match self {
            Self::Kem(_) => kem::SEED_LEN,
            Self::Dsa(_) => dsa::SEED_LEN,
            Self::Aes256 => aead::KEY_LEN,
        }
    }
}
