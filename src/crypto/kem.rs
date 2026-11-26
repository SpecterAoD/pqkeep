//! DE: ML-KEM (FIPS 203) über die RustCrypto-Crate `ml-kem`. Private Schlüssel
//! werden nur als 64-Byte-Seed gespeichert und bei Bedarf neu abgeleitet.
//!
//! EN: ML-KEM (FIPS 203) via the RustCrypto crate `ml-kem`. Private keys are
//! stored only as a 64-byte seed and re-derived when needed.

use ml_kem::kem::{FromSeed, Kem, KeyExport, TryKeyInit};
use ml_kem::{DecapsulateInto, EncapsulateWithHash};
use ml_kem::{MlKem512, MlKem768, MlKem1024};
use zeroize::Zeroize;

use super::seed_state;
use crate::crypto::{KemAlgorithm, SecretBytes, rng};
use crate::{Error, Result};

#[cfg(test)]
#[path = "kem_seed_tests.rs"]
mod tests;

#[path = "kem_encapsulation.rs"]
mod encapsulation;

#[cfg(test)]
#[path = "kem_decapsulation_tests.rs"]
mod decapsulation_tests;

/// DE: Länge des Seeds (d ‖ z) in Bytes. EN: Seed length (d ‖ z) in bytes.
pub const SEED_LEN: usize = 64;

/// DE: Schlüsselpaar; der private Teil liegt nur als Seed vor.
/// EN: Key pair; the private part exists only as a seed.
pub struct KemKeyPair {
    /// DE: Parametersatz. EN: Parameter set.
    pub algorithm: KemAlgorithm,
    /// DE: Öffentlicher Kapselungsschlüssel. EN: Public encapsulation key.
    pub public_key: Vec<u8>,
    seed: SecretBytes,
}

impl KemKeyPair {
    /// DE: Geheimer Seed (64 Byte). EN: Secret seed (64 bytes).
    #[must_use]
    pub fn seed(&self) -> &SecretBytes {
        &self.seed
    }
}

/// DE: Ergebnis der Kapselung: Chiffrat (öffentlich) und gemeinsames Geheimnis.
/// EN: Encapsulation result: ciphertext (public) and shared secret.
pub struct Encapsulated {
    /// DE: An den Besitzer des privaten Schlüssels zu senden. EN: Send to the key holder.
    pub ciphertext: Vec<u8>,
    /// DE: Gemeinsames Geheimnis (32 Byte). EN: Shared secret (32 bytes).
    pub shared_secret: SecretBytes,
}

/// DE: Erzeugt ein neues Schlüsselpaar aus einem OS-Zufalls-Seed.
/// EN: Generates a new key pair from an OS-random seed.
///
/// # Errors
/// DE/EN: [`Error::Rng`].
pub fn generate(algorithm: KemAlgorithm) -> Result<KemKeyPair> {
    let seed = rng::secret(SEED_LEN)?;
    from_seed(algorithm, seed.expose())
}

/// DE: Leitet das Schlüsselpaar deterministisch aus dem Seed ab.
/// EN: Derives the key pair deterministically from the seed.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] bei falscher Seed-Länge / on wrong seed length.
pub fn from_seed(algorithm: KemAlgorithm, seed: &[u8]) -> Result<KemKeyPair> {
    let seed = SecretBytes::from_slice(seed)?;
    let public_key = match algorithm {
        KemAlgorithm::MlKem512 => public_from_seed::<MlKem512>(seed.expose())?,
        KemAlgorithm::MlKem768 => public_from_seed::<MlKem768>(seed.expose())?,
        KemAlgorithm::MlKem1024 => public_from_seed::<MlKem1024>(seed.expose())?,
    };
    Ok(KemKeyPair {
        algorithm,
        public_key,
        seed,
    })
}

/// DE: Kapselt ein neues gemeinsames Geheimnis für den öffentlichen Schlüssel.
/// EN: Encapsulates a fresh shared secret to the public key.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] bei ungültigem Schlüssel / on invalid key;
/// [`Error::MemoryLock`] ohne volle Sperre / without complete locks;
/// [`Error::Rng`] ohne OS-Zufall / if OS randomness fails.
pub fn encapsulate(algorithm: KemAlgorithm, public_key: &[u8]) -> Result<Encapsulated> {
    match algorithm {
        KemAlgorithm::MlKem512 => encaps::<MlKem512>(public_key),
        KemAlgorithm::MlKem768 => encaps::<MlKem768>(public_key),
        KemAlgorithm::MlKem1024 => encaps::<MlKem1024>(public_key),
    }
}

/// DE: Entkapselt mit dem Seed. ML-KEM nutzt implizite Ablehnung: Ein manipuliertes
/// Chiffrat liefert ein anderes (zufällig wirkendes) Geheimnis statt eines Fehlers.
/// EN: Decapsulates using the seed. ML-KEM uses implicit rejection: a tampered
/// ciphertext yields a different (random-looking) secret instead of an error.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] bei falschen Längen / on wrong lengths.
pub fn decapsulate(algorithm: KemAlgorithm, seed: &[u8], ciphertext: &[u8]) -> Result<SecretBytes> {
    match algorithm {
        KemAlgorithm::MlKem512 => decaps::<MlKem512>(seed, ciphertext),
        KemAlgorithm::MlKem768 => decaps::<MlKem768>(seed, ciphertext),
        KemAlgorithm::MlKem1024 => decaps::<MlKem1024>(seed, ciphertext),
    }
}

fn parse_seed<K: FromSeed>(seed: &[u8]) -> Result<SecretBytes> {
    seed_state::parse(seed, ml_kem::kem::Seed::<K>::default().len())
}

fn public_from_seed<K: FromSeed>(seed: &[u8]) -> Result<Vec<u8>> {
    let mut seed = parse_seed::<K>(seed)?;
    let (_dk, ek) = K::from_seed(seed_state::view(&seed)?);
    seed.zeroize();
    Ok(ek.to_bytes().to_vec())
}

fn encaps<K: Kem>(public_key: &[u8]) -> Result<Encapsulated>
where
    K::EncapsulationKey: EncapsulateWithHash,
{
    let ek = K::EncapsulationKey::new_from_slice(public_key).map_err(|_| Error::InvalidInput {
        field: "public_key",
    })?;
    encapsulation::run(|entropy, workspace, hash| {
        ek.encapsulate_with_hash(entropy, workspace, hash).to_vec()
    })
}

fn decaps<K>(seed: &[u8], ciphertext: &[u8]) -> Result<SecretBytes>
where
    K: FromSeed,
    K::DecapsulationKey: DecapsulateInto,
{
    let mut out = SecretBytes::zeroed(32)?;
    let mut seed = parse_seed::<K>(seed)?;
    let (dk, _ek) = K::from_seed(seed_state::view(&seed)?);
    seed.zeroize();
    // DE: Nur geliehene Ausgabe in vorab gesperrten SecretBytes; kein SharedKey-Rückgabearray.
    // EN: Borrow output directly from prelocked SecretBytes; no returned SharedKey array.
    dk.decapsulate_slice_into(
        ciphertext,
        out.expose_mut().try_into().map_err(|_| Error::Crypto)?,
    )
    .map_err(|_| Error::InvalidInput {
        field: "ciphertext",
    })?;
    Ok(out)
}
