//! DE: ML-DSA (FIPS 204) über die RustCrypto-Crate `ml-dsa`. Private Schlüssel
//! werden nur als 32-Byte-Seed (ξ) gespeichert. Signaturen sind „hedged“
//! (randomisiert mit OS-Zufall), wie von FIPS 204 empfohlen.
//!
//! EN: ML-DSA (FIPS 204) via the RustCrypto crate `ml-dsa`. Private keys are
//! stored only as a 32-byte seed (ξ). Signatures are "hedged" (randomised with
//! OS randomness), as recommended by FIPS 204.

use getrandom::SysRng;
use ml_dsa::signature::Keypair;
use ml_dsa::{EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signature};
use ml_dsa::{SigningKey, VerifyingKey};
use zeroize::Zeroize;

use crate::crypto::{DsaAlgorithm, SecretBytes, rng};
use crate::{Error, Result};

/// DE: Länge des Seeds ξ in Bytes. EN: Length of the seed ξ in bytes.
pub const SEED_LEN: usize = 32;

/// DE: Maximale Länge des Kontext-Strings (FIPS 204). EN: Max context length (FIPS 204).
pub const MAX_CONTEXT_LEN: usize = 255;

/// DE: Schlüsselpaar; der private Teil liegt nur als Seed vor.
/// EN: Key pair; the private part exists only as a seed.
pub struct DsaKeyPair {
    /// DE: Parametersatz. EN: Parameter set.
    pub algorithm: DsaAlgorithm,
    /// DE: Öffentlicher Verifikationsschlüssel. EN: Public verifying key.
    pub public_key: Vec<u8>,
    seed: SecretBytes,
}

impl DsaKeyPair {
    /// DE: Geheimer Seed (32 Byte). EN: Secret seed (32 bytes).
    #[must_use]
    pub fn seed(&self) -> &SecretBytes {
        &self.seed
    }
}

/// DE: Erzeugt ein neues Schlüsselpaar aus einem OS-Zufalls-Seed.
/// EN: Generates a new key pair from an OS-random seed.
///
/// # Errors
/// DE/EN: [`Error::Rng`].
pub fn generate(algorithm: DsaAlgorithm) -> Result<DsaKeyPair> {
    let seed = rng::secret(SEED_LEN)?;
    from_seed(algorithm, seed.expose())
}

/// DE: Leitet das Schlüsselpaar deterministisch aus dem Seed ab.
/// EN: Derives the key pair deterministically from the seed.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] bei falscher Seed-Länge / on wrong seed length.
pub fn from_seed(algorithm: DsaAlgorithm, seed: &[u8]) -> Result<DsaKeyPair> {
    let public_key = match algorithm {
        DsaAlgorithm::MlDsa44 => public_from_seed::<MlDsa44>(seed)?,
        DsaAlgorithm::MlDsa65 => public_from_seed::<MlDsa65>(seed)?,
        DsaAlgorithm::MlDsa87 => public_from_seed::<MlDsa87>(seed)?,
    };
    Ok(DsaKeyPair {
        algorithm,
        public_key,
        seed: SecretBytes::from_slice(seed),
    })
}

/// DE: Signiert `message` mit Kontext `context` (max. 255 Byte, darf leer sein).
/// EN: Signs `message` with context `context` (max. 255 bytes, may be empty).
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] (Seed/Kontext), [`Error::Crypto`].
pub fn sign(
    algorithm: DsaAlgorithm,
    seed: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<Vec<u8>> {
    if context.len() > MAX_CONTEXT_LEN {
        return Err(Error::InvalidInput { field: "context" });
    }
    match algorithm {
        DsaAlgorithm::MlDsa44 => sign_with::<MlDsa44>(seed, message, context),
        DsaAlgorithm::MlDsa65 => sign_with::<MlDsa65>(seed, message, context),
        DsaAlgorithm::MlDsa87 => sign_with::<MlDsa87>(seed, message, context),
    }
}

/// DE: Prüft eine Signatur. Ungültige Eingaben ergeben `false`, nie eine Panik.
/// EN: Verifies a signature. Invalid inputs yield `false`, never a panic.
#[must_use]
pub fn verify(
    algorithm: DsaAlgorithm,
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> bool {
    if context.len() > MAX_CONTEXT_LEN {
        return false;
    }
    match algorithm {
        DsaAlgorithm::MlDsa44 => verify_with::<MlDsa44>(public_key, message, context, signature),
        DsaAlgorithm::MlDsa65 => verify_with::<MlDsa65>(public_key, message, context, signature),
        DsaAlgorithm::MlDsa87 => verify_with::<MlDsa87>(public_key, message, context, signature),
    }
}

fn signing_key<P: MlDsaParams>(seed: &[u8]) -> Result<SigningKey<P>> {
    let mut xi = ml_dsa::Seed::try_from(seed).map_err(|_| Error::InvalidInput { field: "seed" })?;
    let sk = SigningKey::<P>::from_seed(&xi);
    xi.zeroize();
    Ok(sk)
}

fn public_from_seed<P: MlDsaParams>(seed: &[u8]) -> Result<Vec<u8>> {
    let sk = signing_key::<P>(seed)?;
    Ok(sk.verifying_key().encode().to_vec())
}

fn sign_with<P: MlDsaParams>(seed: &[u8], message: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    let sk = signing_key::<P>(seed)?;
    let sig = sk
        .expanded_key()
        .sign_randomized(message, context, &mut SysRng)
        .map_err(|_| Error::Crypto)?;
    Ok(sig.encode().to_vec())
}

fn verify_with<P: MlDsaParams>(pk: &[u8], message: &[u8], context: &[u8], sig: &[u8]) -> bool {
    let Ok(enc) = EncodedVerifyingKey::<P>::try_from(pk) else {
        return false;
    };
    let vk = VerifyingKey::<P>::decode(&enc);
    let Ok(sig) = Signature::<P>::try_from(sig) else {
        return false;
    };
    vk.verify_with_context(message, context, &sig)
}
