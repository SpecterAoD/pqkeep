//! DE: Abgesetzte Signaturen (Spezifikation Abschnitt 9, U1) mit ML-DSA-87 über den
//! SHA3-512 einer Datei. Die Signatur beweist, dass die Datei unverändert ist und vom
//! Inhaber des privaten Schlüssels signiert wurde. Wer das ist, muss über den
//! Fingerabdruck (Schlüssel-ID) auf einem zweiten Weg bestätigt werden. Keine
//! qualifizierte elektronische Signatur nach eIDAS. Format: `docs/SIGNATURE_FORMAT.md`.
//!
//! EN: Detached signatures (specification section 9, U1) with ML-DSA-87 over the
//! SHA3-512 of a file. The signature proves that the file is unchanged and was signed
//! by the holder of the private key. Who that is must be confirmed via the fingerprint
//! (key ID) through a second channel. Not a qualified electronic signature under
//! eIDAS. Format: `docs/SIGNATURE_FORMAT.md`.

mod format;
mod hash;

use std::fs::File;
use std::io::Read;
use std::path::Path;

pub use format::{
    HASH_ALGORITHM, MAX_SIG_FILE_BYTES, SIG_ALGORITHM, SIG_CONTEXT, SIG_FORMAT_VERSION, SIG_MAGIC,
    SIGNATURE_LEN, SignatureFile,
};
pub use hash::{DIGEST_LEN, FileDigest, digest_reader};

use crate::crypto::{DsaAlgorithm, dsa};
use crate::envelope::{PublicKeyFile, UnlockedKey, fingerprint, read_limited, time};
use crate::{Error, Result};

/// DE: Empfohlene Dateiendung (`<datei>.pqsig`). EN: Recommended file extension.
pub const EXTENSION: &str = "pqsig";

const DSA: DsaAlgorithm = DsaAlgorithm::MlDsa87;

/// DE: Ergebnis einer erfolgreichen Prüfung. EN: Result of a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// DE: Schlüssel-ID des Signierers. EN: Signer's key ID.
    pub key_id: Vec<u8>,
    /// DE: Zeitpunkt laut Signierer (nicht vertrauenswürdig). EN: Time claimed by the signer (not trusted).
    pub created_utc: String,
    /// DE: Größe der geprüften Datei. EN: Size of the verified file.
    pub size: u64,
}

/// DE: Signiert den Inhalt von `reader` mit einem entsperrten ML-DSA-87-Schlüssel.
/// EN: Signs the content of `reader` with an unlocked ML-DSA-87 key.
///
/// # Errors
/// DE/EN: [`Error::Unsupported`] (anderer Algorithmus / other algorithm), [`Error::Io`],
/// [`Error::Crypto`].
pub fn sign_reader<R: Read>(key: &UnlockedKey, reader: R) -> Result<SignatureFile> {
    if key.algorithm != SIG_ALGORITHM {
        return Err(Error::Unsupported);
    }
    let mut sig = SignatureFile {
        key_id: fingerprint(&key.public_key),
        digest: digest_reader(reader)?,
        created_utc: time::now_rfc3339(),
        signature: Vec::new(),
    };
    let message = sig.message();
    let context = SIG_CONTEXT.as_bytes();
    sig.signature = dsa::sign(DSA, key.secret().expose(), &message, context)?;
    // DE: Gegenprobe gegen Rechen-/Speicherfehler. EN: Cross-check against compute/memory faults.
    if !dsa::verify(DSA, &key.public_key, &message, context, &sig.signature) {
        return Err(Error::Crypto);
    }
    Ok(sig)
}

/// DE: Signiert die Datei unter `path` (gestreamt). EN: Signs the file at `path` (streamed).
///
/// # Errors
/// DE/EN: wie [`sign_reader`] / as [`sign_reader`].
pub fn sign_file(key: &UnlockedKey, path: &Path) -> Result<SignatureFile> {
    sign_reader(key, File::open(path)?)
}

/// DE: Prüft `sig` gegen den Inhalt von `reader` und den öffentlichen Schlüssel.
/// EN: Verifies `sig` against the content of `reader` and the public key.
///
/// # Errors
/// DE/EN: [`Error::InvalidSignature`] (Datei verändert, anderer Schlüssel, Signatur
/// manipuliert / file changed, other key, signature tampered), [`Error::Unsupported`]
/// (Schlüssel ist kein ML-DSA-87 / key is not ML-DSA-87), [`Error::Io`].
pub fn verify_reader<R: Read>(
    public: &PublicKeyFile,
    sig: &SignatureFile,
    reader: R,
) -> Result<Verified> {
    if public.algorithm() != SIG_ALGORITHM {
        return Err(Error::Unsupported);
    }
    if public.key_id() != sig.key_id() {
        return Err(Error::InvalidSignature);
    }
    if digest_reader(reader)? != sig.digest {
        return Err(Error::InvalidSignature);
    }
    let context = SIG_CONTEXT.as_bytes();
    if !dsa::verify(
        DSA,
        public.public_key(),
        &sig.message(),
        context,
        &sig.signature,
    ) {
        return Err(Error::InvalidSignature);
    }
    Ok(Verified {
        key_id: sig.key_id.clone(),
        created_utc: sig.created_utc.clone(),
        size: sig.digest.size,
    })
}

/// DE: Prüft die Datei unter `path` (gestreamt). EN: Verifies the file at `path` (streamed).
///
/// # Errors
/// DE/EN: wie [`verify_reader`] / as [`verify_reader`].
pub fn verify_file(public: &PublicKeyFile, sig: &SignatureFile, path: &Path) -> Result<Verified> {
    verify_reader(public, sig, File::open(path)?)
}

/// DE: Liest eine Signaturdatei (höchstens 64 KiB werden gelesen, gültig sind 16 KiB).
/// EN: Reads a signature file (at most 64 KiB are read, 16 KiB are valid).
///
/// # Errors
/// DE/EN: [`Error::Io`], [`Error::InvalidInput`], [`Error::Unsupported`].
pub fn load(path: &Path) -> Result<SignatureFile> {
    SignatureFile::from_json(&read_limited(path)?)
}
