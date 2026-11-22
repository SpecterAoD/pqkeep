//! DE: Absenderblock des Formats v3 (`docs/V3_SIGNED.md`, #44): öffentlicher ML-DSA-87-Schlüssel
//! des Absenders und Schlüsselbindung (`commit`) im Header, Signatur am Dateiende.
//!
//! ```text
//! Absenderblock = U8(algorithmus = 1) ‖ öffentlicher_schlüssel[2592] ‖ commit[32]
//! commit        = SHA3-256("PQKeep/file/v3\0commit\0" ‖ Dateischlüssel)
//! Nachricht     = "PQKeep/file/v3\0sig\0" ‖ SHA3-512(H) ‖ SHA3-512(C) ‖ U64(Länge C)
//! ```
//!
//! Dieses Modul kodiert, prüft und rechnet nur; Lesen und Schreiben der Datei liegt in
//! `signed_io`.
//!
//! EN: Sender block of format v3 (`docs/V3_SIGNED.md`, #44): the sender's public ML-DSA-87 key and
//! the key commitment in the header, the signature at the end of the file (layout above). This
//! module only encodes, validates and computes; reading and writing the file is in `signed_io`.

use std::io::Read;

use sha3::{Digest, Sha3_256, Sha3_512};

use super::format::{Reader, bad};
use crate::crypto::DsaAlgorithm;
use crate::envelope::fingerprint;
use crate::{Error, Result};

/// DE: Kennung von ML-DSA-87 im Absenderblock. EN: ID of ML-DSA-87 in the sender block.
pub const SIGNER_ML_DSA_87: u8 = 1;
/// DE: Länge des öffentlichen ML-DSA-87-Schlüssels. EN: Length of the public ML-DSA-87 key.
pub const SIGNER_KEY_LEN: usize = 2592;
/// DE: Länge der Schlüsselbindung. EN: Length of the key commitment.
pub const COMMIT_LEN: usize = 32;
/// DE: Länge des Absenderblocks im Header. EN: Length of the sender block in the header.
pub const SIGNER_BLOCK_LEN: usize = 1 + SIGNER_KEY_LEN + COMMIT_LEN;
/// DE: Länge der Signatur am Dateiende. EN: Length of the signature at the end of the file.
pub const FILE_SIGNATURE_LEN: usize = 4627;
/// DE: FIPS-204-Kontext der Signatur. EN: FIPS 204 context of the signature.
pub const FILE_SIG_CONTEXT: &[u8] = b"PQKeep/pqkf-sig/v1";
/// DE: Einziger zulässiger Algorithmus. EN: Only permitted algorithm.
pub const SIGNER_DSA: DsaAlgorithm = DsaAlgorithm::MlDsa87;

const COMMIT_TAG: &[u8] = b"PQKeep/file/v3\0commit\0";
const MESSAGE_TAG: &[u8] = b"PQKeep/file/v3\0sig\0";

/// DE: Absender im Header (öffentlich, ungeprüft bis zur Signaturprüfung).
/// EN: Sender in the header (public, unverified until the signature is checked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    /// DE: Öffentlicher ML-DSA-87-Schlüssel. EN: Public ML-DSA-87 key.
    pub public_key: Vec<u8>,
    /// DE: Schlüsselbindung an den Dateischlüssel. EN: Commitment to the file key.
    pub commit: [u8; COMMIT_LEN],
}

impl Signer {
    /// DE: Schlüssel-ID = SHA3-256 des öffentlichen Schlüssels (wie `*.pub.json`, `.pqsig`).
    /// EN: Key ID = SHA3-256 of the public key (as for `*.pub.json`, `.pqsig`).
    #[must_use]
    pub fn key_id(&self) -> Vec<u8> {
        fingerprint(&self.public_key)
    }

    /// DE: Kodiert den Block. EN: Encodes the block.
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] (Feld `header`) bei falscher Schlüssellänge.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.public_key.len() != SIGNER_KEY_LEN {
            return Err(bad());
        }
        let mut out = Vec::with_capacity(SIGNER_BLOCK_LEN);
        out.push(SIGNER_ML_DSA_87);
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.commit);
        Ok(out)
    }

    /// DE: Liest den Block streng. EN: Reads the block strictly.
    ///
    /// # Errors
    /// DE/EN: [`Error::Unsupported`] (anderer Algorithmus / other algorithm),
    /// [`Error::InvalidInput`] (Feld `header`).
    pub(super) fn read<R: Read>(r: &mut Reader<'_, R>) -> Result<Self> {
        if r.byte()? != SIGNER_ML_DSA_87 {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            public_key: r.bytes(SIGNER_KEY_LEN)?,
            commit: r.array()?,
        })
    }
}

/// DE: Schlüsselbindung für `file_key`. EN: Key commitment for `file_key`.
#[must_use]
pub fn commit(file_key: &[u8]) -> [u8; COMMIT_LEN] {
    let mut hasher = Sha3_256::new();
    hasher.update(COMMIT_TAG);
    hasher.update(file_key);
    hasher.finalize().into()
}

/// DE: Prüft die Schlüsselbindung ohne frühen Abbruch; Abweichung = [`Error::Decrypt`].
/// EN: Checks the key commitment without early exit; mismatch = [`Error::Decrypt`].
///
/// # Errors
/// DE/EN: [`Error::Decrypt`].
pub fn check_commit(signer: &Signer, file_key: &[u8]) -> Result<()> {
    let expected = commit(file_key);
    let diff = expected
        .iter()
        .zip(signer.commit.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff == 0 {
        Ok(())
    } else {
        Err(Error::Decrypt)
    }
}

/// DE: Signierte Nachricht aus Header-Bytes, Hash und Länge des Chiffrats.
/// EN: Signed message from the header bytes, hash and length of the ciphertext.
#[must_use]
pub fn message(header: &[u8], body_hash: &[u8], body_len: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(MESSAGE_TAG.len() + 64 + 64 + 8);
    out.extend_from_slice(MESSAGE_TAG);
    out.extend_from_slice(&Sha3_512::digest(header));
    out.extend_from_slice(body_hash);
    out.extend_from_slice(&body_len.to_le_bytes());
    out
}

#[cfg(test)]
#[path = "signer_v3_tests.rs"]
mod signer_v3_tests;
