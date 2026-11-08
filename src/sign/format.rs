//! DE: Signaturdatei `.pqsig` (JSON, `deny_unknown_fields`) und die eindeutige
//! Binärkodierung der signierten Nachricht. Signiert werden bewusst nicht die
//! JSON-Bytes, da JSON mehrdeutig formatierbar ist. Format-Doku: `docs/SIGNATURE_FORMAT.md`.
//!
//! EN: Signature file `.pqsig` (JSON, `deny_unknown_fields`) and the unambiguous
//! binary encoding of the signed message. The JSON bytes are deliberately not
//! signed since JSON can be formatted ambiguously. Format docs: `docs/SIGNATURE_FORMAT.md`.

use serde::{Deserialize, Serialize};

use super::hash::{DIGEST_LEN, FileDigest};
use crate::crypto::{DsaAlgorithm, KeyAlgorithm};
use crate::envelope::{KEY_ID_LEN, b64_decode, b64_encode, hex_decode, hex_encode, time};
use crate::{Error, Result};

/// DE: Kennung des Dateityps. EN: File type identifier.
pub const SIG_MAGIC: &str = "PQKEEP-SIG";
/// DE: Aktuelle Formatversion. EN: Current format version.
pub const SIG_FORMAT_VERSION: u32 = 1;
/// DE: Einziger zugelassener Algorithmus. EN: Only permitted algorithm.
pub const SIG_ALGORITHM: KeyAlgorithm = KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87);
/// DE: Hash-Verfahren. EN: Hash algorithm.
pub const HASH_ALGORITHM: &str = "SHA3-512";
/// DE: FIPS-204-Kontext-String (Domänentrennung). EN: FIPS 204 context string (domain separation).
pub const SIG_CONTEXT: &str = "PQKeep/sig/v1";
/// DE: Länge einer ML-DSA-87-Signatur (FIPS 204). EN: Length of an ML-DSA-87 signature (FIPS 204).
pub const SIGNATURE_LEN: usize = 4627;
/// DE: Höchstgröße einer Signaturdatei. EN: Maximum size of a signature file.
pub const MAX_SIG_FILE_BYTES: usize = 16 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureJson {
    magic: String,
    format_version: u32,
    algorithm: String,
    key_id: String,
    hash_algorithm: String,
    file_sha3_512: String,
    file_size: u64,
    created_utc: String,
    context: String,
    signature: String,
}

/// DE: Inhalt einer Signaturdatei. Der Zeitstempel ist eine Angabe des Signierers,
/// kein vertrauenswürdiger Zeitnachweis.
/// EN: Content of a signature file. The timestamp is a claim by the signer, not a
/// trusted proof of time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureFile {
    pub(super) key_id: Vec<u8>,
    pub(super) digest: FileDigest,
    pub(super) created_utc: String,
    pub(super) signature: Vec<u8>,
}

impl SignatureFile {
    /// DE: Schlüssel-ID des Signierers (SHA3-256 seines öffentlichen Schlüssels).
    /// EN: Signer's key ID (SHA3-256 of their public key).
    #[must_use]
    pub fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    /// DE: Schlüssel-ID als Hex. EN: Key ID as hex.
    #[must_use]
    pub fn key_id_hex(&self) -> String {
        hex_encode(&self.key_id)
    }

    /// DE: Hashwert und Größe der signierten Datei. EN: Digest and size of the signed file.
    #[must_use]
    pub fn digest(&self) -> &FileDigest {
        &self.digest
    }

    /// DE: Zeitpunkt laut Signierer (RFC 3339, UTC). EN: Time claimed by the signer (RFC 3339, UTC).
    #[must_use]
    pub fn created_utc(&self) -> &str {
        &self.created_utc
    }

    /// DE: Eindeutige Kodierung der signierten Felder: Längenpräfixe, feste Reihenfolge.
    /// EN: Unambiguous encoding of the signed fields: length prefixes, fixed order.
    pub(super) fn message(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        push(&mut out, SIG_MAGIC.as_bytes());
        out.extend_from_slice(&SIG_FORMAT_VERSION.to_le_bytes());
        push(&mut out, SIG_ALGORITHM.id().as_bytes());
        push(&mut out, &self.key_id);
        push(&mut out, HASH_ALGORITHM.as_bytes());
        push(&mut out, &self.digest.sha3_512);
        out.extend_from_slice(&self.digest.size.to_le_bytes());
        push(&mut out, self.created_utc.as_bytes());
        out
    }

    /// DE: JSON-Darstellung. EN: JSON representation.
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] (praktisch nie / practically never).
    pub fn to_json(&self) -> Result<String> {
        let json = SignatureJson {
            magic: SIG_MAGIC.to_owned(),
            format_version: SIG_FORMAT_VERSION,
            algorithm: SIG_ALGORITHM.id().to_owned(),
            key_id: self.key_id_hex(),
            hash_algorithm: HASH_ALGORITHM.to_owned(),
            file_sha3_512: hex_encode(&self.digest.sha3_512),
            file_size: self.digest.size,
            created_utc: self.created_utc.clone(),
            context: SIG_CONTEXT.to_owned(),
            signature: b64_encode(&self.signature),
        };
        let mut text = serde_json::to_string_pretty(&json)
            .map_err(|_| Error::InvalidInput { field: "json" })?;
        text.push('\n');
        Ok(text)
    }

    /// DE: Liest und prüft streng (Größe, Magic, Version, Algorithmus, Längen). Die
    /// Signatur selbst prüft erst [`super::verify_reader`].
    /// EN: Parses and validates strictly (size, magic, version, algorithm, lengths). The
    /// signature itself is only checked by [`super::verify_reader`].
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`], [`Error::Unsupported`].
    pub fn from_json(text: &str) -> Result<Self> {
        if text.len() > MAX_SIG_FILE_BYTES {
            return Err(Error::InvalidInput { field: "file" });
        }
        let json: SignatureJson =
            serde_json::from_str(text).map_err(|_| Error::InvalidInput { field: "json" })?;
        check_fixed(&json)?;
        let hash = hex_decode(&json.file_sha3_512, DIGEST_LEN, "file_sha3_512")?;
        let mut sha3_512 = [0u8; DIGEST_LEN];
        sha3_512.copy_from_slice(&hash);
        time::parse_rfc3339(&json.created_utc)?;
        let signature = b64_decode(&json.signature, SIGNATURE_LEN, "signature")?;
        if signature.len() != SIGNATURE_LEN {
            return Err(Error::InvalidInput { field: "signature" });
        }
        Ok(Self {
            key_id: hex_decode(&json.key_id, KEY_ID_LEN, "key_id")?,
            digest: FileDigest {
                sha3_512,
                size: json.file_size,
            },
            created_utc: json.created_utc,
            signature,
        })
    }
}

/// DE: Felder mit festem Wert. Fremde Version/Verfahren → `Unsupported` (kein Downgrade).
/// EN: Fields with a fixed value. Other version/scheme → `Unsupported` (no downgrade).
fn check_fixed(json: &SignatureJson) -> Result<()> {
    if json.magic != SIG_MAGIC {
        return Err(Error::InvalidInput { field: "magic" });
    }
    let supported = json.format_version == SIG_FORMAT_VERSION
        && json.algorithm == SIG_ALGORITHM.id()
        && json.hash_algorithm == HASH_ALGORITHM;
    if !supported {
        return Err(Error::Unsupported);
    }
    if json.context != SIG_CONTEXT {
        return Err(Error::InvalidInput { field: "context" });
    }
    Ok(())
}

fn push(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u64).to_le_bytes());
    out.extend_from_slice(field);
}

#[cfg(test)]
#[path = "format_tests.rs"]
mod format_tests;
