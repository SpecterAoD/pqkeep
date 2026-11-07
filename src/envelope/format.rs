//! DE: JSON-Darstellung des Containers (serde, `deny_unknown_fields`) und die
//! eindeutige Binärkodierung des Headers für die AAD. Die AAD wird bewusst nicht
//! aus den JSON-Bytes gebildet, da JSON mehrdeutig formatierbar ist.
//!
//! EN: JSON representation of the container (serde, `deny_unknown_fields`) and
//! the unambiguous binary encoding of the header for the AAD. The AAD is
//! deliberately not built from the JSON bytes since JSON can be formatted ambiguously.

use serde::{Deserialize, Serialize};

use super::Metadata;

/// DE: Kennung des Dateityps. EN: File type identifier.
pub const MAGIC: &str = "PQKEEP-KEY";
/// DE: Aktuelle Formatversion. EN: Current format version.
pub const FORMAT_VERSION: u32 = 1;
/// DE: KDF-Bezeichner. EN: KDF identifier.
pub const KDF_ALGORITHM: &str = "argon2id";
/// DE: Argon2-Version 1.3. EN: Argon2 version 1.3.
pub const KDF_VERSION: u32 = 0x13;
/// DE: Verschlüsselungsverfahren. EN: Cipher identifier.
pub const CIPHER_ALGORITHM: &str = "aes-256-gcm";

/// DE: Oberste Ebene der Datei. EN: Top level of the file.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyFileJson {
    pub magic: String,
    pub format_version: u32,
    pub algorithm: String,
    pub key_id: String,
    pub created_utc: String,
    pub metadata: MetadataJson,
    pub public_key: String,
    pub kdf: KdfJson,
    pub cipher: CipherJson,
}

/// DE: Metadaten im JSON. EN: Metadata in JSON.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MetadataJson {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_type: Option<String>,
}

/// DE: KDF-Parameter im JSON. EN: KDF parameters in JSON.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KdfJson {
    pub algorithm: String,
    pub version: u32,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: String,
}

/// DE: Verschlüsselter Teil im JSON. EN: Encrypted part in JSON.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CipherJson {
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
}

impl From<&Metadata> for MetadataJson {
    fn from(m: &Metadata) -> Self {
        Self {
            name: m.name.clone(),
            organization: m.organization.clone(),
            company: m.company.clone(),
            department: m.department.clone(),
            account_type: m.account_type.clone(),
        }
    }
}

impl From<MetadataJson> for Metadata {
    fn from(m: MetadataJson) -> Self {
        Self {
            name: m.name,
            organization: m.organization,
            company: m.company,
            department: m.department,
            account_type: m.account_type,
        }
    }
}

/// DE: Header-Felder, die per AAD gebunden werden (Algorithmus, KDF und Salt bindet
/// `crypto::protect` selbst).
/// EN: Header fields bound via the AAD (algorithm, KDF and salt are bound by
/// `crypto::protect` itself).
pub(crate) struct Header<'a> {
    pub key_id: &'a [u8],
    pub created_utc: &'a str,
    pub metadata: &'a Metadata,
    pub public_key: &'a [u8],
}

impl Header<'_> {
    /// DE: Eindeutige Kodierung: Längenpräfixe, feste Reihenfolge, Präsenzbyte für
    /// optionale Felder. EN: Unambiguous encoding: length prefixes, fixed order,
    /// presence byte for optional fields.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.public_key.len());
        push(&mut out, MAGIC.as_bytes());
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        push(&mut out, self.key_id);
        push(&mut out, self.created_utc.as_bytes());
        for (_, value) in self.metadata.fields() {
            match value {
                Some(v) => {
                    out.push(1);
                    push(&mut out, v.as_bytes());
                }
                None => out.push(0),
            }
        }
        push(&mut out, self.public_key);
        out
    }
}

fn push(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u64).to_le_bytes());
    out.extend_from_slice(field);
}
