//! DE: Datei nur mit dem öffentlichen Schlüssel (`*.pub.json`) zum Weitergeben, z. B.
//! damit andere Dateien für einen verschlüsseln können. Enthält nichts Geheimes.
//! **Nicht signiert:** Ob der Schlüssel wirklich von der genannten Person stammt,
//! muss über den Fingerabdruck (Schlüssel-ID) auf einem zweiten Weg bestätigt werden.
//!
//! EN: File with the public key only (`*.pub.json`) for sharing, e.g. so that
//! others can encrypt files for you. Contains nothing secret. **Not signed:**
//! whether the key really belongs to the named person must be confirmed via the
//! fingerprint (key ID) through a second channel.

use serde::{Deserialize, Serialize};

use super::encoding::{b64_decode, b64_encode, hex_decode, hex_encode};
use super::format::{FORMAT_VERSION, MetadataJson};
use super::keyfile::{KEY_ID_LEN, KeyFile, MAX_FILE_BYTES, key_id_matches};
use super::{Metadata, time};
use crate::crypto::KeyAlgorithm;
use crate::{Error, Result};

/// DE: Kennung der öffentlichen Schlüsseldatei. EN: Public key file magic.
pub const PUBLIC_MAGIC: &str = "PQKEEP-PUB";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicJson {
    magic: String,
    format_version: u32,
    algorithm: String,
    key_id: String,
    created_utc: String,
    metadata: MetadataJson,
    public_key: String,
}

/// DE: Öffentlicher Schlüssel mit Metadaten. EN: Public key with metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyFile {
    algorithm: KeyAlgorithm,
    key_id: Vec<u8>,
    created_utc: String,
    metadata: Metadata,
    public_key: Vec<u8>,
}

impl KeyFile {
    /// DE: Öffentlicher Teil (nur ML-KEM/ML-DSA; AES hat keinen).
    /// EN: Public part (ML-KEM/ML-DSA only; AES has none).
    ///
    /// # Errors
    /// DE/EN: [`Error::Unsupported`] für AES / for AES.
    pub fn public_part(&self) -> Result<PublicKeyFile> {
        if self.algorithm() == KeyAlgorithm::Aes256 {
            return Err(Error::Unsupported);
        }
        Ok(PublicKeyFile {
            algorithm: self.algorithm(),
            key_id: self.key_id().to_vec(),
            created_utc: self.created_utc().to_owned(),
            metadata: self.metadata().clone(),
            public_key: self.public_key().to_vec(),
        })
    }
}

impl PublicKeyFile {
    /// DE: Algorithmus. EN: Algorithm.
    #[must_use]
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// DE: Schlüssel-ID (SHA3-256 des öffentlichen Schlüssels). EN: Key ID (SHA3-256 of the public key).
    #[must_use]
    pub fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    /// DE: Schlüssel-ID als Hex. EN: Key ID as hex.
    #[must_use]
    pub fn key_id_hex(&self) -> String {
        hex_encode(&self.key_id)
    }

    /// DE: Erstellungszeit. EN: Creation time.
    #[must_use]
    pub fn created_utc(&self) -> &str {
        &self.created_utc
    }

    /// DE: Metadaten. EN: Metadata.
    #[must_use]
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// DE: Öffentlicher Schlüssel. EN: Public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// DE: JSON-Darstellung. EN: JSON representation.
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] (praktisch nie / practically never).
    pub fn to_json(&self) -> Result<String> {
        let json = PublicJson {
            magic: PUBLIC_MAGIC.to_owned(),
            format_version: FORMAT_VERSION,
            algorithm: self.algorithm.id().to_owned(),
            key_id: self.key_id_hex(),
            created_utc: self.created_utc.clone(),
            metadata: (&self.metadata).into(),
            public_key: b64_encode(&self.public_key),
        };
        let mut text = serde_json::to_string_pretty(&json)
            .map_err(|_| Error::InvalidInput { field: "json" })?;
        text.push('\n');
        Ok(text)
    }

    /// DE: Liest und prüft streng (Magic, Version, Längen, Schlüssel-ID passt).
    /// EN: Parses and validates strictly (magic, version, lengths, key ID matches).
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`], [`Error::Unsupported`].
    pub fn from_json(text: &str) -> Result<Self> {
        if text.len() > MAX_FILE_BYTES {
            return Err(Error::InvalidInput { field: "file" });
        }
        let json: PublicJson =
            serde_json::from_str(text).map_err(|_| Error::InvalidInput { field: "json" })?;
        if json.magic != PUBLIC_MAGIC {
            return Err(Error::InvalidInput { field: "magic" });
        }
        if json.format_version != FORMAT_VERSION {
            return Err(Error::Unsupported);
        }
        let algorithm = KeyAlgorithm::from_id(&json.algorithm)?;
        if algorithm == KeyAlgorithm::Aes256 {
            return Err(Error::Unsupported);
        }
        time::parse_rfc3339(&json.created_utc)?;
        let metadata = Metadata::from(json.metadata);
        metadata.validate()?;
        let len = algorithm.public_key_len();
        let public_key = b64_decode(&json.public_key, len, "public_key")?;
        if public_key.len() != len {
            return Err(Error::InvalidInput {
                field: "public_key",
            });
        }
        let key_id = hex_decode(&json.key_id, KEY_ID_LEN, "key_id")?;
        if !key_id_matches(algorithm, &key_id, &public_key) {
            return Err(Error::InvalidInput { field: "key_id" });
        }
        Ok(Self {
            algorithm,
            key_id,
            created_utc: json.created_utc,
            metadata,
            public_key,
        })
    }
}
