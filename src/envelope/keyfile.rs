//! DE: Schlüsseldatei: erzeugen (nur mit `StrongPassphrase`), als JSON ausgeben,
//! streng einlesen und mit `Passphrase` entsperren.
//! EN: Key file: create (only with `StrongPassphrase`), serialise to JSON, parse
//! strictly and unlock with `Passphrase`.

use sha3::{Digest, Sha3_256};

use super::encoding::{b64_encode, hex_encode};
use super::format::{
    CIPHER_ALGORITHM, CipherJson, FORMAT_VERSION, Header, KDF_ALGORITHM, KDF_VERSION, KdfJson,
    KeyFileJson, MAGIC,
};
use super::{Metadata, time};
use crate::crypto::kdf::{self, KdfParams};
use crate::crypto::protect::{self, ProtectedKey};
use crate::crypto::{KeyAlgorithm, SecretBytes, aead, dsa, kem, rng};
use crate::security::{Passphrase, StrongPassphrase};
use crate::{Error, Result};

/// DE: Höchstgröße einer Schlüsseldatei. EN: Maximum size of a key file.
pub const MAX_FILE_BYTES: usize = 64 * 1024;
/// DE: Länge der Schlüssel-ID. EN: Length of the key ID.
pub const KEY_ID_LEN: usize = 32;

/// DE: Geschützter Schlüssel mit Metadaten (alle Felder öffentlich speicherbar).
/// EN: Protected key with metadata (all fields safe to store publicly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFile {
    algorithm: KeyAlgorithm,
    key_id: Vec<u8>,
    created_utc: String,
    metadata: Metadata,
    public_key: Vec<u8>,
    protected: ProtectedKey,
}

/// DE: Entsperrter Schlüssel. Das Geheimnis wird beim Drop genullt.
/// EN: Unlocked key. The secret is zeroed on drop.
pub struct UnlockedKey {
    /// DE: Algorithmus. EN: Algorithm.
    pub algorithm: KeyAlgorithm,
    /// DE: Öffentlicher Schlüssel (AES: leer). EN: Public key (AES: empty).
    pub public_key: Vec<u8>,
    secret: SecretBytes,
}

impl UnlockedKey {
    /// DE: Seed (ML-KEM/ML-DSA) bzw. AES-Schlüssel. EN: Seed (ML-KEM/ML-DSA) or AES key.
    #[must_use]
    pub fn secret(&self) -> &SecretBytes {
        &self.secret
    }
}

fn derive_public(algorithm: KeyAlgorithm, secret: &[u8]) -> Result<Vec<u8>> {
    Ok(match algorithm {
        KeyAlgorithm::Kem(a) => kem::from_seed(a, secret)?.public_key,
        KeyAlgorithm::Dsa(a) => dsa::from_seed(a, secret)?.public_key,
        KeyAlgorithm::Aes256 => Vec::new(),
    })
}

fn fingerprint(public_key: &[u8]) -> Vec<u8> {
    Sha3_256::digest(public_key).to_vec()
}

impl KeyFile {
    /// DE: Erzeugt einen neuen Schlüssel und schützt ihn. EN: Generates and protects a new key.
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] (Metadaten / metadata), [`Error::KdfParams`], [`Error::Rng`].
    pub fn generate(
        passphrase: &StrongPassphrase,
        algorithm: KeyAlgorithm,
        metadata: &Metadata,
        params: &KdfParams,
    ) -> Result<Self> {
        let (secret, public_key) = match algorithm {
            KeyAlgorithm::Kem(a) => {
                let kp = kem::generate(a)?;
                (SecretBytes::from_slice(kp.seed().expose()), kp.public_key)
            }
            KeyAlgorithm::Dsa(a) => {
                let kp = dsa::generate(a)?;
                (SecretBytes::from_slice(kp.seed().expose()), kp.public_key)
            }
            KeyAlgorithm::Aes256 => (aead::generate_key()?, Vec::new()),
        };
        Self::create(
            passphrase,
            algorithm,
            secret.expose(),
            &public_key,
            metadata,
            params,
        )
    }

    /// DE: Schützt vorhandenes Schlüsselmaterial; prüft, dass Seed und öffentlicher
    /// Schlüssel zusammenpassen.
    /// EN: Protects existing key material; checks that seed and public key match.
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`], [`Error::KdfParams`], [`Error::Rng`].
    pub fn create(
        passphrase: &StrongPassphrase,
        algorithm: KeyAlgorithm,
        secret: &[u8],
        public_key: &[u8],
        metadata: &Metadata,
        params: &KdfParams,
    ) -> Result<Self> {
        let metadata = metadata.normalized()?;
        if derive_public(algorithm, secret)? != public_key {
            return Err(Error::InvalidInput {
                field: "public_key",
            });
        }
        let key_id = match algorithm {
            // DE: Zufalls-ID; ein Hash würde den AES-Schlüssel überprüfbar machen.
            // EN: Random ID; a hash would make the AES key verifiable.
            KeyAlgorithm::Aes256 => rng::array::<KEY_ID_LEN>()?.to_vec(),
            _ => fingerprint(public_key),
        };
        let created_utc = time::now_rfc3339();
        let header = Header {
            key_id: &key_id,
            created_utc: &created_utc,
            metadata: &metadata,
            public_key,
        };
        let protected = protect::protect(passphrase, algorithm, secret, params, &header.encode())?;
        Ok(Self {
            algorithm,
            key_id,
            created_utc,
            metadata,
            public_key: public_key.to_vec(),
            protected,
        })
    }

    /// DE: Entsperrt den Schlüssel und prüft ihn gegen den öffentlichen Schlüssel.
    /// EN: Unlocks the key and checks it against the public key.
    ///
    /// # Errors
    /// DE/EN: [`Error::Decrypt`] (falsche Passphrase/Manipulation / wrong passphrase/tampering),
    /// [`Error::KdfParams`], [`Error::InvalidInput`].
    pub fn unlock(&self, passphrase: &Passphrase) -> Result<UnlockedKey> {
        let secret = protect::unprotect(passphrase, &self.protected, &self.header().encode())?;
        if derive_public(self.algorithm, secret.expose())? != self.public_key {
            return Err(Error::InvalidInput {
                field: "public_key",
            });
        }
        Ok(UnlockedKey {
            algorithm: self.algorithm,
            public_key: self.public_key.clone(),
            secret,
        })
    }

    fn header(&self) -> Header<'_> {
        Header {
            key_id: &self.key_id,
            created_utc: &self.created_utc,
            metadata: &self.metadata,
            public_key: &self.public_key,
        }
    }

    /// DE: Algorithmus. EN: Algorithm.
    #[must_use]
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// DE: Schlüssel-ID (32 Byte). EN: Key ID (32 bytes).
    #[must_use]
    pub fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    /// DE: Schlüssel-ID als Hex. EN: Key ID as hex.
    #[must_use]
    pub fn key_id_hex(&self) -> String {
        hex_encode(&self.key_id)
    }

    /// DE: Erstellungszeit (RFC 3339, UTC). EN: Creation time (RFC 3339, UTC).
    #[must_use]
    pub fn created_utc(&self) -> &str {
        &self.created_utc
    }

    /// DE: Metadaten (Klartext). EN: Metadata (plaintext).
    #[must_use]
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// DE: Öffentlicher Schlüssel (AES: leer). EN: Public key (AES: empty).
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// DE: KDF-Parameter. EN: KDF parameters.
    #[must_use]
    pub fn kdf_params(&self) -> KdfParams {
        self.protected.kdf
    }

    /// DE: JSON-Darstellung (eingerückt). EN: JSON representation (pretty-printed).
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] (praktisch nie / practically never).
    pub fn to_json(&self) -> Result<String> {
        let p = &self.protected;
        let json = KeyFileJson {
            magic: MAGIC.to_owned(),
            format_version: FORMAT_VERSION,
            algorithm: self.algorithm.id().to_owned(),
            key_id: self.key_id_hex(),
            created_utc: self.created_utc.clone(),
            metadata: (&self.metadata).into(),
            public_key: b64_encode(&self.public_key),
            kdf: KdfJson {
                algorithm: KDF_ALGORITHM.to_owned(),
                version: KDF_VERSION,
                memory_kib: p.kdf.memory_kib,
                iterations: p.kdf.iterations,
                parallelism: p.kdf.parallelism,
                salt: b64_encode(&p.salt),
            },
            cipher: CipherJson {
                algorithm: CIPHER_ALGORITHM.to_owned(),
                nonce: b64_encode(&p.nonce),
                ciphertext: b64_encode(&p.ciphertext),
            },
        };
        let mut text = serde_json::to_string_pretty(&json)
            .map_err(|_| Error::InvalidInput { field: "json" })?;
        text.push('\n');
        Ok(text)
    }

    /// DE: Liest und prüft JSON streng (Größe, Felder, Version, Längen, Grenzen).
    /// EN: Parses and validates JSON strictly (size, fields, version, lengths, bounds).
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] mit Feldnamen / with field name, [`Error::Unsupported`],
    /// [`Error::KdfParams`].
    pub fn from_json(text: &str) -> Result<Self> {
        if text.len() > MAX_FILE_BYTES {
            return Err(Error::InvalidInput { field: "file" });
        }
        let json: KeyFileJson =
            serde_json::from_str(text).map_err(|_| Error::InvalidInput { field: "json" })?;
        super::parse::from_parsed(json)
    }

    pub(crate) fn from_parts(
        algorithm: KeyAlgorithm,
        key_id: Vec<u8>,
        created_utc: String,
        metadata: Metadata,
        public_key: Vec<u8>,
        protected: ProtectedKey,
    ) -> Self {
        Self {
            algorithm,
            key_id,
            created_utc,
            metadata,
            public_key,
            protected,
        }
    }
}

/// DE: Prüft eine Schlüssel-ID gegen den öffentlichen Schlüssel (nicht für AES).
/// EN: Checks a key ID against the public key (not for AES).
pub(crate) fn key_id_matches(algorithm: KeyAlgorithm, key_id: &[u8], public_key: &[u8]) -> bool {
    algorithm == KeyAlgorithm::Aes256 || fingerprint(public_key) == key_id
}

/// DE: Plausible Salt-Länge. EN: Plausible salt length.
pub(crate) fn salt_len_ok(len: usize) -> bool {
    (kdf::MIN_SALT_LEN..=kdf::MAX_SALT_LEN).contains(&len)
}
