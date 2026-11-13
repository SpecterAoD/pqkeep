//! DE: Schlüsseldatei: erzeugen (nur mit `StrongPassphrase`), streng einlesen und mit
//! `Passphrase` entsperren. JSON-Ausgabe und -Prüfung: `parse.rs`; Version 2 mit Faktordatei:
//! `keyfile_v2.rs`.
//! EN: Key file: create (only with `StrongPassphrase`), parse strictly and unlock with
//! `Passphrase`. JSON output and validation: `parse.rs`; version 2 with factor file:
//! `keyfile_v2.rs`.

use sha3::{Digest, Sha3_256};

use super::encoding::hex_encode;
use super::format::Header;
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
    pub(super) algorithm: KeyAlgorithm,
    pub(super) key_id: Vec<u8>,
    pub(super) created_utc: String,
    pub(super) metadata: Metadata,
    pub(super) public_key: Vec<u8>,
    /// DE: Version 2: zum Entsperren ist die Faktordatei nötig.
    /// EN: Version 2: the factor file is needed to unlock.
    pub(super) factor: bool,
    pub(super) protected: ProtectedKey,
}

/// DE: Entsperrter Schlüssel. Das Geheimnis wird beim Drop genullt.
/// EN: Unlocked key. The secret is zeroed on drop.
pub struct UnlockedKey {
    /// DE: Algorithmus. EN: Algorithm.
    pub algorithm: KeyAlgorithm,
    /// DE: Öffentlicher Schlüssel (AES: leer). EN: Public key (AES: empty).
    pub public_key: Vec<u8>,
    pub(super) secret: SecretBytes,
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

/// DE: Schlüssel-ID = SHA3-256 des öffentlichen Schlüssels. EN: Key ID = SHA3-256 of the public key.
pub(crate) fn fingerprint(public_key: &[u8]) -> Vec<u8> {
    Sha3_256::digest(public_key).to_vec()
}

/// DE: Neues Schlüsselmaterial: (Seed bzw. AES-Schlüssel, öffentlicher Schlüssel).
/// EN: Fresh key material: (seed or AES key, public key).
pub(super) fn new_secret(algorithm: KeyAlgorithm) -> Result<(SecretBytes, Vec<u8>)> {
    Ok(match algorithm {
        KeyAlgorithm::Kem(a) => {
            let kp = kem::generate(a)?;
            (SecretBytes::from_slice(kp.seed().expose()), kp.public_key)
        }
        KeyAlgorithm::Dsa(a) => {
            let kp = dsa::generate(a)?;
            (SecretBytes::from_slice(kp.seed().expose()), kp.public_key)
        }
        KeyAlgorithm::Aes256 => (aead::generate_key()?, Vec::new()),
    })
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
        let (secret, public_key) = new_secret(algorithm)?;
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
        Self::build(algorithm, secret, public_key, metadata, false, |header| {
            protect::protect(passphrase, algorithm, secret, params, header)
        })
    }

    /// DE: Gemeinsamer Teil des Erzeugens: prüft Material und Metadaten, bildet ID und Header;
    /// `protect` verschlüsselt mit dem kodierten Header als AAD-Teil.
    /// EN: Shared part of creation: checks material and metadata, builds ID and header;
    /// `protect` encrypts with the encoded header as part of the AAD.
    pub(super) fn build(
        algorithm: KeyAlgorithm,
        secret: &[u8],
        public_key: &[u8],
        metadata: &Metadata,
        factor: bool,
        protect: impl FnOnce(&[u8]) -> Result<ProtectedKey>,
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
            factor,
        };
        let protected = protect(&header.encode())?;
        Ok(Self {
            algorithm,
            key_id,
            created_utc,
            metadata,
            public_key: public_key.to_vec(),
            factor,
            protected,
        })
    }

    /// DE: Entsperrt den Schlüssel und prüft ihn gegen den öffentlichen Schlüssel.
    /// EN: Unlocks the key and checks it against the public key.
    ///
    /// # Errors
    /// DE/EN: [`Error::Decrypt`] (falsche Passphrase/Manipulation / wrong passphrase/tampering),
    /// [`Error::KdfParams`], [`Error::InvalidInput`] (`factor_required`: Version 2 braucht die
    /// Faktordatei, siehe [`Self::unlock_with_factor`]; gemeldet vor der Ableitung / reported
    /// before the derivation).
    pub fn unlock(&self, passphrase: &Passphrase) -> Result<UnlockedKey> {
        if self.factor {
            return Err(Error::InvalidInput {
                field: "factor_required",
            });
        }
        let secret = protect::unprotect(passphrase, &self.protected, &self.header().encode())?;
        self.finish(secret)
    }

    /// DE: Prüft das entschlüsselte Geheimnis gegen den öffentlichen Schlüssel.
    /// EN: Checks the decrypted secret against the public key.
    pub(super) fn finish(&self, secret: SecretBytes) -> Result<UnlockedKey> {
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

    pub(super) fn header(&self) -> Header<'_> {
        Header {
            key_id: &self.key_id,
            created_utc: &self.created_utc,
            metadata: &self.metadata,
            public_key: &self.public_key,
            factor: self.factor,
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
