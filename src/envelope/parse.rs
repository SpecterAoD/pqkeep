//! DE: Strenge Prüfung des eingelesenen JSON: Magic, Version (Downgrade-Schutz),
//! Algorithmus, KDF- und Cipher-Bezeichner, Zeitstempel, Metadaten, Längen aller
//! Binärfelder, Schlüssel-ID gegen öffentlichen Schlüssel, KDF-Grenzen.
//!
//! EN: Strict validation of parsed JSON: magic, version (downgrade protection),
//! algorithm, KDF and cipher identifiers, timestamp, metadata, lengths of all
//! binary fields, key ID against public key, KDF bounds.

use super::encoding::{b64_decode as decode_b64, hex_decode as decode_key_id};
use super::format::{
    CIPHER_ALGORITHM, FORMAT_VERSION, KDF_ALGORITHM, KDF_VERSION, KeyFileJson, MAGIC,
};
use super::keyfile::{KEY_ID_LEN, KeyFile, key_id_matches, salt_len_ok};
use super::{Metadata, time};
use crate::crypto::KeyAlgorithm;
use crate::crypto::aead::{NONCE_LEN, TAG_LEN};
use crate::crypto::kdf::{KdfParams, MAX_SALT_LEN};
use crate::crypto::protect::ProtectedKey;
use crate::{Error, Result};

fn field(field: &'static str) -> Error {
    Error::InvalidInput { field }
}

/// DE: Wandelt geprüftes JSON in eine [`KeyFile`]. EN: Turns validated JSON into a [`KeyFile`].
pub(crate) fn from_parsed(json: KeyFileJson) -> Result<KeyFile> {
    let algorithm = check_identifiers(&json)?;
    time::parse_rfc3339(&json.created_utc)?;
    let public_key = decode_b64(&json.public_key, algorithm.public_key_len(), "public_key")?;
    if public_key.len() != algorithm.public_key_len() {
        return Err(field("public_key"));
    }
    let key_id = decode_key_id(&json.key_id, KEY_ID_LEN, "key_id")?;
    if !key_id_matches(algorithm, &key_id, &public_key) {
        return Err(field("key_id"));
    }
    let protected = decode_protected(algorithm, &json)?;
    let metadata = Metadata::from(json.metadata);
    metadata.validate()?;
    Ok(KeyFile::from_parts(
        algorithm,
        key_id,
        json.created_utc,
        metadata,
        public_key,
        protected,
    ))
}

/// DE: Magic, Version (Downgrade-Schutz), Algorithmus, KDF- und Cipher-Bezeichner.
/// EN: Magic, version (downgrade protection), algorithm, KDF and cipher identifiers.
fn check_identifiers(json: &KeyFileJson) -> Result<KeyAlgorithm> {
    if json.magic != MAGIC {
        return Err(field("magic"));
    }
    if json.format_version != FORMAT_VERSION {
        return Err(Error::Unsupported);
    }
    let algorithm = KeyAlgorithm::from_id(&json.algorithm)?;
    let ids_ok = json.kdf.algorithm == KDF_ALGORITHM
        && json.kdf.version == KDF_VERSION
        && json.cipher.algorithm == CIPHER_ALGORITHM;
    if ids_ok {
        Ok(algorithm)
    } else {
        Err(Error::Unsupported)
    }
}

/// DE: KDF-Parameter (Grenzen), Salt, Nonce und Chiffrat mit exakten Längen.
/// EN: KDF parameters (bounds), salt, nonce and ciphertext with exact lengths.
fn decode_protected(algorithm: KeyAlgorithm, json: &KeyFileJson) -> Result<ProtectedKey> {
    let kdf = KdfParams {
        memory_kib: json.kdf.memory_kib,
        iterations: json.kdf.iterations,
        parallelism: json.kdf.parallelism,
    };
    kdf.validate()?;
    let salt = decode_b64(&json.kdf.salt, MAX_SALT_LEN, "salt")?;
    if !salt_len_ok(salt.len()) {
        return Err(field("salt"));
    }
    let nonce = decode_b64(&json.cipher.nonce, NONCE_LEN, "nonce")?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| field("nonce"))?;
    let ct_len = algorithm.secret_len() + TAG_LEN;
    let ciphertext = decode_b64(&json.cipher.ciphertext, ct_len, "ciphertext")?;
    if ciphertext.len() != ct_len {
        return Err(field("ciphertext"));
    }
    Ok(ProtectedKey {
        algorithm,
        kdf,
        salt,
        nonce,
        ciphertext,
    })
}
