//! DE: JSON-Ausgabe und strenge Prüfung des eingelesenen JSON: Magic, Version
//! (Downgrade-Schutz; Version 2 nur mit `kdf.factor = "file-32"`, Version 1 nur ohne das Feld),
//! Algorithmus, KDF- und Cipher-Bezeichner, Zeitstempel, Metadaten, Längen aller
//! Binärfelder, Schlüssel-ID gegen öffentlichen Schlüssel, KDF-Grenzen.
//!
//! EN: JSON output and strict validation of parsed JSON: magic, version (downgrade
//! protection; version 2 only with `kdf.factor = "file-32"`, version 1 only without the
//! field), algorithm, KDF and cipher identifiers, timestamp, metadata, lengths of all
//! binary fields, key ID against public key, KDF bounds.

use super::encoding::{b64_decode as decode_b64, b64_encode, hex_decode as decode_key_id};
use super::format::{
    CIPHER_ALGORITHM, CipherJson, FORMAT_VERSION, FORMAT_VERSION_V2, KDF_ALGORITHM,
    KDF_FACTOR_FILE, KDF_VERSION, KdfJson, KeyFileJson, MAGIC,
};
use super::keyfile::{KEY_ID_LEN, KeyFile, MAX_FILE_BYTES, key_id_matches, salt_len_ok};
use super::{Metadata, time};
use crate::crypto::KeyAlgorithm;
use crate::crypto::aead::{NONCE_LEN, TAG_LEN};
use crate::crypto::kdf::{KdfParams, MAX_SALT_LEN};
use crate::crypto::protect::ProtectedKey;
use crate::{Error, Result};

fn field(field: &'static str) -> Error {
    Error::InvalidInput { field }
}

impl KeyFile {
    /// DE: JSON-Darstellung (eingerückt). EN: JSON representation (pretty-printed).
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] (praktisch nie / practically never).
    pub fn to_json(&self) -> Result<String> {
        let p = &self.protected;
        let json = KeyFileJson {
            magic: MAGIC.to_owned(),
            format_version: self.format_version(),
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
                factor: self.factor.then(|| KDF_FACTOR_FILE.to_owned()),
            },
            cipher: CipherJson {
                algorithm: CIPHER_ALGORITHM.to_owned(),
                nonce: b64_encode(&p.nonce),
                ciphertext: b64_encode(&p.ciphertext),
            },
        };
        let mut text = serde_json::to_string_pretty(&json).map_err(|_| field("json"))?;
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
            return Err(field("file"));
        }
        let json: KeyFileJson = serde_json::from_str(text).map_err(|_| field("json"))?;
        from_parsed(json)
    }
}

/// DE: Wandelt geprüftes JSON in eine [`KeyFile`]. EN: Turns validated JSON into a [`KeyFile`].
fn from_parsed(json: KeyFileJson) -> Result<KeyFile> {
    let (algorithm, factor) = check_identifiers(&json)?;
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
    Ok(KeyFile {
        algorithm,
        key_id,
        created_utc: json.created_utc,
        metadata,
        public_key,
        factor,
        protected,
    })
}

/// DE: Magic, Version (Downgrade-Schutz), Algorithmus, KDF- und Cipher-Bezeichner. Liefert
/// zusätzlich, ob die Datei eine Faktordatei verlangt (Version 2).
/// EN: Magic, version (downgrade protection), algorithm, KDF and cipher identifiers. Also
/// returns whether the file requires a factor file (version 2).
fn check_identifiers(json: &KeyFileJson) -> Result<(KeyAlgorithm, bool)> {
    if json.magic != MAGIC {
        return Err(field("magic"));
    }
    let factor = match (json.format_version, json.kdf.factor.as_deref()) {
        (FORMAT_VERSION, None) => false,
        (FORMAT_VERSION_V2, Some(KDF_FACTOR_FILE)) => true,
        (FORMAT_VERSION | FORMAT_VERSION_V2, _) => return Err(field("kdf_factor")),
        _ => return Err(Error::Unsupported),
    };
    let algorithm = KeyAlgorithm::from_id(&json.algorithm)?;
    let ids_ok = json.kdf.algorithm == KDF_ALGORITHM
        && json.kdf.version == KDF_VERSION
        && json.cipher.algorithm == CIPHER_ALGORITHM;
    if ids_ok {
        Ok((algorithm, factor))
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
