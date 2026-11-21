//! DE: Rohe Testarchive, korrekt mit Laufzeitschlüsseln verschlüsselt.
//! EN: Raw test archives correctly encrypted with runtime keys.

use std::path::Path;

use pqkeep::crypto::stream::EncryptWriter;
use pqkeep::crypto::wrap::{self, Wrapped};
use pqkeep::crypto::{KemAlgorithm, KeyAlgorithm, aead, rng};
use pqkeep::envelope::{KeyFile, UnlockedKey};
use pqkeep::files::{Content, FileHeader, HeaderMode};
use sha3::{Digest, Sha3_256};

/// DE: Rohes Archiv: Einträge als (Tag, Pfad, Inhalt, Prüfsumme korrekt?).
/// EN: Raw archive: entries as (tag, path, content, checksum correct?).
pub fn dir_entry(path: &str) -> Vec<u8> {
    let mut v = vec![1u8];
    v.extend_from_slice(&u16::try_from(path.len()).unwrap().to_le_bytes());
    v.extend_from_slice(path.as_bytes());
    v
}

pub fn file_entry(path: &str, data: &[u8], good_hash: bool) -> Vec<u8> {
    let mut v = vec![2u8];
    v.extend_from_slice(&u16::try_from(path.len()).unwrap().to_le_bytes());
    v.extend_from_slice(path.as_bytes());
    v.extend_from_slice(&(data.len() as u64).to_le_bytes());
    v.extend_from_slice(data);
    let mut hash = Sha3_256::digest(data).to_vec();
    if !good_hash {
        hash[0] ^= 1;
    }
    v.extend_from_slice(&hash);
    v
}

pub fn end(count: u64) -> Vec<u8> {
    let mut v = vec![0u8];
    v.extend_from_slice(&count.to_le_bytes());
    v
}

pub struct Key {
    pub file: KeyFile,
    pub unlocked: UnlockedKey,
}

pub fn key() -> Key {
    let (file, pass) = super::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    let unlocked = file.unlock(pass.as_ref()).unwrap();
    Key { file, unlocked }
}

/// DE: Verschlüsselt rohe Archivbytes korrekt für den Empfänger.
/// EN: Correctly encrypts raw archive bytes for the recipient.
pub fn build(key: &Key, content: Content, plaintext: &[u8], out: &Path) {
    let file_key = aead::generate_key().unwrap();
    let recipient_id: [u8; 32] = key.file.key_id().try_into().unwrap();
    let mut header = FileHeader {
        content,
        prefix: rng::array().unwrap(),
        mode: HeaderMode::Recipient {
            algorithm: KemAlgorithm::MlKem768,
            recipient_id,
            kem_ciphertext: Vec::new(),
        },
        wrapped: Wrapped {
            nonce: [0; 12],
            ciphertext: Vec::new(),
        },
    };
    let aad = header.wrap_aad();
    let r = wrap::wrap_for_recipient(
        KemAlgorithm::MlKem768,
        key.file.public_key(),
        &recipient_id,
        file_key.expose(),
        &aad,
    )
    .unwrap();
    header.mode = HeaderMode::Recipient {
        algorithm: KemAlgorithm::MlKem768,
        recipient_id,
        kem_ciphertext: r.kem_ciphertext,
    };
    header.wrapped = r.wrapped;
    let mut bytes = header.encode();
    let mut enc = EncryptWriter::new(
        file_key.expose(),
        header.prefix,
        &header.stream_aad(),
        Vec::new(),
    )
    .unwrap();
    enc.push(plaintext).unwrap();
    bytes.extend(enc.finish().unwrap().0);
    std::fs::write(out, bytes).unwrap();
}
