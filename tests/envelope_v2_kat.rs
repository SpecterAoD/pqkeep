//! DE: Known-Answer-Test der Schlüsseldatei v2 (C07 aus `docs/V2_TESTS.md`): eine ohne den
//! Rust-Code gebaute `*.key.json` (`tests/kat/v2_keyfile.json` aus
//! `scripts/v2_keyfile_vector.py`: Header/AAD der Python-Referenz, Argon2id aus `argon2pure`,
//! AES-256-GCM aus Python `cryptography`) muss sich mit Passphrase und Faktordatei entsperren
//! lassen und bytegleich wieder ausgegeben werden. Nur öffentliche Testbytes.
//!
//! EN: Known-answer test of key file v2 (C07 in `docs/V2_TESTS.md`): a `*.key.json` built
//! without the Rust code (`tests/kat/v2_keyfile.json` from `scripts/v2_keyfile_vector.py`:
//! header/AAD of the Python reference, Argon2id from `argon2pure`, AES-256-GCM from Python
//! `cryptography`) must unlock with passphrase and factor file and serialise back
//! byte-identically. Public test bytes only.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use pqkeep::Error;
use pqkeep::crypto::KeyAlgorithm;
use pqkeep::crypto::factor::Factor;
use pqkeep::crypto::kdf;
use pqkeep::envelope::{FORMAT_VERSION_V2, KeyFile};
use pqkeep::security::Passphrase;
use serde_json::Value;

/// DE: Öffentlicher Testwert aus `scripts/v2_argon2_vectors.py`. EN: Public test value.
const PASSPHRASE: &str = "PQKeep v2 Testvektor – nicht geheim";

fn load(name: &str) -> Value {
    let path = format!("{}/tests/kat/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn bytes(doc: &Value, field: &str) -> Vec<u8> {
    hex::decode(doc[field].as_str().unwrap()).unwrap()
}

#[test]
fn c07_independent_key_file_unlocks() {
    let vector = load("v2_keyfile.json");
    let text = String::from_utf8(bytes(&vector, "document_hex")).unwrap();
    let factor = Factor::from_bytes(&bytes(&load("v2_argon2id.json"), "factor_hex")).unwrap();
    let passphrase = Passphrase::new(PASSPHRASE).unwrap();

    let file = KeyFile::from_json(&text).unwrap();
    assert_eq!(file.algorithm(), KeyAlgorithm::Aes256);
    assert_eq!(file.format_version(), FORMAT_VERSION_V2);
    assert!(file.needs_factor());
    assert_eq!(file.kdf_params().memory_kib, kdf::MIN_MEMORY_KIB);
    assert_eq!(file.kdf_params().parallelism, 4);
    assert_eq!(file.to_json().unwrap(), text, "bytegleich / byte-identical");

    let unlocked = file.unlock_with_factor(&passphrase, &factor).unwrap();
    assert_eq!(unlocked.secret().expose(), bytes(&vector, "plain_hex"));

    // DE: Ohne Faktor, mit anderem Faktor oder anderer Passphrase öffnet nichts.
    // EN: Nothing opens without the factor, with another factor or another passphrase.
    let required = Error::InvalidInput {
        field: "factor_required",
    };
    assert_eq!(file.unlock(&passphrase).err(), Some(required));
    let other = Factor::from_bytes(&[0x5a; 32]).unwrap();
    let wrong_factor = file.unlock_with_factor(&passphrase, &other);
    assert_eq!(wrong_factor.err(), Some(Error::Decrypt));
    let wrong = Passphrase::new("PQKeep v2 Testvektor – nicht geheim!").unwrap();
    let wrong_passphrase = file.unlock_with_factor(&wrong, &factor);
    assert_eq!(wrong_passphrase.err(), Some(Error::Decrypt));
}

/// DE: Fester Anteil von C09 (das Fuzz-Ziel `keyfile_parse` sucht zufällig weiter): die
/// v2-Datei an jeder Stelle gekürzt oder mit einem geänderten Byte führt nie zu einer Panik,
/// und was sich lesen lässt, bleibt beim erneuten Schreiben und Lesen dasselbe.
/// EN: Fixed part of C09 (the fuzz target `keyfile_parse` keeps searching at random): the v2
/// file truncated anywhere or with one changed byte never panics, and whatever parses stays
/// the same when written and read again.
#[test]
fn c09_truncated_or_mutated_json_never_panics() {
    let raw = bytes(&load("v2_keyfile.json"), "document_hex");
    let check = |data: &[u8]| {
        if let Ok(file) = KeyFile::from_json(&String::from_utf8_lossy(data)) {
            let again = KeyFile::from_json(&file.to_json().unwrap()).unwrap();
            assert_eq!(again, file);
            assert_eq!(
                file.needs_factor(),
                file.format_version() == FORMAT_VERSION_V2
            );
        }
    };
    // DE: Ohne das Zeilenende ist die Datei noch vollständig; jede kürzere nicht.
    // EN: Without the trailing newline the file is still complete; any shorter one is not.
    for end in 0..raw.len() - 1 {
        assert!(KeyFile::from_json(&String::from_utf8_lossy(&raw[..end])).is_err());
    }
    for index in 0..raw.len() {
        for replacement in [b'0', b'2', b'"', b'}', b' ', 0xff] {
            let mut data = raw.clone();
            data[index] = replacement;
            check(&data);
        }
    }
}
