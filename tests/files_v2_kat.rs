//! DE: C02 (Inhalt) aus `docs/V2_TESTS.md`: eine vollständige v2-Datei, die ohne den Rust-Code
//! gebaut wurde (`scripts/v2_content_vector.py`: Header aus der Python-Referenz, Packschlüssel aus
//! dem argon2pure-Vektor, AES-256-GCM aus Python `cryptography`), muss sich öffnen lassen und den
//! erwarteten Klartext liefern. Nur öffentliche Testbytes.
//! EN: C02 (content) in `docs/V2_TESTS.md`: a complete v2 file built without the Rust code
//! (`scripts/v2_content_vector.py`: header from the Python reference, wrapping key from the
//! argon2pure vector, AES-256-GCM from Python `cryptography`) must open and yield the expected
//! plaintext. Public test bytes only.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use pqkeep::Error;
use pqkeep::crypto::factor::Factor;
use pqkeep::crypto::kdf::{self, KdfParams};
use pqkeep::files::{self, Content, Slot, Unlock};
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
fn c02_independent_file_opens() {
    let vector = load("v2_content.json");
    let factor = Factor::from_bytes(&bytes(&load("v2_argon2id.json"), "factor_hex")).unwrap();
    let passphrase = Passphrase::new(PASSPHRASE).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("vektor.pqkf");
    std::fs::write(&input, bytes(&vector, "file_hex")).unwrap();

    let header = files::inspect_v2(&input).unwrap();
    assert_eq!(header.content, Content::File);
    let expected = Slot::Passphrase {
        factor: true,
        params: KdfParams {
            memory_kib: kdf::MIN_MEMORY_KIB,
            iterations: kdf::MIN_ITERATIONS,
            parallelism: 1,
        },
        salt: (32..64).collect(),
        nonce: [200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211],
    };
    assert_eq!(header.slots, [expected]);
    assert_eq!(files::inspect(&input).err(), Some(Error::Unsupported));

    let out = dir.path().join("klartext");
    let unlock = Unlock::PassphraseWithFactor {
        passphrase: &passphrase,
        factor: &factor,
    };
    let report = files::decrypt(&input, &out, &unlock).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), bytes(&vector, "plain_hex"));
    assert_eq!((report.files, report.directories), (1, 0));

    // DE: Anderer Faktor oder andere Passphrase öffnen nicht. EN: Other factor/passphrase fail.
    let other = Factor::from_bytes(&[0x5a; 32]).unwrap();
    let wrong_factor = Unlock::PassphraseWithFactor {
        passphrase: &passphrase,
        factor: &other,
    };
    let out = dir.path().join("zweiter");
    assert_eq!(
        files::decrypt(&input, &out, &wrong_factor).err(),
        Some(Error::Decrypt)
    );
    let wrong = Passphrase::new("PQKeep v2 Testvektor - nicht geheim").unwrap();
    let wrong_passphrase = Unlock::PassphraseWithFactor {
        passphrase: &wrong,
        factor: &factor,
    };
    assert_eq!(
        files::decrypt(&input, &out, &wrong_passphrase).err(),
        Some(Error::Decrypt)
    );
    assert_eq!(common::dir_names(dir.path()), ["klartext", "vektor.pqkf"]);
}
