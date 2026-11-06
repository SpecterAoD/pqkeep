//! DE: Property-Tests für den Parser: beliebige Eingaben und zufällig veränderte
//! gültige Container führen nie zu einer Panik. Entsperren wird für veränderte,
//! aber einlesbare Container nicht versucht (Argon2 wäre zu langsam); das deckt
//! `envelope_tamper.rs` gezielt ab.
//! EN: Property tests for the parser: arbitrary input and randomly mutated valid
//! containers never cause a panic. Unlocking is not attempted for mutated but
//! parseable containers (Argon2 would be too slow); `envelope_tamper.rs` covers that.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::OnceLock;

use pqc_keyforge::crypto::KeyAlgorithm;
use pqc_keyforge::envelope::KeyFile;
use proptest::prelude::*;

fn valid_json() -> &'static str {
    static JSON: OnceLock<String> = OnceLock::new();
    JSON.get_or_init(|| {
        let (file, _) = common::key_file(KeyAlgorithm::Kem(
            pqc_keyforge::crypto::KemAlgorithm::default(),
        ));
        file.to_json().unwrap()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_text_never_panics(text in ".{0,4096}") {
        let _ = KeyFile::from_json(&text);
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let text = String::from_utf8_lossy(&bytes);
        let _ = KeyFile::from_json(&text);
    }

    #[test]
    fn mutated_valid_container_never_panics(
        edits in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>(), 0u8..3), 1..8)
    ) {
        let mut bytes = valid_json().as_bytes().to_vec();
        for (index, value, kind) in edits {
            if bytes.is_empty() {
                break;
            }
            let i = index.index(bytes.len());
            match kind {
                0 => bytes[i] = value,
                1 => { bytes.remove(i); }
                _ => bytes.insert(i, value),
            }
        }
        let text = String::from_utf8_lossy(&bytes);
        if let Ok(file) = KeyFile::from_json(&text) {
            // DE: Was eingelesen wird, muss sich wieder ausgeben und einlesen lassen.
            // EN: Whatever parses must serialise and parse again.
            let again = KeyFile::from_json(&file.to_json().unwrap()).unwrap();
            prop_assert_eq!(again, file);
        }
    }
}
