//! DE: Property-Tests: Header-Parser mit beliebigen Bytes und zufällig veränderte
//! verschlüsselte Dateien (Empfänger-Modus, schnell) führen nie zu einer Panik und
//! hinterlassen keine Ausgabe.
//! EN: Property tests: header parser with arbitrary bytes and randomly mutated
//! encrypted files (recipient mode, fast) never panic and leave no output.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::OnceLock;

use pqc_keyforge::crypto::{KemAlgorithm, KeyAlgorithm};
use pqc_keyforge::envelope::UnlockedKey;
use pqc_keyforge::files::{self, FileHeader, Protection, Unlock};
use proptest::prelude::*;

struct Sample {
    bytes: Vec<u8>,
    key: UnlockedKey,
}

fn sample() -> &'static Sample {
    static S: OnceLock<Sample> = OnceLock::new();
    S.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("baum");
        std::fs::create_dir(&src).unwrap();
        common::write_sample_tree(&src);
        let (key_file, pass) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem512));
        let enc = dir.path().join("baum.pqkf");
        files::encrypt(
            &src,
            &enc,
            &Protection::Recipient(&key_file.public_part().unwrap()),
        )
        .unwrap();
        Sample {
            bytes: std::fs::read(&enc).unwrap(),
            key: key_file.unlock(pass.as_ref()).unwrap(),
        }
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn header_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = FileHeader::read(&mut bytes.as_slice());
    }

    #[test]
    fn header_with_valid_magic_never_panics(rest in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let mut bytes = b"PQKFENC\0\x01\x00".to_vec();
        bytes.extend(rest);
        let _ = FileHeader::read(&mut bytes.as_slice());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn mutated_file_never_panics_or_leaks(
        edits in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>(), 0u8..3), 1..4)
    ) {
        let s = sample();
        let mut bytes = s.bytes.clone();
        for (index, value, kind) in edits {
            let i = index.index(bytes.len());
            match kind {
                0 => bytes[i] ^= value | 1,
                1 => { bytes.remove(i); }
                _ => bytes.insert(i, value),
            }
        }
        // DE: Entfernen + Einfügen desselben Bytes kann das Original ergeben.
        // EN: Removing + inserting the same byte can restore the original.
        prop_assume!(bytes != s.bytes);
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.pqkf");
        std::fs::write(&input, &bytes).unwrap();
        let result = files::decrypt(&input, &dir.path().join("out"), &Unlock::Key(&s.key));
        prop_assert!(result.is_err());
        prop_assert_eq!(common::dir_names(dir.path()), vec!["in.pqkf".to_owned()]);
    }
}
