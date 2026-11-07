//! DE: Tests der Fehlertexte: zweisprachig, nicht leer, ohne Eingabedaten.
//! EN: Tests of error messages: bilingual, non-empty, without input data.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use pqkeep::Error;

fn all_variants() -> Vec<Error> {
    vec![
        Error::InvalidInput { field: "name" },
        Error::Crypto,
        Error::Decrypt,
        Error::KdfParams,
        Error::Rng,
        Error::Unsupported,
        Error::Io(std::io::ErrorKind::NotFound),
    ]
}

#[test]
fn messages_are_bilingual_and_non_empty() {
    for err in all_variants() {
        let msg = err.to_string();
        assert!(!msg.trim().is_empty(), "leere Meldung / empty message");
        assert!(
            msg.contains(" / "),
            "nicht zweisprachig / not bilingual: {msg}"
        );
    }
}

#[test]
fn invalid_input_shows_field_name_only() {
    let msg = Error::InvalidInput {
        field: "passphrase",
    }
    .to_string();
    assert!(msg.contains("passphrase"));
}

#[test]
fn io_error_does_not_leak_path() {
    // DE: Der Pfad wird zur Laufzeit erzeugt und darf nicht in der Meldung stehen.
    // EN: The path is generated at runtime and must not appear in the message.
    let dir = std::env::temp_dir().join(format!("pqkeep-missing-{}", std::process::id()));
    let io_err = std::fs::read(&dir).unwrap_err();
    let msg = Error::from(io_err).to_string();
    let dir_str = dir.to_string_lossy();
    assert!(
        !msg.contains(dir_str.as_ref()),
        "Pfad in Meldung / path in message"
    );
    assert!(!msg.contains("pqkeep-missing"));
}

#[test]
fn io_conversion_keeps_kind() {
    let err = Error::from(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    assert_eq!(err, Error::Io(std::io::ErrorKind::PermissionDenied));
}
