//! DE: Tests (#85): stabile `kind`-Namen je Exit-Code und Fehlerobjekt.
//! EN: Tests (#85): stable `kind` names per exit code and the error object.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{SCHEMA, error, kind};
use crate::cli::io::{Failure, code};

#[test]
fn kinds_are_stable() {
    let all: Vec<&str> = (0..=8).map(kind).collect();
    assert_eq!(
        all,
        [
            "ok",
            "error",
            "usage",
            "decrypt_failed",
            "weak_passphrase",
            "target_exists",
            "no_windows",
            "invalid_signature",
            "error"
        ]
    );
    assert_eq!(code::INVALID, 7);
    assert_eq!(SCHEMA, "pqkeep-json/1");
}

#[test]
fn error_object_has_code_kind_and_message() {
    let value = error(&Failure::new(3, "falsch"));
    assert_eq!(value["code"], 3);
    assert_eq!(value["kind"], "decrypt_failed");
    assert_eq!(value["message"], "falsch");
}
