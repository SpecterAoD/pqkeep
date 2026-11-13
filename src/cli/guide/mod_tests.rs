#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::signing::sign_args;
use super::{command_line, quote, wanted};
use crate::cli::args::build;
use pqkeep::security::Lang;

#[test]
fn quoting_for_display() {
    assert_eq!(quote("ml-kem-1024"), "ml-kem-1024");
    assert_eq!(quote("Anna Muster"), "'Anna Muster'");
    assert_eq!(quote("O'Neil"), r"'O'\''Neil'");
    assert_eq!(quote(""), "''");
    let args = ["generate".to_owned(), "--name".to_owned(), "A B".to_owned()];
    assert_eq!(command_line(&args), "pqkeep generate --name 'A B'");
}

/// DE: U01: Geführtes Signieren gibt die Faktordatei nur weiter, wenn eine gewählt wurde.
/// EN: U01: guided signing passes the factor file on only if one was chosen.
#[test]
fn u01_sign_arguments_with_and_without_factor_file() {
    assert_eq!(
        sign_args("k.key.json", None, "a.sig", "a.pdf"),
        [
            "sign",
            "--key",
            "k.key.json",
            "--out",
            "a.sig",
            "--",
            "a.pdf"
        ]
    );
    assert_eq!(
        sign_args("k.key.json", Some("/usb/k.factor"), "a.sig", "-a.pdf"),
        [
            "sign",
            "--key",
            "k.key.json",
            "--factor-file",
            "/usb/k.factor",
            "--out",
            "a.sig",
            "--",
            "-a.pdf"
        ]
    );
}

#[test]
fn never_wanted_without_a_terminal() {
    // DE: Testprozesse haben kein Terminal. EN: Test processes have no terminal.
    for argv in [
        &["pqkeep", "generate"][..],
        &["pqkeep", "sign"],
        &["pqkeep", "verify"],
    ] {
        let m = build(Lang::En).try_get_matches_from(argv).unwrap();
        let (name, sub) = m.subcommand().unwrap();
        assert!(!wanted(name, sub), "{argv:?}");
    }
}
