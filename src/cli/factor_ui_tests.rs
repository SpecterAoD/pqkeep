//! DE: Tests (U01): Menü und Kontextmenü fragen beim Entschlüsseln genau nach dem, was die Datei
//! bzw. die Schlüsseldatei verlangt – nie nach einer unnötigen Faktordatei, nie ohne die nötige.
//! EN: Tests (U01): when decrypting, menu and context menu ask exactly for what the file or the
//! key file requires – never for an unneeded factor file, never without the needed one.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use pqkeep::crypto::factor::Factor;
use pqkeep::crypto::kdf::{self, KdfParams};
use pqkeep::crypto::{DsaAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{self, KeyFile, Metadata, Overwrite};
use pqkeep::security::generator;

use super::{Ask, Extra, key_needs, plan};
use crate::cli::unlock::Access;

/// DE: Führt `plan` aus und merkt sich die Fragen. EN: Runs `plan` and records the questions.
fn run(passphrase: Option<bool>, recipient: bool, key_factor: bool) -> (Extra, Vec<Ask>) {
    let access = Access {
        passphrase,
        recipient,
    };
    let mut asked = Vec::new();
    let extra = plan(
        access,
        |key| {
            assert_eq!(key, Path::new("/k/eigen.key.json"));
            key_factor
        },
        |what| {
            asked.push(what);
            Ok(match what {
                Ask::Key => "/k/eigen.key.json",
                Ask::Factor => "/usb/a.factor",
            }
            .to_owned())
        },
    )
    .ok()
    .unwrap();
    (extra, asked)
}

#[test]
fn u01_passphrase_file_without_factor_asks_nothing() {
    let (extra, asked) = run(Some(false), false, true);
    assert_eq!(extra, Extra::default());
    assert_eq!(asked, []);
}

#[test]
fn u01_passphrase_file_with_factor_asks_for_the_factor_file() {
    let (extra, asked) = run(Some(true), false, false);
    assert_eq!(extra.args, ["--factor-file", "/usb/a.factor"]);
    assert!(!extra.key);
    assert_eq!(asked, [Ask::Factor]);
}

#[test]
fn u01_recipient_file_asks_for_the_key_and_its_factor_only_if_needed() {
    let (extra, asked) = run(None, true, false);
    assert_eq!(extra.args, ["--key", "/k/eigen.key.json"]);
    assert!(extra.key);
    assert_eq!(asked, [Ask::Key]);

    let (extra, asked) = run(None, true, true);
    assert_eq!(
        extra.refs(),
        [
            "--key",
            "/k/eigen.key.json",
            "--factor-file",
            "/usb/a.factor"
        ]
    );
    assert_eq!(asked, [Ask::Key, Ask::Factor]);
}

/// DE: Datei mit beiden Zugängen: ohne `--key` gilt die Passphrase (wie bei `decrypt`).
/// EN: File with both slots: without `--key` the passphrase is used (as with `decrypt`).
#[test]
fn u01_file_with_both_slots_uses_the_passphrase() {
    let (extra, asked) = run(Some(true), true, false);
    assert_eq!(extra.args, ["--factor-file", "/usb/a.factor"]);
    assert_eq!(asked, [Ask::Factor]);
}

#[test]
fn u01_cancelling_a_question_stops() {
    let access = Access {
        passphrase: Some(true),
        recipient: false,
    };
    let cancelled = plan(
        access,
        |_| false,
        |_| Err(crate::cli::io::Failure::new(2, "")),
    );
    assert!(cancelled.is_err());
}

#[test]
fn u01_key_file_version_decides_about_the_factor_file() {
    let dir = tempfile::tempdir().unwrap();
    let params = KdfParams {
        memory_kib: kdf::MIN_MEMORY_KIB,
        iterations: kdf::MIN_ITERATIONS,
        parallelism: kdf::auto_parallelism(),
    };
    let pass = generator::generate(&generator::Options::default()).unwrap();
    let alg = KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa44);
    let meta = Metadata::with_name("Test");
    let factor_path = dir.path().join("a.factor");
    Factor::create(&factor_path).unwrap();
    let factor = Factor::read(&factor_path).unwrap();

    let v1 = dir.path().join("v1.key.json");
    let key = KeyFile::generate(&pass, alg, &meta, &params).unwrap();
    envelope::save(&key, &v1, Overwrite::No).unwrap();
    let v2 = dir.path().join("v2.key.json");
    let key = KeyFile::generate_with_factor(&pass, &factor, alg, &meta, &params).unwrap();
    envelope::save(&key, &v2, Overwrite::No).unwrap();

    assert!(!key_needs(&v1));
    assert!(key_needs(&v2));
    // DE: Nicht lesbar oder keine Schlüsseldatei: nicht fragen, der Befehl meldet den Fehler.
    // EN: Unreadable or not a key file: do not ask, the command reports the error.
    assert!(!key_needs(&dir.path().join("fehlt.key.json")));
    assert!(!key_needs(&factor_path));
}
