//! DE: Tests (U01, #47): Prüfung der Empfängerliste vor jeder Passphrase-Abfrage, Meldungen und
//! Regeln für `--with-passphrase` und `--factor-file`.
//! EN: Tests (U01, #47): checking the recipient list before any passphrase prompt, messages and
//! rules for `--with-passphrase` and `--factor-file`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use pqkeep::crypto::{DsaAlgorithm, KemAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{KeyFile, Metadata, PublicKeyFile};
use pqkeep::files::MAX_RECIPIENTS;
use pqkeep::security::{Lang, generator};

use super::{check, check_factor, line, message};
use crate::cli::args::build;

fn public(algorithm: KeyAlgorithm) -> PublicKeyFile {
    let params = pqkeep::crypto::kdf::KdfParams {
        memory_kib: pqkeep::crypto::kdf::MIN_MEMORY_KIB,
        iterations: pqkeep::crypto::kdf::MIN_ITERATIONS,
        parallelism: pqkeep::crypto::kdf::auto_parallelism(),
    };
    let pass = generator::generate(&generator::Options::default()).unwrap();
    let meta = Metadata::with_name("Anna Muster");
    let key = KeyFile::generate(&pass, algorithm, &meta, &params).unwrap();
    key.public_part().unwrap()
}

#[test]
fn u01_recipient_list_is_checked() {
    let a = public(KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    let b = public(KeyAlgorithm::Kem(KemAlgorithm::MlKem1024));
    let dsa = public(KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa44));
    assert_eq!(check(&[]), Ok(()));
    assert_eq!(check(&[a.clone(), b.clone()]), Ok(()));
    assert_eq!(check(&[a.clone(), dsa]), Err("recipient_kind"));
    assert_eq!(
        check(&[a.clone(), b, a.clone()]),
        Err("recipient_duplicate")
    );
    let too_many = vec![a; MAX_RECIPIENTS + 1];
    assert_eq!(check(&too_many), Err("recipient_count"));
}

#[test]
fn u01_recipient_line_shows_name_and_fingerprint() {
    let a = public(KeyAlgorithm::Kem(KemAlgorithm::MlKem512));
    let de = line(Lang::De, 0, 2, &a);
    assert!(de.starts_with("Empfänger 1/2: Anna Muster ("), "{de}");
    assert!(de.contains(&a.key_id_hex()[..4]), "{de}");
    assert!(line(Lang::En, 1, 2, &a).starts_with("Recipient 2/2: "));
}

#[test]
fn u01_messages_exist_in_both_languages() {
    for field in [
        "recipient",
        "recipient_kind",
        "recipient_count",
        "recipient_duplicate",
        "factor_needs_passphrase",
    ] {
        let text = message(field).unwrap();
        assert!(text.contains(" / "), "{field}");
    }
    assert_eq!(message("factor"), None);
}

#[test]
fn u01_factor_file_with_recipients_needs_with_passphrase() {
    let ok = |argv: &[&str]| {
        let m = build(Lang::En).try_get_matches_from(argv).unwrap();
        let (_, sub) = m.subcommand().unwrap();
        check_factor(sub, Lang::En).is_ok()
    };
    let base = ["pqkeep", "encrypt", "a.txt"];
    assert!(ok(&[&base[..], &["--factor-file", "f"]].concat()));
    assert!(ok(&[&base[..], &["--to", "k", "--to", "l"]].concat()));
    assert!(!ok(
        &[&base[..], &["--to", "k", "--factor-file", "f"]].concat()
    ));
    let with = ["--to", "k", "--with-passphrase", "--factor-file", "f"];
    assert!(ok(&[&base[..], &with].concat()));
    // DE: `--with-passphrase` ohne Empfänger ist ein Bedienfehler. EN: Without recipients: error.
    let alone = [&base[..], &["--with-passphrase"]].concat();
    assert!(build(Lang::En).try_get_matches_from(alone).is_err());
}
