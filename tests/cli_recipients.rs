//! DE: Mehrere Empfänger auf der Kommandozeile (U01, #47): `--to` mehrfach (bis 64), optional mit
//! eigener Passphrase (`--with-passphrase`, auch mit Faktordatei). Jeder Empfänger öffnet die
//! Datei, ein fremder Schlüssel nicht; Doppel, zu viele und falsche Schlüssel werden vor der
//! Passphrase-Abfrage abgelehnt; ein einzelner Empfänger bleibt Format v1.
//! EN: Several recipients on the command line (U01, #47): repeated `--to` (up to 64), optionally
//! with an own passphrase (`--with-passphrase`, also with a factor file). Every recipient opens the
//! file, a foreign key does not; duplicates, too many and wrong keys are rejected before the
//! passphrase prompt; a single recipient stays format v1.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

use pqkeep::crypto::{DsaAlgorithm, KemAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{self, Overwrite};
use pqkeep::files::MAX_RECIPIENTS;

fn run(dir: &Path, args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut full = vec!["--lang", "de"];
    full.extend_from_slice(args);
    common::pqkeep(&full, stdin, dir)
}

/// DE: Schlüssel `name.key.json` + `name.pub.json` (Minimalparameter); liefert die Passphrase
/// als Stdin-Zeile. EN: Key `name.key.json` + `name.pub.json` (minimal parameters); returns the
/// passphrase as a stdin line.
fn key(dir: &Path, algorithm: KeyAlgorithm, name: &str) -> String {
    let (file, pass) = common::key_file(algorithm);
    let key_path = dir.join(format!("{name}.key.json"));
    envelope::save(&file, &key_path, Overwrite::No).unwrap();
    let public = file.public_part().unwrap();
    let pub_path = dir.join(format!("{name}.pub.json"));
    envelope::save_public(&public, &pub_path, Overwrite::No).unwrap();
    format!("{}\n", pass.as_ref().expose_str())
}

fn kem(dir: &Path, name: &str) -> String {
    key(dir, KeyAlgorithm::Kem(KemAlgorithm::MlKem768), name)
}

/// DE: Entschlüsselt `src` nach `out` mit `name.key.json`. EN: Decrypts with `name.key.json`.
fn open(dir: &Path, src: &str, out: &str, name: &str, pass: &str) -> (i32, String) {
    let key = format!("{name}.key.json");
    let args = ["decrypt", src, "-k", &key, "-o", out, "--passphrase-stdin"];
    let (code, _, err) = run(dir, &args, pass);
    (code, err)
}

fn version(dir: &Path, file: &str) -> u16 {
    common::v2_files::version(&std::fs::read(dir.join(file)).unwrap())
}

#[test]
fn u01_two_recipients_each_open_and_a_foreign_key_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let anna = kem(d, "anna");
    let ben = key(d, KeyAlgorithm::Kem(KemAlgorithm::MlKem1024), "ben");
    let fremd = kem(d, "fremd");
    std::fs::write(d.join("a.txt"), b"Inhalt").unwrap();
    let enc = [
        "encrypt",
        "a.txt",
        "--to",
        "anna.pub.json",
        "--to",
        "ben.pub.json",
    ];
    let (code, out, err) = run(d, &enc, "");
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Verschlüsselt"), "{out}");
    assert!(
        err.contains("Empfänger 1/2:") && err.contains("Empfänger 2/2:"),
        "{err}"
    );
    assert_eq!(version(d, "a.txt.pqkf"), 2);
    let (_, shown, _) = run(d, &["inspect", "a.txt.pqkf"], "");
    assert_eq!(shown.matches("Empfänger:").count(), 2, "{shown}");
    assert!(!shown.contains("Passphrase"), "{shown}");

    for (name, pass, out) in [("anna", &anna, "anna.txt"), ("ben", &ben, "ben.txt")] {
        let (code, err) = open(d, "a.txt.pqkf", out, name, pass);
        assert_eq!(code, 0, "{err}");
        assert_eq!(std::fs::read(d.join(out)).unwrap(), b"Inhalt");
    }
    let (code, err) = open(d, "a.txt.pqkf", "fremd.txt", "fremd", &fremd);
    assert_eq!(code, 1);
    assert!(err.contains("nicht unter den Empfängern"), "{err}");
    assert!(!d.join("fremd.txt").exists());
    // DE: Ohne Schlüssel und ohne Passphrase-Zugang geht es nicht. EN: No key, no passphrase slot.
    let (code, _, _) = run(d, &["decrypt", "a.txt.pqkf", "-o", "x.txt"], "");
    assert_ne!(code, 0);
    assert!(!d.join("x.txt").exists());
}

#[test]
fn u01_single_recipient_stays_version_1() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let anna = kem(d, "anna");
    std::fs::write(d.join("a.txt"), b"A").unwrap();
    let (code, _, err) = run(d, &["encrypt", "a.txt", "--to", "anna.pub.json"], "");
    assert_eq!(code, 0, "{err}");
    // DE: Keine Empfängerliste bei nur einem Empfänger. EN: No recipient list for a single one.
    assert!(!err.contains("Empfänger 1/1"), "{err}");
    assert_eq!(version(d, "a.txt.pqkf"), 1);
    assert_eq!(open(d, "a.txt.pqkf", "b.txt", "anna", &anna).0, 0);
}

#[test]
fn u01_recipients_with_own_passphrase_and_factor_file() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let anna = kem(d, "anna");
    assert_eq!(run(d, &["factor", "--out", "a.factor"], "").0, 0);
    std::fs::write(d.join("a.txt"), b"A").unwrap();
    let p = format!("{}\n", common::random_passphrase().as_ref().expose_str());
    let enc = [
        "encrypt",
        "a.txt",
        "--to",
        "anna.pub.json",
        "--with-passphrase",
        "--factor-file",
        "a.factor",
        "--passphrase-stdin",
    ];
    let (code, _, err) = run(d, &enc, &p);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("Empfänger 1/1:"), "{err}");
    assert_eq!(version(d, "a.txt.pqkf"), 2);
    let (_, shown, _) = run(d, &["inspect", "a.txt.pqkf"], "");
    assert!(shown.contains("Faktordatei: erforderlich") && shown.contains("Empfänger:"));

    // DE: Ohne `-k` gilt die Passphrase – sie braucht die Faktordatei.
    // EN: Without `-k` the passphrase is used – it needs the factor file.
    let dec = ["decrypt", "a.txt.pqkf", "-o", "p.txt", "--passphrase-stdin"];
    let (code, _, err) = run(d, &dec, &p);
    assert_eq!(code, 2);
    assert!(err.contains("--factor-file"), "{err}");
    let (code, _, err) = run(d, &[&dec[..], &["--factor-file", "a.factor"]].concat(), &p);
    assert_eq!(code, 0, "{err}");
    assert_eq!(std::fs::read(d.join("p.txt")).unwrap(), b"A");
    // DE: Der Empfänger braucht keine Faktordatei. EN: The recipient needs no factor file.
    let (code, err) = open(d, "a.txt.pqkf", "k.txt", "anna", &anna);
    assert_eq!(code, 0, "{err}");
}

#[test]
fn u01_wrong_recipient_lists_are_rejected_before_anything_is_asked() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    kem(d, "anna");
    key(d, KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa44), "signatur");
    std::fs::copy(d.join("anna.pub.json"), d.join("kopie.pub.json")).unwrap();
    std::fs::write(d.join("a.txt"), b"A").unwrap();
    let cases: [(&[&str], &str); 5] = [
        (
            &["--to", "anna.pub.json", "--to", "kopie.pub.json"],
            "mehrfach",
        ),
        (
            &["--to", "anna.pub.json", "--to", "anna.pub.json"],
            "mehrfach",
        ),
        (
            &["--to", "anna.pub.json", "--to", "signatur.pub.json"],
            "ML-KEM",
        ),
        (&["--to", "signatur.pub.json"], "ML-KEM"),
        (
            &["--to", "anna.pub.json", "--factor-file", "fehlt.factor"],
            "--with-passphrase",
        ),
    ];
    for (extra, expected) in cases {
        let (code, out, err) = run(d, &[&["encrypt", "a.txt"][..], extra].concat(), "");
        assert_eq!(code, 2, "{extra:?}: {err}");
        assert!(err.contains(expected), "{extra:?}: {err}");
        assert!(
            !out.contains("Passphrase") && !err.contains("Passphrase:"),
            "{err}"
        );
    }
    let mut many = vec!["encrypt", "a.txt"];
    for _ in 0..=MAX_RECIPIENTS {
        many.extend(["--to", "anna.pub.json"]);
    }
    let (code, _, err) = run(d, &many, "");
    assert_eq!(code, 2);
    assert!(err.contains("Höchstens 64"), "{err}");
    // DE: `--with-passphrase` nur mit Empfängern. EN: `--with-passphrase` only with recipients.
    assert_eq!(run(d, &["encrypt", "a.txt", "--with-passphrase"], "").0, 2);
    assert!(!d.join("a.txt.pqkf").exists());
}

#[test]
fn u01_sixty_four_recipients_and_each_file_separately() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    // DE: 64 Schlüssel auf beiden Kernen erzeugen. EN: Create 64 keys on both cores.
    let names: Vec<String> = (0..MAX_RECIPIENTS).map(|i| format!("k{i:02}")).collect();
    let passes: Vec<String> = std::thread::scope(|s| {
        let half = names.len() / 2;
        let (a, b) = names.split_at(half);
        let first = s.spawn(|| a.iter().map(|n| kem(d, n)).collect::<Vec<_>>());
        let mut out: Vec<String> = b.iter().map(|n| kem(d, n)).collect();
        let mut all = first.join().unwrap();
        all.append(&mut out);
        all
    });
    std::fs::write(d.join("a.txt"), b"A").unwrap();
    std::fs::write(d.join("b.txt"), b"B").unwrap();
    let publics: Vec<String> = names.iter().map(|n| format!("{n}.pub.json")).collect();
    let mut enc = vec!["encrypt", "a.txt"];
    for p in &publics {
        enc.extend(["--to", p.as_str()]);
    }
    let (code, _, err) = run(d, &enc, "");
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("Empfänger 64/64:"), "{err}");
    let last = MAX_RECIPIENTS - 1;
    let (code, err) = open(d, "a.txt.pqkf", "a64.txt", &names[last], &passes[last]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(std::fs::read(d.join("a64.txt")).unwrap(), b"A");

    // DE: `--each` mit zwei Empfängern: jede Datei für beide. EN: `--each`: each file for both.
    std::fs::remove_file(d.join("a.txt.pqkf")).unwrap();
    let each = [
        "encrypt",
        "a.txt",
        "b.txt",
        "--each",
        "--to",
        &publics[0],
        "--to",
        &publics[1],
    ];
    let (code, _, err) = run(d, &each, "");
    assert_eq!(code, 0, "{err}");
    let (code, err) = open(d, "b.txt.pqkf", "b1.txt", &names[1], &passes[1]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(std::fs::read(d.join("b1.txt")).unwrap(), b"B");
    assert_eq!(open(d, "a.txt.pqkf", "a0.txt", &names[0], &passes[0]).0, 0);
}

#[test]
fn u01_help_in_both_languages() {
    let dir = tempfile::tempdir().unwrap();
    for (lang, words) in [
        (
            "de",
            [
                "bis zu 64 Empfänger",
                "eigene Passphrase",
                "mehrere Empfänger",
            ],
        ),
        (
            "en",
            [
                "up to 64 recipients",
                "own passphrase",
                "several recipients",
            ],
        ),
    ] {
        let (code, out, _) = common::pqkeep(&["--lang", lang, "encrypt", "--help"], "", dir.path());
        assert_eq!(code, 0);
        assert!(out.contains("--with-passphrase"), "{out}");
        for word in words {
            assert!(out.contains(word), "{word}: {out}");
        }
        common::assert_no_secret_like_words(&out, "encrypt --help");
    }
}
