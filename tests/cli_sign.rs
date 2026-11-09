//! DE: `pqkeep sign` / `pqkeep verify`: Rundlauf, Manipulation, falscher Schlüssel, falsche
//! Schlüsselart (vor der Passphrase), fehlende Signatur, vorhandenes Ziel, Namen mit führendem `-`,
//! Exit-Codes (0 gültig, 7 ungültig) und ehrliche Hilfe.
//! EN: `pqkeep sign` / `pqkeep verify`: round trip, tampering, wrong key, wrong key type (before
//! the passphrase), missing signature, existing target, names with a leading `-`, exit codes
//! (0 valid, 7 invalid) and honest help.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::Path;

fn pass() -> String {
    format!("{}\n", common::random_passphrase().as_ref().expose_str())
}

fn run(dir: &Path, args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut full = vec!["--lang", "en"];
    full.extend_from_slice(args);
    common::pqkeep(&full, stdin, dir)
}

/// DE: Schlüsselpaar `name.key.json`/`name.pub.json`; liefert die Passphrase.
/// EN: Key pair `name.key.json`/`name.pub.json`; returns the passphrase.
fn key(dir: &Path, name: &str, algorithm: &str) -> String {
    let p = pass();
    let out = format!("{name}.key.json");
    let args = [
        "generate",
        "-a",
        algorithm,
        "--name",
        name,
        "--out",
        &out,
        "--passphrase-stdin",
    ];
    assert_eq!(run(dir, &args, &p).0, 0);
    let public = format!("{name}.pub.json");
    assert_eq!(run(dir, &["export", &out, "-o", &public], "").0, 0);
    p
}

#[test]
fn sign_and_verify_roundtrip_and_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let p = key(dir.path(), "anna", "ml-dsa-87");
    fs::write(dir.path().join("vertrag.pdf"), b"%PDF Vertrag").unwrap();
    let sign = [
        "sign",
        "--key",
        "anna.key.json",
        "--passphrase-stdin",
        "vertrag.pdf",
    ];
    let (code, out, err) = run(dir.path(), &sign, &p);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("vertrag.pdf.pqsig") && out.contains("fingerprint"),
        "{out}"
    );
    let verify = ["verify", "--pub", "anna.pub.json", "vertrag.pdf"];
    let (code, out, _) = run(dir.path(), &verify, "");
    assert_eq!(code, 0, "{out}");
    assert!(out.starts_with("[VERIFIED] ") && out.contains("(anna)") && out.contains("eIDAS"));
    fs::write(dir.path().join("vertrag.pdf"), b"%PDF Vertrag!").unwrap();
    let (code, out, _) = run(dir.path(), &verify, "");
    assert_eq!(code, 7);
    assert!(out.starts_with("[INVALID] "), "{out}");
}

#[test]
fn other_key_is_named_and_wrong_key_types_fail_early() {
    let dir = tempfile::tempdir().unwrap();
    let p = key(dir.path(), "anna", "ml-dsa-87");
    key(dir.path(), "bob", "ml-dsa-87");
    let p65 = key(dir.path(), "carl", "ml-dsa-65");
    key(dir.path(), "kem", "ml-kem-768");
    fs::write(dir.path().join("a.txt"), b"x").unwrap();
    let sign = ["sign", "-k", "anna.key.json", "--passphrase-stdin", "a.txt"];
    assert_eq!(run(dir.path(), &sign, &p).0, 0);
    let (code, out, _) = run(dir.path(), &["verify", "-p", "bob.pub.json", "a.txt"], "");
    assert_eq!(code, 7);
    assert!(out.contains("different key"), "{out}");
    // DE: Falsche Schlüsselart → Abbruch vor der Passphrase (leere Eingabe genügt).
    // EN: Wrong key type → abort before the passphrase (empty input suffices).
    let sign65 = [
        "sign",
        "-k",
        "carl.key.json",
        "--passphrase-stdin",
        "-o",
        "b.pqsig",
        "a.txt",
    ];
    let (code, _, err) = run(dir.path(), &sign65, "");
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("ML-DSA-87"), "{err}");
    let _ = p65;
    let (code, _, _) = run(dir.path(), &["verify", "-p", "kem.pub.json", "a.txt"], "");
    assert_eq!(code, 2);
}

#[test]
fn missing_signature_existing_target_and_custom_paths() {
    let dir = tempfile::tempdir().unwrap();
    let p = key(dir.path(), "anna", "ml-dsa-87");
    fs::write(dir.path().join("-x.txt"), b"x").unwrap();
    let (code, _, _) = run(
        dir.path(),
        &["verify", "-p", "anna.pub.json", "--", "-x.txt"],
        "",
    );
    assert_eq!(code, 1, "fehlende Signatur / missing signature");
    let sign = [
        "sign",
        "-k",
        "anna.key.json",
        "--passphrase-stdin",
        "-o",
        "sig dir.pqsig",
        "--",
        "-x.txt",
    ];
    assert_eq!(run(dir.path(), &sign, &p).0, 0);
    let (code, _, _) = run(dir.path(), &sign, &p);
    assert_eq!(code, 5, "vorhandenes Ziel / existing target");
    let verify = [
        "verify",
        "-p",
        "anna.pub.json",
        "-s",
        "sig dir.pqsig",
        "--",
        "-x.txt",
    ];
    assert_eq!(run(dir.path(), &verify, "").0, 0);
}

#[test]
fn wrong_passphrase_is_a_decrypt_error() {
    let dir = tempfile::tempdir().unwrap();
    key(dir.path(), "anna", "ml-dsa-87");
    fs::write(dir.path().join("a.txt"), b"x").unwrap();
    let sign = ["sign", "-k", "anna.key.json", "--passphrase-stdin", "a.txt"];
    assert_eq!(run(dir.path(), &sign, &pass()).0, 3);
    assert!(!dir.path().join("a.txt.pqsig").exists());
}

#[test]
fn help_is_honest_in_both_languages() {
    let dir = tempfile::tempdir().unwrap();
    for (lang, word) in [("de", "eIDAS"), ("en", "eIDAS")] {
        for cmd in ["sign", "verify"] {
            let (_, out, _) = common::pqkeep(&["--lang", lang, cmd, "--help"], "", dir.path());
            assert!(out.contains(word), "{lang} {cmd}: {out}");
        }
    }
}
