//! DE: Kommandozeile `encrypt --anonymous-recipients` (experimentell, #316/#340): Warnung, nur
//! ML-KEM-1024, `inspect` ohne ID, Entschlüsseln mit Schlüssel und fremdem Schlüssel.
//! EN: Command line `encrypt --anonymous-recipients` (experimental, #316/#340): warning,
//! ML-KEM-1024 only, `inspect` without ID, decrypting with own and foreign key.

// DE: Tests dürfen unwrap/expect nutzen. EN: Tests may use unwrap/expect.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::Path;

fn run(dir: &Path, args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut full = vec!["--lang", "en"];
    full.extend_from_slice(args);
    common::pqkeep(&full, stdin, dir)
}

fn key(dir: &Path, name: &str, algorithm: &str) -> String {
    let p = format!("{}\n", common::random_passphrase().as_ref().expose_str());
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
fn anonymous_recipients_on_the_command_line() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let anna = key(d, "anna", "ml-kem-1024");
    let ben = key(d, "ben", "ml-kem-1024");
    let _ = key(d, "carl", "ml-kem-768");
    fs::write(d.join("a.txt"), b"anonym").unwrap();
    let base = ["encrypt", "--anonymous-recipients", "--to", "anna.pub.json"];
    // DE: ML-KEM-768 wird vor jeder Arbeit abgewiesen. EN: ML-KEM-768 is rejected up front.
    let mixed = [&base[..], &["--to", "carl.pub.json", "--", "a.txt"]].concat();
    let (code, _, err) = run(d, &mixed, "");
    assert_eq!(code, 2, "{err}");
    assert!(!d.join("a.txt.pqkf").exists());
    let ok = [&base[..], &["--to", "ben.pub.json", "--", "a.txt"]].concat();
    let (code, _, err) = run(d, &ok, "");
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("EXPERIMENTAL"), "{err}");
    let (_, shown, _) = run(d, &["inspect", "a.txt.pqkf"], "");
    assert_eq!(
        shown.matches("anonymous, ML-KEM-1024").count(),
        2,
        "{shown}"
    );
    let (_, json, _) = run(d, &["inspect", "--json", "a.txt.pqkf"], "");
    assert!(
        json.contains("anonymous_recipient") && !json.contains("recipient_id"),
        "{json}"
    );
    for (name, pass) in [("anna", &anna), ("ben", &ben)] {
        let out = format!("{name}.txt");
        let k = format!("{name}.key.json");
        let args = [
            "decrypt",
            "a.txt.pqkf",
            "-k",
            &k,
            "-o",
            &out,
            "--passphrase-stdin",
        ];
        let (code, _, err) = run(d, &args, pass);
        assert_eq!(code, 0, "{err}");
        assert_eq!(fs::read(d.join(&out)).unwrap(), b"anonym");
    }
}
