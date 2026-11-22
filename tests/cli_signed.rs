//! DE: Absender-Signatur auf der Kommandozeile (#44): `encrypt --sign-with`, `decrypt`/`check`
//! mit `--signer`, Anzeige in `inspect` (ungeprüft) und `--json`, Manipulation (Exit-Code 7),
//! Bedienregel ohne Terminal, falsche Schlüsselarten vor jeder Abfrage, Signaturschlüssel mit
//! Faktordatei, mehrere Quellen. Alles läuft mit der Standard-Sandbox.
//! EN: Sender signature on the command line (#44): `encrypt --sign-with`, `decrypt`/`check` with
//! `--signer`, display in `inspect` (unverified) and `--json`, tampering (exit code 7), the rule
//! without a terminal, wrong key kinds before any prompt, signing key with factor file, several
//! sources. Everything runs with the default sandbox.

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
fn key(dir: &Path, name: &str, algorithm: &str, extra: &[&str]) -> String {
    let p = pass();
    let out = format!("{name}.key.json");
    let mut args = vec!["generate", "-a", algorithm, "--name", name, "--out", &out];
    args.extend_from_slice(extra);
    args.push("--passphrase-stdin");
    assert_eq!(run(dir, &args, &p).0, 0);
    let public = format!("{name}.pub.json");
    assert_eq!(run(dir, &["export", &out, "-o", &public], "").0, 0);
    p
}

/// DE: Anna signiert, Ben empfängt; liefert (Anna-, Ben-Passphrase).
/// EN: Anna signs, Ben receives; returns (Anna's, Ben's passphrase).
fn setup(dir: &Path) -> (String, String) {
    let anna = key(dir, "anna", "ml-dsa-87", &[]);
    let ben = key(dir, "ben", "ml-kem-768", &[]);
    fs::write(dir.join("brief.txt"), b"Hallo Ben").unwrap();
    let args = [
        "encrypt",
        "brief.txt",
        "--to",
        "ben.pub.json",
        "--sign-with",
        "anna.key.json",
        "--passphrase-stdin",
    ];
    let (code, _, err) = run(dir, &args, &anna);
    assert_eq!(code, 0, "{err}");
    (anna, ben)
}

fn anna_id(dir: &Path) -> String {
    let (_, out, _) = run(dir, &["inspect", "anna.pub.json", "--json"], "");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    v["key_id"].as_str().unwrap().to_owned()
}

#[test]
fn signed_roundtrip_names_the_verified_sender() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (_, ben) = setup(d);
    let id = anna_id(d);
    let (code, out, _) = run(d, &["inspect", "brief.txt.pqkf"], "");
    assert_eq!(code, 0);
    assert!(out.contains("Sender (unverified"), "{out}");
    let (_, out, _) = run(d, &["inspect", "brief.txt.pqkf", "--json"], "");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["format_version"], 3);
    assert_eq!(v["signer"]["key_id"], id.as_str());
    assert_eq!(v["signer"]["verified"], false);
    let dec = [
        "decrypt",
        "brief.txt.pqkf",
        "--key",
        "ben.key.json",
        "--signer",
        "anna.pub.json",
        "-o",
        "zurueck.txt",
        "--passphrase-stdin",
    ];
    let (code, out, err) = run(d, &dec, &ben);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Signed by (verified)"), "{out}");
    assert_eq!(fs::read(d.join("zurueck.txt")).unwrap(), b"Hallo Ben");
    let check = [
        "check",
        "brief.txt.pqkf",
        "--key",
        "ben.key.json",
        "--json",
        "--passphrase-stdin",
    ];
    let (code, out, _) = run(d, &check, &ben);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["results"][0]["signer"], id.as_str());
}

#[test]
fn wrong_sender_and_tampering_exit_7_without_output() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (_, ben) = setup(d);
    key(d, "eve", "ml-dsa-87", &[]);
    let base = ["--key", "ben.key.json", "--passphrase-stdin"];
    let check = [
        &["check", "brief.txt.pqkf", "--signer", "eve.pub.json"][..],
        &base,
    ]
    .concat();
    assert_eq!(run(d, &check, &ben).0, 7);
    let mut bytes = fs::read(d.join("brief.txt.pqkf")).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(d.join("kaputt.pqkf"), &bytes).unwrap();
    let dec = [&["decrypt", "kaputt.pqkf", "-o", "k.txt"][..], &base].concat();
    let (code, _, err) = run(d, &dec, &ben);
    assert_eq!(code, 7, "{err}");
    assert!(!d.join("k.txt").exists());
}

#[test]
fn unsigned_file_with_signer_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    key(d, "anna", "ml-dsa-87", &[]);
    let ben = key(d, "ben", "ml-kem-768", &[]);
    fs::write(d.join("a.txt"), b"a").unwrap();
    assert_eq!(
        run(d, &["encrypt", "a.txt", "--to", "ben.pub.json"], "").0,
        0
    );
    let dec = [
        "decrypt",
        "a.txt.pqkf",
        "--key",
        "ben.key.json",
        "--signer",
        "anna.pub.json",
        "--passphrase-stdin",
    ];
    assert_eq!(run(d, &dec, &ben).0, 7);
    assert!(!d.join("a.txt.decrypted").exists() && fs::read(d.join("a.txt")).unwrap() == b"a");
}

#[test]
fn usage_rules_come_before_any_prompt() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let anna = key(d, "anna", "ml-dsa-87", &[]);
    key(d, "ben", "ml-kem-768", &[]);
    fs::write(d.join("a.txt"), b"a").unwrap();
    // DE: Datei-Passphrase und Signaturschlüssel ohne Terminal. EN: File passphrase and signing
    // key without a terminal.
    let both = [
        "encrypt",
        "a.txt",
        "--sign-with",
        "anna.key.json",
        "--passphrase-stdin",
    ];
    let (code, _, err) = run(d, &both, &anna);
    assert_eq!(code, 2);
    assert!(err.contains("--sign-passphrase-file"), "{err}");
    // DE: Falsche Schlüsselarten. EN: Wrong key kinds.
    let kem_sign = [
        "encrypt",
        "a.txt",
        "--to",
        "ben.pub.json",
        "--sign-with",
        "ben.key.json",
    ];
    let (code, _, err) = run(d, &kem_sign, "");
    assert_eq!(code, 2);
    assert!(err.contains("ML-DSA-87"), "{err}");
    assert!(!d.join("a.txt.pqkf").exists());
    // DE: `--signer` mit ML-KEM-Schlüssel an einer echten `.pqkf`. EN: `--signer` with an ML-KEM
    // key on a real `.pqkf`.
    assert_eq!(
        run(d, &["encrypt", "a.txt", "--to", "ben.pub.json"], "").0,
        0
    );
    let kem_signer = ["check", "a.txt.pqkf", "--signer", "ben.pub.json"];
    let (code, _, err) = run(d, &kem_signer, "");
    assert_eq!(code, 2);
    assert!(err.contains("ML-DSA-87"), "{err}");
}

#[test]
fn signing_key_with_factor_file_and_several_sources() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    assert_eq!(run(d, &["factor", "--out", "f.bin"], "").0, 0);
    let anna = key(d, "anna", "ml-dsa-87", &["--factor-file", "f.bin"]);
    key(d, "ben", "ml-kem-768", &[]);
    fs::write(d.join("a.txt"), b"a").unwrap();
    fs::write(d.join("b.txt"), b"b").unwrap();
    let base = [
        "encrypt",
        "a.txt",
        "b.txt",
        "--each",
        "--to",
        "ben.pub.json",
        "--sign-with",
        "anna.key.json",
        "--passphrase-stdin",
    ];
    // DE: Faktordatei fehlt → Bedienfehler vor der Abfrage. EN: Factor file missing → usage error.
    assert_eq!(run(d, &base, &anna).0, 2);
    let with = [&base[..], &["--sign-factor-file", "f.bin"]].concat();
    let (code, _, err) = run(d, &with, &anna);
    assert_eq!(code, 0, "{err}");
    for name in ["a.txt.pqkf", "b.txt.pqkf"] {
        let bytes = fs::read(d.join(name)).unwrap();
        assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), 3, "{name}");
    }
}

/// DE: #286: Datei-Passphrase und Signaturschlüssel ohne Terminal über `--sign-passphrase-file`.
/// EN: #286: file passphrase and signing key without a terminal via `--sign-passphrase-file`.
// DE: Rechteprüfung gibt es nur unter Linux. EN: Permission checks exist on Linux only.
#[cfg(target_os = "linux")]
#[test]
fn sign_passphrase_file_enables_batch_signing() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let anna = key(d, "anna", "ml-dsa-87", &[]);
    key(d, "eve", "ml-dsa-87", &[]);
    fs::write(d.join("a.txt"), b"geheim").unwrap();
    let file_pass = pass();
    for (name, text) in [("file.pass", &file_pass), ("sign.pass", &anna)] {
        fs::write(d.join(name), text).unwrap();
        fs::set_permissions(d.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let enc = [
        "--batch",
        "--passphrase-file",
        "file.pass",
        "encrypt",
        "a.txt",
        "--sign-with",
        "anna.key.json",
        "--sign-passphrase-file",
        "sign.pass",
    ];
    let (code, out, err) = run(d, &enc, "");
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("a.txt.pqkf"), "{out}");
    let check = [
        "--batch",
        "--passphrase-file",
        "file.pass",
        "check",
        "a.txt.pqkf",
        "--signer",
        "anna.pub.json",
    ];
    assert_eq!(run(d, &check, "").0, 0);
    let other = [&check[..6], &["eve.pub.json"]].concat();
    assert_eq!(run(d, &other, "").0, 7);
    // DE: Zu offene Rechte → Bedienfehler, nichts geschrieben. EN: Too open permissions → usage error.
    fs::remove_file(d.join("a.txt.pqkf")).unwrap();
    fs::set_permissions(d.join("sign.pass"), fs::Permissions::from_mode(0o644)).unwrap();
    let (code, _, err) = run(d, &enc, "");
    assert_eq!(code, 2, "{err}");
    assert!(!d.join("a.txt.pqkf").exists());
    // DE: Nur zusammen mit `--sign-with`. EN: Only together with `--sign-with`.
    let lone = ["encrypt", "a.txt", "--sign-passphrase-file", "sign.pass"];
    assert_eq!(run(d, &lone, "").0, 2);
}

/// DE: #287: So liefert das Kontextmenü beide Passphrasen über eine Pipe – neue Datei-Passphrase
/// (zwei Zeilen), danach die des Signaturschlüssels. EN: #287: this is how the context menu delivers
/// both passphrases through one pipe – new file passphrase (two lines), then the signing key's.
#[test]
fn context_pipe_delivers_file_and_signing_passphrases() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let anna = key(d, "anna", "ml-dsa-87", &[]);
    fs::write(d.join("a.txt"), b"geheim").unwrap();
    let file_pass = pass();
    let stdin = format!("{file_pass}{file_pass}{anna}");
    let enc = [
        "encrypt",
        "--sign-with",
        "anna.key.json",
        "--passphrase-stdin",
        "--confirm-stdin",
        "--sign-passphrase-next-line",
        "--",
        "a.txt",
    ];
    let (code, _, err) = run(d, &enc, &stdin);
    assert_eq!(code, 0, "{err}");
    let check = [
        "check",
        "a.txt.pqkf",
        "--signer",
        "anna.pub.json",
        "--passphrase-stdin",
    ];
    let (code, out, _) = run(d, &check, &file_pass);
    assert_eq!(code, 0);
    assert!(out.contains("Signed by (verified)"), "{out}");
    // DE: Abweichende Wiederholung → nichts geschrieben. EN: Mismatching repeat → nothing written.
    fs::remove_file(d.join("a.txt.pqkf")).unwrap();
    let wrong = format!("{file_pass}{}{anna}", pass());
    assert_ne!(run(d, &enc, &wrong).0, 0);
    assert!(!d.join("a.txt.pqkf").exists());
}
