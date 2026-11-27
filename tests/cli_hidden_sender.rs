//! DE: Verborgener Absender auf der Kommandozeile (#316 Schritt 5): `--hide-sender` ohne
//! `--sign-with` ist ein Bedienfehler (Exit 2); `inspect` zeigt „Absender verborgen“ ohne Schlüssel-ID,
//! `--json` mit `hidden`; `decrypt --signer` passend (0) bzw. fremd (7, ohne Ausgabe);
//! `--privacy high --sign-with` verbirgt den Absender.
//! EN: Hidden sender on the command line (#316 step 5): `--hide-sender` without `--sign-with` is a
//! usage error (exit 2); `inspect` shows "sender hidden" without key ID, `--json` with `hidden`;
//! `decrypt --signer` matching (0) or foreign (7, no output); `--privacy high --sign-with` hides the
//! sender.

// DE: Tests dürfen unwrap/expect nutzen. EN: Tests may use unwrap/expect.
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

fn encrypt(dir: &Path, extra: &[&str], stdin: &str) -> (i32, String, String) {
    let base = ["encrypt", "brief.txt", "--to", "ben.pub.json"];
    let args = [&base[..], extra, &["--passphrase-stdin"]].concat();
    run(dir, &args, stdin)
}

fn decrypt(dir: &Path, file: &str, signer: &str, ben: &str) -> (i32, String, String) {
    let _ = fs::remove_file(dir.join("zurueck.txt"));
    let args = [
        "decrypt",
        file,
        "--key",
        "ben.key.json",
        "--signer",
        signer,
        "-o",
        "zurueck.txt",
        "--passphrase-stdin",
    ];
    run(dir, &args, ben)
}

#[test]
fn hidden_sender_roundtrip_inspect_and_wrong_sender() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let anna = key(d, "anna", "ml-dsa-87");
    let ben = key(d, "ben", "ml-kem-768");
    key(d, "eve", "ml-dsa-87");
    fs::write(d.join("brief.txt"), b"Hallo Ben").unwrap();
    // DE: Ohne --sign-with: Bedienfehler, nichts erzeugt. EN: Without --sign-with: usage error.
    let (code, _, err) = encrypt(d, &["--hide-sender"], "");
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("--sign-with"), "{err}");
    assert!(!d.join("brief.txt.pqkf").exists());
    let extra = ["--sign-with", "anna.key.json", "--hide-sender"];
    let (code, _, err) = encrypt(d, &extra, &anna);
    assert_eq!(code, 0, "{err}");
    let (code, out, _) = run(d, &["inspect", "brief.txt.pqkf"], "");
    assert_eq!(code, 0);
    assert!(out.contains("sender hidden"), "{out}");
    assert!(!out.contains("Sender (unverified"), "{out}");
    let (_, out, _) = run(d, &["inspect", "brief.txt.pqkf", "--json"], "");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["format_version"], 4);
    assert_eq!(v["signer"]["hidden"], true);
    assert!(v["signer"]["key_id"].is_null());
    let (code, out, err) = decrypt(d, "brief.txt.pqkf", "anna.pub.json", &ben);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Signed by (verified)"), "{out}");
    assert_eq!(fs::read(d.join("zurueck.txt")).unwrap(), b"Hallo Ben");
    let (code, _, _) = decrypt(d, "brief.txt.pqkf", "eve.pub.json", &ben);
    assert_eq!(code, 7);
    assert!(!d.join("zurueck.txt").exists());
}

#[test]
fn privacy_high_hides_the_sender_when_signing() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let anna = key(d, "anna", "ml-dsa-87");
    key(d, "ben", "ml-kem-768");
    fs::write(d.join("brief.txt"), b"Hallo Ben").unwrap();
    let extra = ["--sign-with", "anna.key.json", "--privacy", "high"];
    let (code, _, err) = encrypt(d, &extra, &anna);
    assert_eq!(code, 0, "{err}");
    let made: Vec<String> = common::dir_names(d)
        .into_iter()
        .filter(|n| Path::new(n).extension().is_some_and(|e| e == "pqkf"))
        .collect();
    assert_eq!(made.len(), 1, "{made:?}");
    let (_, out, _) = run(d, &["inspect", &made[0], "--json"], "");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["signer"]["hidden"], true, "{out}");
}
