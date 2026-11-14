//! DE: `encrypt --json` und `decrypt --json` (#85, zweiter Teil): ein Objekt mit `results` und
//! `summary`, Fehler des ganzen Befehls als `error`, Teilfehler je Eintrag; keine Geheimnisse.
//! EN: `encrypt --json` and `decrypt --json` (#85, second part): one object with `results` and
//! `summary`, errors of the whole command as `error`, partial failures per entry; no secrets.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

use pqkeep::crypto::{KemAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{self, Overwrite};
use serde_json::Value;

/// DE: Führt pqkeep aus und liest stdout als JSON; prüft Hülle und Exit-Code.
/// EN: Runs pqkeep and parses stdout as JSON; checks envelope and exit code.
fn json(dir: &Path, args: &[&str], stdin: &str) -> (i32, Value) {
    let mut full = vec!["--lang", "en"];
    full.extend_from_slice(args);
    full.push("--json");
    let (code, out, err) = common::pqkeep(&full, stdin, dir);
    assert!(out.trim_start().starts_with('{'), "{out}\n{err}");
    let value: Value = serde_json::from_str(&out).expect("JSON");
    assert_eq!(out.trim().lines().count(), 1, "{out}");
    assert_eq!(value["schema"], "pqkeep-json/1");
    assert_eq!(value["command"], args[0]);
    assert_eq!(value["exit_code"], code, "{value}");
    assert_eq!(value["ok"], code == 0);
    (code, value)
}

/// DE: Empfängerschlüssel „anna“ anlegen; liefert die Passphrase-Zeile.
/// EN: Creates recipient key "anna"; returns the passphrase line.
fn anna(d: &Path) -> String {
    let (file, pass) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    envelope::save(&file, &d.join("anna.key.json"), Overwrite::No).unwrap();
    let public = file.public_part().unwrap();
    envelope::save_public(&public, &d.join("anna.pub.json"), Overwrite::No).unwrap();
    format!("{}\n", pass.as_ref().expose_str())
}

#[test]
fn encrypt_and_decrypt_single_file() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let pass = anna(d);
    std::fs::write(d.join("a.txt"), b"Inhalt").unwrap();
    let (code, v) = json(d, &["encrypt", "a.txt", "--to", "anna.pub.json"], "");
    assert_eq!(code, 0, "{v}");
    let r = &v["results"][0];
    assert_eq!(r["source"], "a.txt");
    assert_eq!(r["target"], "a.txt.pqkf");
    assert_eq!(
        (r["files"].as_u64(), r["bytes"].as_u64()),
        (Some(1), Some(6))
    );
    assert_eq!(r["skipped"], 0);
    assert_eq!(v["summary"]["total"], 1);

    // DE: Ziel existiert: Fehler des ganzen Befehls. EN: Target exists: error of the whole command.
    let (code, v) = json(d, &["encrypt", "a.txt", "--to", "anna.pub.json"], "");
    assert_eq!(code, 5);
    assert_eq!(v["error"]["kind"], "target_exists");
    assert!(v.get("results").is_none());

    let args = [
        "decrypt",
        "a.txt.pqkf",
        "-k",
        "anna.key.json",
        "--out",
        "b.txt",
        "--passphrase-stdin",
    ];
    let (code, v) = json(d, &args, &pass);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["results"][0]["target"], "b.txt");
    assert_eq!(std::fs::read(d.join("b.txt")).unwrap(), b"Inhalt");
    assert!(!v.to_string().contains(pass.trim()));
}

#[test]
fn each_and_many_report_per_file() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let pass = anna(d);
    for name in ["a.txt", "b.txt"] {
        std::fs::write(d.join(name), name).unwrap();
    }
    std::fs::write(d.join("b.txt.pqkf"), b"belegt").unwrap();
    let args = [
        "encrypt",
        "a.txt",
        "b.txt",
        "--each",
        "--to",
        "anna.pub.json",
    ];
    let (code, v) = json(d, &args, "");
    assert_eq!(code, 5, "{v}");
    assert_eq!(v["results"][0]["ok"], true);
    assert_eq!(v["results"][1]["error"]["kind"], "target_exists");
    assert_eq!(
        (v["summary"]["ok"].as_u64(), v["summary"]["failed"].as_u64()),
        (Some(1), Some(1))
    );

    // DE: b neu verschlüsseln; beim Entschlüsseln existiert b.txt noch, a.txt nicht mehr.
    // EN: Re-encrypt b; when decrypting b.txt still exists, a.txt no longer.
    std::fs::remove_file(d.join("b.txt.pqkf")).unwrap();
    let (code, _) = json(d, &["encrypt", "b.txt", "--to", "anna.pub.json"], "");
    assert_eq!(code, 0);
    std::fs::remove_file(d.join("a.txt")).unwrap();
    let args = [
        "decrypt",
        "a.txt.pqkf",
        "b.txt.pqkf",
        "-k",
        "anna.key.json",
        "--passphrase-stdin",
    ];
    let (code, v) = json(d, &args, &pass);
    assert_eq!(code, 5, "{v}");
    assert_eq!(v["results"][0]["target"], "a.txt");
    assert_eq!(v["results"][1]["error"]["kind"], "target_exists");
    assert_eq!(std::fs::read(d.join("a.txt")).unwrap(), b"a.txt");
}

#[test]
fn container_lists_all_sources() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    anna(d);
    std::fs::write(d.join("a.txt"), b"A").unwrap();
    common::write_sample_tree(&d.join("baum"));
    let args = [
        "encrypt",
        "a.txt",
        "baum",
        "--out",
        "c.pqkf",
        "--to",
        "anna.pub.json",
    ];
    let (code, v) = json(d, &args, "");
    assert_eq!(code, 0, "{v}");
    let r = &v["results"][0];
    assert_eq!(r["source"], serde_json::json!(["a.txt", "baum"]));
    assert_eq!(r["target"], "c.pqkf");
    assert!(r["files"].as_u64().unwrap() > 1);

    // DE: Ohne --out/--each: Bedienfehler als JSON. EN: Without --out/--each: usage error as JSON.
    let (code, v) = json(
        d,
        &["encrypt", "a.txt", "baum", "--to", "anna.pub.json"],
        "",
    );
    assert_eq!(code, 2);
    assert_eq!(v["error"]["kind"], "usage");
}

#[test]
fn weak_passphrase_has_a_message() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("a.txt"), b"A").unwrap();
    let (code, v) = json(d, &["encrypt", "a.txt", "--passphrase-stdin"], "abc\n");
    assert_eq!(code, 4);
    assert_eq!(v["error"]["kind"], "weak_passphrase");
    assert_eq!(v["error"]["message"], "Passphrase rejected");
    assert!(!d.join("a.txt.pqkf").exists());
}
