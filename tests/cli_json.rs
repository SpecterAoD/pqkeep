//! DE: `--json` (#85) für `check`, `inspect`, `verify`: genau ein JSON-Objekt auf stdout mit
//! Schema `pqkeep-json/1`, `exit_code` gleich dem echten Exit-Code, gültiges JSON auch bei
//! Fehlern, keine Geheimnisse, Hilfe DE/EN mit allen Exit-Codes.
//! EN: `--json` (#85) for `check`, `inspect`, `verify`: exactly one JSON object on stdout with
//! schema `pqkeep-json/1`, `exit_code` equal to the real exit code, valid JSON even on errors, no
//! secrets, help DE/EN with all exit codes.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

use pqkeep::crypto::{DsaAlgorithm, KemAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{self, Overwrite};
use pqkeep::files::{self, PassphraseAccess, Protection};
use serde_json::Value;

/// DE: Führt pqkeep aus und liest stdout als JSON; prüft Hülle und Exit-Code.
/// EN: Runs pqkeep and parses stdout as JSON; checks envelope and exit code.
fn json(dir: &Path, args: &[&str], stdin: &str) -> (i32, Value, String) {
    let mut full = vec!["--lang", "en"];
    full.extend_from_slice(args);
    full.push("--json");
    let (code, out, err) = common::pqkeep(&full, stdin, dir);
    let value: Value = serde_json::from_str(&out).expect(&out);
    assert_eq!(out.trim().lines().count(), 1, "{out}");
    assert_eq!(value["schema"], "pqkeep-json/1");
    assert_eq!(value["exit_code"], code, "{value}");
    assert_eq!(value["ok"], code == 0);
    (code, value, err)
}

/// DE: Schlüssel speichern (Minimalparameter); liefert die Passphrase-Zeile.
/// EN: Saves a key (minimal parameters); returns the passphrase line.
fn key(d: &Path, algorithm: KeyAlgorithm, name: &str) -> String {
    let (file, pass) = common::key_file(algorithm);
    envelope::save(&file, &d.join(format!("{name}.key.json")), Overwrite::No).unwrap();
    let public = file.public_part().unwrap();
    let path = d.join(format!("{name}.pub.json"));
    envelope::save_public(&public, &path, Overwrite::No).unwrap();
    format!("{}\n", pass.as_ref().expose_str())
}

#[test]
fn check_reports_each_file_and_the_summary() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let pass = common::random_passphrase();
    let protection = Protection::Passphrase {
        passphrase: &pass,
        params: common::min_params(),
    };
    std::fs::write(d.join("a.txt"), b"abc").unwrap();
    files::encrypt(&d.join("a.txt"), &d.join("a.pqkf"), &protection).unwrap();
    std::fs::write(d.join("kaputt.pqkf"), b"nope").unwrap();
    let p = format!("{}\n", pass.as_ref().expose_str());
    let args = [
        "check",
        "a.pqkf",
        "kaputt.pqkf",
        "fehlt.pqkf",
        "--passphrase-stdin",
    ];
    let (code, v, _) = json(d, &args, &p);
    assert_eq!(code, 1);
    assert_eq!(v["command"], "check");
    let results = v["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0]["ok"], true);
    assert_eq!(results[0]["bytes"], 3);
    assert_eq!(results[1]["error"]["kind"], "error");
    assert_eq!(v["summary"]["failed"], 2);
    assert!(!v.to_string().contains(pass.as_ref().expose_str()));
    // DE: Falsche Passphrase: decrypt_failed, Exit 3. EN: Wrong passphrase: exit 3.
    let wrong = format!("{}\n", common::random_passphrase().as_ref().expose_str());
    let (code, v, _) = json(d, &["check", "a.pqkf", "--passphrase-stdin"], &wrong);
    assert_eq!(code, 3);
    assert_eq!(v["results"][0]["error"]["kind"], "decrypt_failed");
    // DE: Früher Fehler (Sandbox: Schlüssel fehlt) ebenfalls als JSON.
    // EN: Early error (sandbox: key missing) as JSON too.
    let (code, v, _) = json(d, &["check", "a.pqkf", "-k", "fehlt.key.json"], "");
    assert_eq!(code, 1);
    assert_eq!(v["error"]["kind"], "error");
}

#[test]
fn inspect_keys_and_encrypted_files() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    key(d, KeyAlgorithm::Kem(KemAlgorithm::MlKem768), "anna");
    let (_, v, _) = json(d, &["inspect", "anna.pub.json"], "");
    assert_eq!(v["type"], "public_key");
    assert_eq!(v["algorithm"], "ML-KEM-768");
    assert_eq!(v["metadata"]["name"], "Test User");
    let (_, v, _) = json(d, &["inspect", "anna.key.json"], "");
    assert_eq!(v["type"], "key_file");
    assert_eq!(v["factor_required"], false);
    assert!(v["kdf"]["memory_kib"].as_u64().unwrap() > 0);
    assert!(v.get("secret").is_none() && !v.to_string().contains("seed"));

    // DE: v2 mit Passphrase + Faktordatei und Empfänger. EN: v2 with passphrase + factor + recipient.
    let pass = common::random_passphrase();
    let factor = common::v2_files::factor();
    let public = envelope::load_public(&d.join("anna.pub.json")).unwrap();
    let protection = Protection::Slots {
        passphrase: Some(PassphraseAccess {
            passphrase: &pass,
            params: common::min_params(),
            factor: Some(&factor),
        }),
        recipients: &[&public],
    };
    common::write_sample_tree(&d.join("baum"));
    files::encrypt(&d.join("baum"), &d.join("baum.pqkf"), &protection).unwrap();
    let (code, v, _) = json(d, &["inspect", "baum.pqkf"], "");
    assert_eq!(code, 0);
    assert_eq!(v["format_version"], 2);
    assert_eq!(v["content"], "directory");
    let slots = v["slots"].as_array().unwrap();
    assert_eq!(slots.len(), 2);
    assert_eq!(slots[0]["factor_required"], true);
    assert_eq!(slots[1]["recipient_id"], public.key_id_hex());

    let (code, v, _) = json(d, &["inspect", "fehlt.pqkf"], "");
    assert_eq!(code, 1);
    assert_eq!(v["error"]["code"], 1);
}

#[test]
fn verify_valid_and_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let p = key(d, KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87), "sig");
    std::fs::write(d.join("vertrag.txt"), b"Vertrag").unwrap();
    let sign = [
        "sign",
        "vertrag.txt",
        "-k",
        "sig.key.json",
        "--passphrase-stdin",
    ];
    let (code, _, err) = common::pqkeep(&sign, &p, d);
    assert_eq!(code, 0, "{err}");
    let verify = ["verify", "vertrag.txt", "-p", "sig.pub.json"];
    let (code, v, _) = json(d, &verify, "");
    assert_eq!(code, 0);
    assert_eq!(v["valid"], true);
    assert_eq!(v["signer"]["name"], "Test User");
    std::fs::write(d.join("vertrag.txt"), b"Vertrag!").unwrap();
    let (code, v, _) = json(d, &verify, "");
    assert_eq!(code, 7);
    assert_eq!(v["valid"], false);
    assert_eq!(v["signer_matches"], true);
    // DE: Ohne Pflichtangaben: Bedienfehler als JSON. EN: Missing input: usage error as JSON.
    let (code, v, _) = json(d, &["verify", "vertrag.txt"], "");
    assert_eq!(code, 2);
    assert_eq!(v["error"]["kind"], "usage");
}

#[test]
fn help_lists_json_and_all_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    for (lang, words) in [
        (
            "de",
            [
                "--json",
                "pqkeep-json/1",
                "7  Signatur ungültig",
                "6  keine Fenster",
            ],
        ),
        (
            "en",
            [
                "--json",
                "pqkeep-json/1",
                "7  invalid signature",
                "6  no windows",
            ],
        ),
    ] {
        for cmd in ["check", "inspect", "verify", "encrypt", "decrypt"] {
            let (_, out, _) = common::pqkeep(&["--lang", lang, cmd, "--help"], "", dir.path());
            for word in words {
                assert!(out.contains(word), "{cmd} {word}: {out}");
            }
        }
    }
    // DE: Befehle ohne `--json`: Bedienfehler. EN: Commands without `--json`: usage error.
    let (code, ..) = common::pqkeep(&["generate", "--json"], "", dir.path());
    assert_eq!(code, 2);
}
