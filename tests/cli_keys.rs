//! DE: CLI-Schlüsselbefehle: generate → inspect → export → Entsperren; Exit-Codes
//! für schwache Passphrase, vorhandenes Ziel, fehlende Datei; Überschreiben nur mit
//! --force --yes. Passphrasen kommen über Stdin (nie als Argument).
//! EN: CLI key commands: generate → inspect → export → unlock; exit codes for
//! weak passphrase, existing target, missing file; overwriting only with
//! --force --yes. Passphrases come via stdin (never as an argument).

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use pqkeep::envelope;
use pqkeep::security::Passphrase;

fn new_pass() -> String {
    common::random_passphrase().as_ref().expose_str().to_owned()
}

/// DE: Erzeugt per CLI einen ML-DSA-65-Schlüssel „max.key.json“. EN: Generates an ML-DSA-65 key via CLI.
fn generate_max(dir: &std::path::Path, pass: &str) -> (String, String) {
    let args = [
        "--lang",
        "de",
        "generate",
        "--name",
        "Max Muster",
        "--organization",
        "Beispiel AG",
        "--algorithm",
        "ml-dsa-65",
        "--out",
        "max.key.json",
        "--passphrase-stdin",
    ];
    let (code, out, err) = common::pqkeep(&args, &format!("{pass}\n"), dir);
    assert_eq!(code, 0, "{err}");
    (out, err)
}

#[test]
fn generate_and_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let pass = new_pass();
    let (out, err) = generate_max(dir.path(), &pass);
    assert!(out.contains("Schlüssel gespeichert") && out.contains("ML-DSA-65"));
    assert!(err.contains("nicht verschlüsselt"));
    let (key, _) = envelope::load(&dir.path().join("max.key.json")).unwrap();
    let unlocked = key.unlock(&Passphrase::new(&pass).unwrap()).unwrap();
    assert_eq!(unlocked.public_key, key.public_key());
}

#[test]
fn inspect_shows_metadata_not_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let pass = new_pass();
    generate_max(dir.path(), &pass);
    let (code, out, _) =
        common::pqkeep(&["--lang", "en", "inspect", "max.key.json"], "", dir.path());
    assert_eq!(code, 0);
    for expected in [
        "Key file",
        "ML-DSA-65",
        "Max Muster",
        "Beispiel AG",
        "m=262144 KiB",
    ] {
        assert!(out.contains(expected), "{expected}: {out}");
    }
    assert!(
        !out.contains(&pass),
        "Passphrase nie ausgeben / never print passphrase"
    );
}

#[test]
fn export_public_key() {
    let dir = tempfile::tempdir().unwrap();
    generate_max(dir.path(), &new_pass());
    let (key, _) = envelope::load(&dir.path().join("max.key.json")).unwrap();
    let (code, out, _) = common::pqkeep(
        &["export", "max.key.json", "--out", "max.pub.json"],
        "",
        dir.path(),
    );
    assert_eq!(code, 0);
    let public = envelope::load_public(&dir.path().join("max.pub.json")).unwrap();
    assert_eq!(public.key_id(), key.key_id());
    assert!(out.contains(&key.key_id_hex()[..4]));
    let (code, out, _) =
        common::pqkeep(&["--lang", "de", "inspect", "max.pub.json"], "", dir.path());
    assert_eq!(code, 0);
    assert!(out.contains("Öffentliche Schlüsseldatei"));
}

#[test]
fn weak_passphrase_exit_4_and_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let args = [
        "--lang",
        "en",
        "generate",
        "--name",
        "x",
        "--out",
        "k.json",
        "--passphrase-stdin",
    ];
    let (code, _, err) = common::pqkeep(&args, "password123\n", dir.path());
    assert_eq!(code, 4);
    assert!(err.contains("too short") && err.contains("Passphrase rejected"));
    assert!(!dir.path().join("k.json").exists());
}

#[test]
fn existing_target_exit_5_and_force_yes() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("k.json"), b"alt").unwrap();
    let pass = format!("{}\n", new_pass());
    let base = [
        "--lang",
        "de",
        "generate",
        "--name",
        "x",
        "--out",
        "k.json",
        "--passphrase-stdin",
    ];
    let (code, _, err) = common::pqkeep(&base, &pass, dir.path());
    assert_eq!(code, 5);
    assert!(err.contains("existiert bereits"));
    assert_eq!(std::fs::read(dir.path().join("k.json")).unwrap(), b"alt");

    // DE: --force ohne Terminal und ohne --yes wird verweigert. EN: --force without TTY/--yes refused.
    let mut forced = base.to_vec();
    forced.push("--force");
    let (code, _, _) = common::pqkeep(&forced, &pass, dir.path());
    assert_eq!(code, 2);
    forced.push("--yes");
    let (code, _, err) = common::pqkeep(&forced, &pass, dir.path());
    assert_eq!(code, 0, "{err}");
    assert!(envelope::load(&dir.path().join("k.json")).is_ok());
}

#[test]
fn missing_and_invalid_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let (code, _, err) = common::pqkeep(&["--lang", "de", "inspect", "fehlt.json"], "", dir.path());
    assert_eq!(code, 1);
    assert!(err.contains("nicht gefunden"));
    std::fs::write(dir.path().join("kaputt.json"), b"{}").unwrap();
    let (code, _, _) = common::pqkeep(&["inspect", "kaputt.json"], "", dir.path());
    assert_eq!(code, 1);
    let args = [
        "generate",
        "--name",
        "",
        "--out",
        "k.json",
        "--passphrase-stdin",
    ];
    let (code, _, _) = common::pqkeep(&args, "x\n", dir.path());
    assert_eq!(code, 1, "leerer Name / empty name");
    let args = [
        "generate",
        "--algorithm",
        "rsa",
        "--name",
        "x",
        "--out",
        "k.json",
    ];
    let (code, _, _) = common::pqkeep(&args, "", dir.path());
    assert_eq!(code, 2);
}

#[test]
fn aes_key_has_no_public_export() {
    let dir = tempfile::tempdir().unwrap();
    let args = [
        "generate",
        "--algorithm",
        "aes-256",
        "--name",
        "x",
        "--out",
        "a.json",
        "--passphrase-stdin",
    ];
    let (code, _, _) = common::pqkeep(&args, &format!("{}\n", new_pass()), dir.path());
    assert_eq!(code, 0);
    let (code, _, _) = common::pqkeep(&["export", "a.json", "--out", "a.pub.json"], "", dir.path());
    assert_eq!(code, 1);
    assert!(!dir.path().join("a.pub.json").exists());
}
