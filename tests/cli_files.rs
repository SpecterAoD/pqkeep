//! DE: CLI encrypt/decrypt: Passphrase und Empfänger (pub.json / Schlüsseldatei),
//! Ordner, Standard-Zielnamen, Exit-Codes (3 falsche Passphrase, 5 Ziel existiert,
//! 2 fehlender Schlüssel), übersprungene Einträge.
//! EN: CLI encrypt/decrypt: passphrase and recipient (pub.json / key file),
//! directories, default target names, exit codes (3 wrong passphrase, 5 target
//! exists, 2 missing key), skipped entries.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

fn pass() -> String {
    format!("{}\n", common::random_passphrase().as_ref().expose_str())
}

fn run(dir: &Path, args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut full = vec!["--lang", "de"];
    full.extend_from_slice(args);
    common::pqkeep(&full, stdin, dir)
}

#[test]
fn file_with_passphrase_default_names() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("bericht.pdf"), b"PDF-Inhalt").unwrap();
    let p = pass();
    let (code, out, err) = run(
        dir.path(),
        &["encrypt", "bericht.pdf", "--passphrase-stdin"],
        &p,
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("bericht.pdf.pqkf"));
    std::fs::rename(
        dir.path().join("bericht.pdf"),
        dir.path().join("original.pdf"),
    )
    .unwrap();
    let (code, out, _) = run(
        dir.path(),
        &["decrypt", "bericht.pdf.pqkf", "--passphrase-stdin"],
        &p,
    );
    assert_eq!(code, 0);
    assert!(out.contains("Entschlüsselt: bericht.pdf"));
    assert_eq!(
        std::fs::read(dir.path().join("bericht.pdf")).unwrap(),
        b"PDF-Inhalt"
    );

    // DE: Erneut entschlüsseln → Ziel existiert → Exit 5. EN: Decrypt again → exists → exit 5.
    let (code, _, err) = run(
        dir.path(),
        &["decrypt", "bericht.pdf.pqkf", "--passphrase-stdin"],
        &p,
    );
    assert_eq!(code, 5);
    assert!(err.contains("existiert bereits"));
    let (code, _, err) = run(
        dir.path(),
        &[
            "decrypt",
            "bericht.pdf.pqkf",
            "-o",
            "x.pdf",
            "--passphrase-stdin",
        ],
        &pass(),
    );
    assert_eq!(code, 3, "falsche Passphrase / wrong passphrase");
    assert!(err.contains("Entschlüsselung fehlgeschlagen"));
    assert!(!dir.path().join("x.pdf").exists());
}

#[test]
fn weak_passphrase_rejected_for_encrypt() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"x").unwrap();
    let (code, _, err) = run(
        dir.path(),
        &["encrypt", "a.txt", "--passphrase-stdin"],
        "kurz\n",
    );
    assert_eq!(code, 4);
    assert!(err.contains("zu kurz"));
    assert!(!dir.path().join("a.txt.pqkf").exists());
}

/// DE: Erzeugt „anna.key.json“ und „anna.pub.json“; liefert die Passphrase (mit \n).
/// EN: Creates "anna.key.json" and "anna.pub.json"; returns the passphrase (with \n).
fn setup_anna(dir: &Path) -> String {
    let key_pass = pass();
    let generate = [
        "generate",
        "--name",
        "Anna",
        "--out",
        "anna.key.json",
        "--passphrase-stdin",
    ];
    assert_eq!(run(dir, &generate, &key_pass).0, 0);
    assert_eq!(
        run(dir, &["export", "anna.key.json", "-o", "anna.pub.json"], "").0,
        0
    );
    key_pass
}

#[test]
fn directory_for_recipient() {
    let dir = tempfile::tempdir().unwrap();
    let key_pass = setup_anna(dir.path());
    let src = dir.path().join("Projekt");
    std::fs::create_dir(&src).unwrap();
    common::write_sample_tree(&src);

    let (code, out, err) = run(
        dir.path(),
        &["encrypt", "Projekt", "--to", "anna.pub.json"],
        "",
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("5 / 4"), "{out}");
    let (code, out, _) = run(dir.path(), &["inspect", "Projekt.pqkf"], "");
    assert_eq!(code, 0);
    assert!(out.contains("Empfänger (ML-KEM)"));

    let (code, _, err) = run(dir.path(), &["decrypt", "Projekt.pqkf", "-o", "Zurück"], "");
    assert_eq!(code, 2, "ohne --key / without --key");
    assert!(err.contains("--key"));
    let args = [
        "decrypt",
        "Projekt.pqkf",
        "--key",
        "anna.key.json",
        "-o",
        "Zurück",
        "--passphrase-stdin",
    ];
    let (code, _, err) = run(dir.path(), &args, &key_pass);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        common::read_tree(&dir.path().join("Zurück")),
        common::read_tree(&src)
    );
}

#[cfg(unix)]
#[test]
fn skipped_entries_are_reported() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("q");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("ok.txt"), b"ok").unwrap();
    std::os::unix::fs::symlink("/etc/hostname", src.join("link")).unwrap();
    let (code, _, err) = run(dir.path(), &["encrypt", "q", "--passphrase-stdin"], &pass());
    assert_eq!(code, 0);
    assert!(
        err.contains("Übersprungen: link (symbolischer Link)"),
        "{err}"
    );
}

#[test]
fn missing_source_and_bad_files() {
    let dir = tempfile::tempdir().unwrap();
    let (code, _, err) = run(
        dir.path(),
        &["encrypt", "fehlt.txt", "--passphrase-stdin"],
        &pass(),
    );
    assert_eq!(code, 1);
    assert!(err.contains("nicht gefunden"), "{err}");
    std::fs::write(dir.path().join("kein.pqkf"), b"kein Container").unwrap();
    let (code, _, _) = run(
        dir.path(),
        &["decrypt", "kein.pqkf", "--passphrase-stdin"],
        &pass(),
    );
    assert_eq!(code, 1);
}
