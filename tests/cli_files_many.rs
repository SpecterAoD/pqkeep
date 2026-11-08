//! DE: CLI mit mehreren Quellen: `encrypt --each`, Container mit `--out`, `--rename`,
//! `decrypt` mehrerer Dateien, gemischte Modi, Fehler einzelner Dateien, viele Dateien,
//! problematische Namen.
//! EN: CLI with several sources: `encrypt --each`, container with `--out`, `--rename`,
//! `decrypt` of several files, mixed modes, failures of single files, many files, awkward names.

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

fn write(dir: &Path, names: &[&str]) {
    for n in names {
        fs::write(dir.join(n), n.as_bytes()).unwrap();
    }
}

#[test]
fn each_continues_after_a_failure_and_reports() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), &["a.txt", "b ä.txt", "c.txt"]);
    fs::write(dir.path().join("b ä.txt.pqkf"), b"belegt").unwrap();
    let args = [
        "encrypt",
        "--each",
        "--passphrase-stdin",
        "--",
        "a.txt",
        "b ä.txt",
        "c.txt",
    ];
    let (code, out, err) = run(dir.path(), &args, &pass());
    assert_eq!(code, 5, "{out}{err}");
    assert!(err.contains("Failed: b ä.txt"), "{err}");
    assert!(out.contains("Done: 2 / 3"), "{out}");
    assert!(dir.path().join("a.txt.pqkf").is_file() && dir.path().join("c.txt.pqkf").is_file());
    assert_eq!(
        fs::read(dir.path().join("b ä.txt.pqkf")).unwrap(),
        b"belegt"
    );
}

#[test]
fn each_with_rename_and_decrypt_many() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), &["a.txt", "-b.txt"]);
    fs::write(dir.path().join("a.txt.pqkf"), b"belegt").unwrap();
    let p = pass();
    let enc = [
        "encrypt",
        "--each",
        "--rename",
        "--passphrase-stdin",
        "--",
        "a.txt",
        "-b.txt",
    ];
    let (code, _, err) = run(dir.path(), &enc, &p);
    assert_eq!(code, 0, "{err}");
    assert!(dir.path().join("a.txt (2).pqkf").is_file());
    fs::remove_file(dir.path().join("a.txt")).unwrap();
    fs::remove_file(dir.path().join("-b.txt")).unwrap();
    let dec = [
        "decrypt",
        "--passphrase-stdin",
        "--",
        "a.txt (2).pqkf",
        "-b.txt.pqkf",
    ];
    let (code, out, err) = run(dir.path(), &dec, &p);
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(fs::read(dir.path().join("a.txt (2)")).unwrap(), b"a.txt");
    assert_eq!(fs::read(dir.path().join("-b.txt")).unwrap(), b"-b.txt");
}

#[test]
fn container_with_many_files_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let names: Vec<String> = (0..200).map(|i| format!("datei {i:03}.txt")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    write(dir.path(), &refs);
    let p = pass();
    let mut args = vec![
        "encrypt",
        "--out",
        "auswahl.pqkf",
        "--passphrase-stdin",
        "--",
    ];
    args.extend(&refs);
    let (code, _, err) = run(dir.path(), &args, &p);
    assert_eq!(code, 0, "{err}");
    let dec = ["decrypt", "--passphrase-stdin", "auswahl.pqkf"];
    assert_eq!(run(dir.path(), &dec, &p).0, 0);
    let out = dir.path().join("auswahl");
    assert_eq!(common::dir_names(&out).len(), 200);
    assert_eq!(
        fs::read(out.join("datei 199.txt")).unwrap(),
        b"datei 199.txt"
    );
}

#[test]
fn several_sources_need_out_or_each() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), &["a.txt", "b.txt"]);
    let (code, _, err) = run(dir.path(), &["encrypt", "a.txt", "b.txt"], "");
    assert_eq!(code, 2);
    assert!(err.contains("--each"), "{err}");
    let (code, _, _) = run(
        dir.path(),
        &["encrypt", "--each", "--out", "x", "a.txt"],
        "",
    );
    assert_eq!(code, 2);
    assert_eq!(common::dir_names(dir.path()), ["a.txt", "b.txt"]);
}

#[test]
fn decrypt_many_rejects_out_and_mixed_modes_and_reports_wrong_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), &["a.txt", "b.txt"]);
    let (p, q) = (pass(), pass());
    for (name, pw) in [("a.txt", &p), ("b.txt", &q)] {
        let args = ["encrypt", "--passphrase-stdin", name];
        assert_eq!(run(dir.path(), &args, pw).0, 0);
        fs::remove_file(dir.path().join(name)).unwrap();
    }
    let both = ["decrypt", "--passphrase-stdin", "a.txt.pqkf", "b.txt.pqkf"];
    let (code, out, err) = run(dir.path(), &both, &p);
    assert_eq!(code, 3, "{out}{err}");
    assert!(out.contains("Done: 1 / 2") && err.contains("Failed: b.txt.pqkf"));
    let (code, _, err) = run(dir.path(), &[&both[..], &["--out", "x"]].concat(), &p);
    assert_eq!(code, 2);
    assert!(err.contains("--out"), "{err}");
    // DE: Empfänger-Datei dazu → gemischte Modi. EN: Add a recipient file → mixed modes.
    let generate = [
        "generate",
        "--name",
        "A",
        "--out",
        "k.key.json",
        "--passphrase-stdin",
    ];
    assert_eq!(run(dir.path(), &generate, &pass()).0, 0);
    assert_eq!(
        run(
            dir.path(),
            &["export", "k.key.json", "-o", "k.pub.json"],
            ""
        )
        .0,
        0
    );
    write(dir.path(), &["c.txt"]);
    assert_eq!(
        run(dir.path(), &["encrypt", "--to", "k.pub.json", "c.txt"], "").0,
        0
    );
    let mixed = ["decrypt", "--passphrase-stdin", "a.txt.pqkf", "c.txt.pqkf"];
    let (code, _, err) = run(dir.path(), &mixed, &p);
    assert_eq!(code, 2);
    assert!(err.contains("protected differently"), "{err}");
}
