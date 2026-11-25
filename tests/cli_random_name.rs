//! DE: CLI mit zufälligen äußeren Namen (#315): `encrypt --random-name`/`--privacy high`, `decrypt`
//! automatisch bzw. mit `--original-name`, `--each`, Container, Ordner, Konflikte, JSON.
//! EN: CLI with random outer names (#315): `encrypt --random-name`/`--privacy high`, `decrypt`
//! automatically or with `--original-name`, `--each`, container, directory, conflicts, JSON.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use pqkeep::files::is_random_name;

fn pass() -> String {
    format!("{}\n", common::random_passphrase().as_ref().expose_str())
}

fn run(dir: &Path, args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut full = vec!["--lang", "en"];
    full.extend_from_slice(args);
    common::pqkeep(&full, stdin, dir)
}

/// DE: Alle Dateien mit zufälligem Namen in `dir`. EN: All randomly named files in `dir`.
fn random_files(dir: &Path) -> Vec<PathBuf> {
    common::dir_names(dir)
        .into_iter()
        .filter(|n| is_random_name(n))
        .map(|n| dir.join(n))
        .collect()
}

fn name(p: &Path) -> &str {
    p.file_name().unwrap().to_str().unwrap()
}

#[test]
fn single_file_roundtrip_restores_name() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("steuer-2026.pdf"), b"inhalt").unwrap();
    let p = pass();
    let args = [
        "encrypt",
        "--random-name",
        "--passphrase-stdin",
        "--",
        "steuer-2026.pdf",
    ];
    let (code, out, err) = run(dir.path(), &args, &p);
    assert_eq!(code, 0, "{out}{err}");
    let enc = random_files(dir.path());
    assert_eq!(enc.len(), 1);
    assert!(!out.contains("steuer"), "{out}");
    fs::remove_file(dir.path().join("steuer-2026.pdf")).unwrap();
    // DE: Automatisch am Namen erkannt. EN: Recognised automatically by the name.
    let args = ["decrypt", "--passphrase-stdin", "--", name(&enc[0])];
    let (code, out, err) = run(dir.path(), &args, &p);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("steuer-2026.pdf"), "{out}");
    assert_eq!(
        fs::read(dir.path().join("steuer-2026.pdf")).unwrap(),
        b"inhalt"
    );
    // DE: Nochmals: Ziel existiert (Exit 5), mit --rename nummeriert.
    // EN: Again: target exists (exit 5), numbered with --rename.
    let (code, _, err) = run(dir.path(), &args, &p);
    assert_eq!(code, 5, "{err}");
    let args = [
        "decrypt",
        "--rename",
        "--passphrase-stdin",
        "--",
        name(&enc[0]),
    ];
    let (code, out, err) = run(dir.path(), &args, &p);
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(
        fs::read(dir.path().join("steuer-2026 (2).pdf")).unwrap(),
        b"inhalt"
    );
    // DE: Mit --out wie bisher: Ziel frei wählbar. EN: With --out as before: free target.
    let args = [
        "decrypt",
        "--passphrase-stdin",
        "--out",
        "x.bin",
        "--",
        name(&enc[0]),
    ];
    let (code, _, err) = run(dir.path(), &args, &p);
    assert_eq!(code, 0, "{err}");
    assert_eq!(fs::read(dir.path().join("x.bin")).unwrap(), b"inhalt");
}

#[test]
fn directory_each_and_container() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir(root.join("Urlaub")).unwrap();
    common::write_sample_tree(&root.join("Urlaub"));
    fs::write(root.join("a.txt"), b"a").unwrap();
    let p = pass();
    let args = [
        "encrypt",
        "--privacy",
        "high",
        "--each",
        "--passphrase-stdin",
        "--",
        "Urlaub",
        "a.txt",
    ];
    let (code, out, err) = run(root, &args, &p);
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(random_files(root).len(), 2);
    let out_dir = root.join("zurück");
    fs::create_dir(&out_dir).unwrap();
    for f in random_files(root) {
        fs::rename(&f, out_dir.join(name(&f))).unwrap();
    }
    let mut args = vec!["decrypt", "--passphrase-stdin", "--"];
    let moved: Vec<String> = common::dir_names(&out_dir);
    let paths: Vec<String> = moved.iter().map(|n| format!("zurück/{n}")).collect();
    args.extend(paths.iter().map(String::as_str));
    let (code, out, err) = run(root, &args, &p);
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(
        common::read_tree(&out_dir.join("Urlaub")),
        common::read_tree(&root.join("Urlaub"))
    );
    assert_eq!(fs::read(out_dir.join("a.txt")).unwrap(), b"a");
    // DE: Container: Name aus --out nur im Archiv. EN: Container: name from --out only inside.
    let args = [
        "encrypt",
        "--random-name",
        "--passphrase-stdin",
        "--out",
        "Auswahl.pqkf",
        "--",
        "Urlaub",
        "a.txt",
    ];
    let (code, out, err) = run(root, &args, &p);
    assert_eq!(code, 0, "{out}{err}");
    assert!(!root.join("Auswahl.pqkf").exists());
    let enc = random_files(root);
    assert_eq!(enc.len(), 1);
    let args = [
        "decrypt",
        "--original-name",
        "--passphrase-stdin",
        "--",
        name(&enc[0]),
    ];
    let (code, out, err) = run(root, &args, &p);
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(fs::read(root.join("Auswahl").join("a.txt")).unwrap(), b"a");
}

#[test]
fn usage_errors_and_plain_archives() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.txt"), b"a").unwrap();
    let p = pass();
    let args = [
        "encrypt",
        "--random-name",
        "--passphrase-stdin",
        "--out",
        "b.pqkf",
        "--",
        "a.txt",
    ];
    let (code, _, err) = run(dir.path(), &args, &p);
    assert_eq!(code, 2, "{err}");
    let args = ["decrypt", "--original-name", "--out", "x", "--", "a.txt"];
    let (code, _, err) = run(dir.path(), &args, &p);
    assert_eq!(code, 2, "{err}");
    // DE: Normal verschlüsselter Ordner hat keinen einzelnen Originalnamen.
    // EN: A normally encrypted directory has no single original name.
    fs::create_dir(dir.path().join("baum")).unwrap();
    common::write_sample_tree(&dir.path().join("baum"));
    let args = ["encrypt", "--passphrase-stdin", "--", "baum"];
    assert_eq!(run(dir.path(), &args, &p).0, 0);
    let args = [
        "decrypt",
        "--original-name",
        "--passphrase-stdin",
        "--",
        "baum.pqkf",
    ];
    let (code, _, err) = run(dir.path(), &args, &p);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("no single original name"), "{err}");
    assert!(
        !common::dir_names(dir.path())
            .iter()
            .any(|n| n.starts_with('.'))
    );
}

#[test]
fn json_reports_random_and_restored_targets() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.txt"), b"a").unwrap();
    let p = pass();
    let args = [
        "encrypt",
        "--json",
        "--random-name",
        "--passphrase-stdin",
        "--",
        "a.txt",
    ];
    let (code, out, err) = run(dir.path(), &args, &p);
    assert_eq!(code, 0, "{out}{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let target = v["results"][0]["target"].as_str().unwrap().to_owned();
    assert!(is_random_name(name(Path::new(&target))), "{target}");
    fs::remove_file(dir.path().join("a.txt")).unwrap();
    let args = ["decrypt", "--json", "--passphrase-stdin", "--", &target];
    let (code, out, err) = run(dir.path(), &args, &p);
    assert_eq!(code, 0, "{out}{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(
        v["results"][0]["target"]
            .as_str()
            .unwrap()
            .ends_with("a.txt"),
        "{out}"
    );
}
