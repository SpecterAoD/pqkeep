//! DE: Unbeaufsichtigter Betrieb (S3): `--passphrase-file` (auch außerhalb des Arbeitsordners, also
//! mit Sandbox-Freigabe), Rechteprüfung, Konflikt mit `--passphrase-stdin`, `--batch` fragt nie.
//! EN: Unattended operation (S3): `--passphrase-file` (also outside the working folder, i.e. with
//! sandbox access), permission check, conflict with `--passphrase-stdin`, `--batch` never prompts.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn run(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let mut full = vec!["--lang", "en"];
    full.extend_from_slice(args);
    common::pqkeep(&full, "", dir)
}

/// DE: Passphrase-Datei in eigenem Ordner. EN: Passphrase file in its own folder.
fn pass_file(root: &Path, mode: u32) -> PathBuf {
    let secrets = root.join("secrets");
    fs::create_dir_all(&secrets).unwrap();
    let path = secrets.join(format!("pass-{mode:o}"));
    let p = common::random_passphrase();
    fs::write(&path, format!("{}\n", p.as_ref().expose_str())).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

#[test]
fn encrypt_and_decrypt_with_passphrase_file() {
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    fs::create_dir(&work).unwrap();
    fs::write(work.join("dump.sql"), b"INSERT ...").unwrap();
    let pf = pass_file(root.path(), 0o600);
    let pf = pf.to_str().unwrap();
    let (code, _, err) = run(
        &work,
        &["--batch", "--passphrase-file", pf, "encrypt", "dump.sql"],
    );
    assert_eq!(code, 0, "{err}");
    fs::remove_file(work.join("dump.sql")).unwrap();
    let (code, _, err) = run(
        &work,
        &[
            "decrypt",
            "--batch",
            "--passphrase-file",
            pf,
            "dump.sql.pqkf",
        ],
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(fs::read(work.join("dump.sql")).unwrap(), b"INSERT ...");
}

#[test]
fn key_generation_and_recipient_decrypt_unattended() {
    let root = tempfile::tempdir().unwrap();
    let pf = pass_file(root.path(), 0o400);
    let pf = pf.to_str().unwrap();
    let gen_args = [
        "generate",
        "--name",
        "Backup",
        "--out",
        "b.key.json",
        "--passphrase-file",
        pf,
    ];
    let (code, _, err) = run(root.path(), &gen_args);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        run(root.path(), &["export", "b.key.json", "-o", "b.pub.json"]).0,
        0
    );
    fs::write(root.path().join("a.txt"), b"x").unwrap();
    assert_eq!(
        run(
            root.path(),
            &["--batch", "encrypt", "--to", "b.pub.json", "a.txt"]
        )
        .0,
        0
    );
    fs::remove_file(root.path().join("a.txt")).unwrap();
    let dec = [
        "--batch",
        "decrypt",
        "--key",
        "b.key.json",
        "--passphrase-file",
        pf,
        "a.txt.pqkf",
    ];
    let (code, _, err) = run(root.path(), &dec);
    assert_eq!(code, 0, "{err}");
}

#[test]
fn open_permissions_and_conflicts_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("a.txt"), b"x").unwrap();
    let open = pass_file(root.path(), 0o644);
    let (code, _, err) = run(
        root.path(),
        &[
            "encrypt",
            "--passphrase-file",
            open.to_str().unwrap(),
            "a.txt",
        ],
    );
    assert_eq!(code, 2);
    assert!(err.contains("chmod 600"), "{err}");
    let ok = pass_file(root.path(), 0o600);
    let both = [
        "encrypt",
        "--passphrase-stdin",
        "--passphrase-file",
        ok.to_str().unwrap(),
        "a.txt",
    ];
    let (code, _, err) = run(root.path(), &both);
    assert_eq!(code, 2);
    assert!(err.contains("mutually exclusive"), "{err}");
    assert!(!root.path().join("a.txt.pqkf").exists());
}

#[test]
fn batch_never_prompts() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("a.txt"), b"x").unwrap();
    let (code, _, err) = run(root.path(), &["--batch", "encrypt", "a.txt"]);
    assert_eq!(code, 2);
    assert!(err.contains("--batch"), "{err}");
    let pf = pass_file(root.path(), 0o600);
    let gen_args = [
        "generate",
        "--name",
        "A",
        "--out",
        "k.json",
        "--passphrase-file",
        pf.to_str().unwrap(),
    ];
    assert_eq!(run(root.path(), &gen_args).0, 0);
    let again = [&["--batch"][..], &gen_args, &["--force"]].concat();
    let (code, _, err) = run(root.path(), &again);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("--batch"), "{err}");
}

#[test]
fn sign_uses_the_global_passphrase_file() {
    let root = tempfile::tempdir().unwrap();
    let pf = pass_file(root.path(), 0o600);
    let pf = pf.to_str().unwrap();
    let gen_args = [
        "generate",
        "-a",
        "ml-dsa-87",
        "--name",
        "S",
        "--out",
        "s.key.json",
        "--passphrase-file",
        pf,
    ];
    assert_eq!(run(root.path(), &gen_args).0, 0);
    fs::write(root.path().join("a.txt"), b"x").unwrap();
    let sign = [
        "--batch",
        "sign",
        "--key",
        "s.key.json",
        "--passphrase-file",
        pf,
        "a.txt",
    ];
    let (code, _, err) = run(root.path(), &sign);
    assert_eq!(code, 0, "{err}");
    assert!(root.path().join("a.txt.pqsig").is_file());
}
