//! DE: Verschlüsseln aus einer Pipe (#83, Testkatalog P10): `encrypt --stdin` nach `--out` bzw.
//! `--stdout`, Empfänger und Signatur, leere Eingabe, mehrere MiB, Bedienregeln, JSON, abgebrochene
//! Pipe; Entschlüsseln nur in eine Datei.
//! EN: Encrypting from a pipe (#83, test catalogue P10): `encrypt --stdin` to `--out` or `--stdout`,
//! recipients and signature, empty input, several MiB, usage rules, JSON, broken pipe; decrypting
//! into a file only.
#![cfg(unix)]
// DE: Tests dürfen unwrap/expect nutzen. EN: Tests may use unwrap/expect.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// DE: Ergebnis eines Laufs mit Binär-stdin. EN: Result of a run with binary stdin.
struct Out {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
}

fn run(dir: &Path, args: &[&str], input: &[u8]) -> Out {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pqkeep"))
        .args(["--lang", "en"])
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let data = input.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let out = child.wait_with_output().unwrap();
    writer.join().unwrap();
    Out {
        code: out.status.code().unwrap_or(-1),
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// DE: Passphrase-Datei (0600). EN: Passphrase file (0600).
fn pass_file(dir: &Path) -> PathBuf {
    let path = dir.join("pass.txt");
    let p = common::random_passphrase();
    fs::write(&path, format!("{}\n", p.as_ref().expose_str())).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 253).unwrap()).collect()
}

#[test]
fn stdin_to_file_and_stdout_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let pf = pass_file(dir.path());
    let pf = pf.to_str().unwrap();
    for (len, name) in [(0usize, "leer"), (5 * 1024 * 1024 + 17, "gross")] {
        let plain = data(len);
        let out = format!("{name}.pqkf");
        let r = run(
            dir.path(),
            &["--passphrase-file", pf, "encrypt", "--stdin", "--out", &out],
            &plain,
        );
        assert_eq!(r.code, 0, "{}", r.stderr);
        let r = run(dir.path(), &["--passphrase-file", pf, "decrypt", &out], b"");
        assert_eq!(r.code, 0, "{}", r.stderr);
        assert_eq!(fs::read(dir.path().join(name)).unwrap(), plain);
    }
    // DE: --stdout: nur die Datei auf stdout, Meldungen auf stderr. EN: only the file on stdout.
    let plain = data(70_000);
    let r = run(
        dir.path(),
        &["--passphrase-file", pf, "encrypt", "--stdin", "--stdout"],
        &plain,
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout.starts_with(b"PQKFENC\0\x04\0\x03"),
        "v4, Strom / stream"
    );
    assert!(r.stderr.contains("Encrypted: stdout"), "{}", r.stderr);
    fs::write(dir.path().join("p.pqkf"), &r.stdout).unwrap();
    let r = run(
        dir.path(),
        &["--passphrase-file", pf, "decrypt", "p.pqkf", "-o", "p.bin"],
        b"",
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(fs::read(dir.path().join("p.bin")).unwrap(), plain);
}

/// DE: Ben (ML-KEM-768, Passphrase zurück) und Anna (ML-DSA-87, Passphrase-Datei zurück).
/// EN: Ben (ML-KEM-768, passphrase returned) and Anna (ML-DSA-87, passphrase file returned).
fn keys(d: &Path) -> (String, PathBuf) {
    let ben = format!("{}\n", common::random_passphrase().as_ref().expose_str());
    let generate = [
        "generate",
        "-a",
        "ml-kem-768",
        "--name",
        "Ben",
        "--out",
        "ben.key.json",
        "--passphrase-stdin",
    ];
    assert_eq!(run(d, &generate, ben.as_bytes()).code, 0);
    assert_eq!(
        run(d, &["export", "ben.key.json", "-o", "ben.pub.json"], b"").code,
        0
    );
    let anna = pass_file(d);
    let generate = [
        "generate",
        "-a",
        "ml-dsa-87",
        "--name",
        "Anna",
        "--out",
        "anna.key.json",
        "--passphrase-stdin",
    ];
    assert_eq!(run(d, &generate, &fs::read(&anna).unwrap()).code, 0);
    (ben, anna)
}

#[test]
fn recipients_signature_and_json() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (ben, anna) = keys(d);
    let plain = data(1000);
    let base = [
        "encrypt",
        "--stdin",
        "--to",
        "ben.pub.json",
        "--sign-with",
        "anna.key.json",
    ];
    // DE: Signieren ohne --sign-passphrase-file: Bedienfehler. EN: without it: usage error.
    let r = run(d, &[&base[..], &["--out", "x.pqkf"]].concat(), &plain);
    assert_eq!(r.code, 2, "{}", r.stderr);
    let signed = [
        &base[..],
        &[
            "--sign-passphrase-file",
            anna.to_str().unwrap(),
            "--out",
            "s.pqkf",
            "--json",
        ],
    ]
    .concat();
    let r = run(d, &signed, &plain);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let v: serde_json::Value = serde_json::from_slice(&r.stdout).unwrap();
    assert_eq!(v["results"][0]["bytes"], 1000, "{v}");
    let dec = [
        "decrypt",
        "s.pqkf",
        "-k",
        "ben.key.json",
        "-o",
        "s.bin",
        "--passphrase-stdin",
    ];
    let r = run(d, &dec, ben.as_bytes());
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout.starts_with(b"Decrypted"),
        "{}",
        String::from_utf8_lossy(&r.stdout)
    );
    assert_eq!(fs::read(d.join("s.bin")).unwrap(), plain);
}

#[test]
fn usage_rules_come_first() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let pf = pass_file(d);
    let pf = pf.to_str().unwrap();
    fs::write(d.join("a.txt"), b"a").unwrap();
    for args in [
        vec!["encrypt", "--stdin", "--out", "x.pqkf"],
        vec!["--passphrase-file", pf, "encrypt", "--stdin"],
        vec!["--passphrase-file", pf, "encrypt", "--stdout", "a.txt"],
        vec![
            "--passphrase-file",
            pf,
            "encrypt",
            "--stdin",
            "a.txt",
            "--out",
            "x.pqkf",
        ],
        vec![
            "--passphrase-file",
            pf,
            "encrypt",
            "--stdin",
            "--stdout",
            "--json",
        ],
        vec![
            "--passphrase-file",
            pf,
            "encrypt",
            "--stdin",
            "--passphrase-stdin",
            "--out",
            "x.pqkf",
        ],
    ] {
        let r = run(d, &args, b"x");
        assert_eq!(r.code, 2, "{args:?}: {}", r.stderr);
    }
    assert!(!d.join("x.pqkf").exists());
}

#[test]
fn broken_pipe_is_a_clean_error() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let pf = pass_file(d);
    let pf = pf.to_str().unwrap();
    // DE: Leser beendet die Pipe sofort: sauberer Fehler, kein Absturz.
    // EN: Reader closes the pipe at once: clean error, no crash.
    let mut child = Command::new(env!("CARGO_BIN_EXE_pqkeep"))
        .args([
            "--lang",
            "en",
            "--passphrase-file",
            pf,
            "encrypt",
            "--stdin",
            "--stdout",
        ])
        .current_dir(d)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let mut stdin = child.stdin.take().unwrap();
    let _ = stdin.write_all(&data(3 * 1024 * 1024));
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
