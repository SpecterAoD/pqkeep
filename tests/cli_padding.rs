//! DE: Kommandozeile mit Füllung (#316 Schritt 3): `encrypt --pad`, Stufe `--privacy high`
//! (zufälliger Name und Füllung), `inspect` zeigt die verborgene Größe, `--pad` mit `--stdin`.
//! EN: Command line with padding (#316 step 3): `encrypt --pad`, level `--privacy high` (random
//! name and padding), `inspect` shows the hidden size, `--pad` with `--stdin`.
#![cfg(unix)]
// DE: Tests dürfen unwrap/expect nutzen. EN: Tests may use unwrap/expect.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn run(dir: &Path, args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut full = vec!["--lang", "en"];
    full.extend_from_slice(args);
    common::pqkeep(&full, stdin, dir)
}

fn pass() -> String {
    format!("{}\n", common::random_passphrase().as_ref().expose_str())
}

#[test]
fn pad_and_privacy_high_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    fs::write(d.join("a.txt"), vec![b'a'; 1001]).unwrap();
    let p = pass();
    let (code, _, err) = run(
        d,
        &["encrypt", "--pad", "--passphrase-stdin", "--", "a.txt"],
        &p,
    );
    assert_eq!(code, 0, "{err}");
    let (_, shown, _) = run(d, &["inspect", "a.txt.pqkf"], "");
    assert!(
        shown.contains("size hidden (padding, format v4)"),
        "{shown}"
    );
    fs::remove_file(d.join("a.txt")).unwrap();
    let (code, _, err) = run(
        d,
        &["decrypt", "--passphrase-stdin", "--", "a.txt.pqkf"],
        &p,
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(fs::read(d.join("a.txt")).unwrap(), vec![b'a'; 1001]);
    // DE: Stufe hoch: zufälliger Name und Füllung. EN: Level high: random name and padding.
    let args = [
        "encrypt",
        "--privacy",
        "high",
        "--passphrase-stdin",
        "--",
        "a.txt",
    ];
    let (code, _, err) = run(d, &args, &p);
    assert_eq!(code, 0, "{err}");
    let random = common::dir_names(d)
        .into_iter()
        .find(|n| pqkeep::files::is_random_name(n))
        .unwrap();
    let (_, json, _) = run(d, &["inspect", "--json", &random], "");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        (v["padded"].as_bool(), v["format_version"].as_u64()),
        (Some(true), Some(4)),
        "{v}"
    );
}

#[test]
fn pad_with_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let pf = d.join("pass.txt");
    fs::write(&pf, pass()).unwrap();
    fs::set_permissions(&pf, fs::Permissions::from_mode(0o600)).unwrap();
    let pf = pf.to_str().unwrap();
    let args = [
        "--passphrase-file",
        pf,
        "encrypt",
        "--stdin",
        "--pad",
        "--out",
        "s.pqkf",
    ];
    let (code, _, err) = run(d, &args, "Inhalt aus der Pipe");
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = run(
        d,
        &["--passphrase-file", pf, "decrypt", "s.pqkf", "-o", "s.txt"],
        "",
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        fs::read_to_string(d.join("s.txt")).unwrap(),
        "Inhalt aus der Pipe"
    );
}
