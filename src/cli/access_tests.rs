//! DE: U02 – Sandbox-Freigaben mit Faktordatei: genau diese eine Datei kommt lesend hinzu, sonst
//! nichts; `pqkeep factor` darf nur in den Zielordner schreiben.
//! EN: U02 – sandbox permissions with a factor file: exactly this one file is added read-only,
//! nothing else; `pqkeep factor` may only write to the target directory.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use pqkeep::hardening::sandbox::CliAccess;
use pqkeep::security::Lang;

use super::for_command;
use crate::cli::args::build;

fn access(argv: &[&str]) -> Option<CliAccess> {
    let m = build(Lang::En).try_get_matches_from(argv).unwrap();
    let (name, sub) = m.subcommand().unwrap();
    for_command(name, sub, Lang::En).ok().flatten()
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// DE: Ordner mit Quelle, Schlüssel- und Faktordatei. EN: Directory with source, key and factor file.
fn setup() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let file = |name: &str| {
        let path = dir.path().join(name);
        std::fs::write(&path, b"x").unwrap();
        path
    };
    let (source, key, factor) = (file("a.txt"), file("k.json"), file("f.factor"));
    (dir, source, key, factor)
}

#[test]
fn u02_factor_file_adds_exactly_one_read_permission() {
    let (dir, source, key, factor) = setup();
    let (s, k, f) = (text(&source), text(&key), text(&factor));
    let plain = access(&["pqkeep", "encrypt", s]).unwrap();
    let with = access(&["pqkeep", "encrypt", s, "--factor-file", f]).unwrap();
    assert_eq!(plain.read, std::slice::from_ref(&source));
    assert_eq!(with.read, [factor.clone(), source.clone()]);
    assert_eq!(with.write_dirs, plain.write_dirs);
    assert_eq!(with.write_dirs, [dir.path().to_path_buf()]);

    let with = access(&["pqkeep", "decrypt", s, "-k", k, "--factor-file", f]).unwrap();
    assert_eq!(with.read, [factor.clone(), source.clone(), key.clone()]);
    let with = access(&["pqkeep", "sign", s, "-k", k, "--factor-file", f]).unwrap();
    assert_eq!(with.read, [factor.clone(), source, key]);

    let out = dir.path().join("neu.key.json");
    let argv = ["pqkeep", "generate", "-n", "A", "-o", text(&out)];
    let plain = access(&argv).unwrap();
    let with = access(&[&argv[..], &["--factor-file", f]].concat()).unwrap();
    assert_eq!(plain.read, [] as [PathBuf; 0]);
    assert_eq!(with.read, [factor]);
    assert_eq!(with.write_dirs, plain.write_dirs);
}

#[test]
fn u02_factor_command_writes_only_into_the_target_directory() {
    let (dir, ..) = setup();
    let out = dir.path().join("neu.factor");
    let access = access(&["pqkeep", "factor", "--out", text(&out)]).unwrap();
    assert_eq!(access.read, [] as [PathBuf; 0]);
    assert_eq!(access.write_dirs, [dir.path().to_path_buf()]);
}

#[test]
fn u02_missing_factor_file_is_reported_before_the_sandbox() {
    let (dir, source, ..) = setup();
    let missing = dir.path().join("fehlt.factor");
    let argv = [
        "pqkeep",
        "encrypt",
        text(&source),
        "--factor-file",
        text(&missing),
    ];
    assert!(access(&argv).is_none());
}
