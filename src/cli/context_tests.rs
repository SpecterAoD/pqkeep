#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use super::{absolute, free_target};
use crate::cli::files_cmd::{default_decrypted, default_encrypted};

/// DE: Namen mit führendem `-` werden zu absoluten Pfaden – kein Wert sieht wie eine Option aus.
/// EN: Names with a leading `-` become absolute paths – no value looks like an option.
#[test]
fn hyphen_names_become_absolute() {
    for name in ["-report.txt", "--no-sandbox", "-x.pqkf"] {
        let abs = absolute(Path::new(name));
        assert!(abs.is_absolute(), "{name}");
        assert!(!abs.to_str().unwrap().starts_with('-'));
        let out = default_encrypted(&abs).unwrap();
        assert!(out.is_absolute() && !out.to_str().unwrap().starts_with('-'));
    }
}

#[test]
fn free_target_never_returns_an_existing_path() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("bericht.txt");
    assert_eq!(free_target(&base).unwrap(), base);
    std::fs::write(&base, b"x").unwrap();
    let second = free_target(&base).unwrap();
    assert_eq!(second, dir.path().join("bericht (2).txt"));
    std::fs::write(&second, b"x").unwrap();
    assert_eq!(
        free_target(&base).unwrap(),
        dir.path().join("bericht (3).txt")
    );
    let dec = default_decrypted(&dir.path().join("a.pdf.pqkf")).unwrap();
    assert_eq!(dec, dir.path().join("a.pdf"));
}
