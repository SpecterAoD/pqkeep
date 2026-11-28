//! DE: Echte native Aufrufe und std-kompatible Windows-Pfadgrenzen.
//! EN: Actual native calls and std-compatible Windows path boundaries.
#![allow(clippy::unwrap_used)]

use super::*;
use std::{io::Read, path::Path};

fn owned(text: &str) -> NativePath {
    NativePath::from_path(Path::new(text)).unwrap()
}

#[test]
fn legacy_boundary_matches_the_std_248_unit_rule() {
    let short = owned(&format!("C:\\{}", "x".repeat(243)));
    let boundary = owned(&format!("C:\\{}", "x".repeat(244)));
    assert!(unchanged(short.encoded().unwrap()));
    assert!(!unchanged(boundary.encoded().unwrap()));
    let normalized = for_open(&boundary).unwrap().unwrap();
    assert!(normalized.encoded().unwrap().starts_with(VERBATIM));
    crate::locked_owner_test_support::locked(normalized.0.get().0.expose());
}

#[test]
fn absolute_drive_unc_verbatim_and_nt_prefixes_follow_std_branches() {
    for text in [
        "",
        "C:",
        "C:\\public",
        "C:/public",
        "\\\\host\\share",
        "\\\\?\\C:\\public",
        "\\??\\C:\\public",
    ] {
        let input = owned(text);
        assert!(for_open(&input).unwrap().is_none());
    }
    for (source, expected) in [
        ("C:\\public", "\\\\?\\C:\\public"),
        ("\\\\.\\public", "\\\\?\\public"),
        ("\\\\host\\share", "\\\\?\\UNC\\host\\share"),
        ("\\\\?\\C:\\public", "\\\\?\\C:\\public"),
        ("\\??\\C:\\public", "\\??\\C:\\public"),
    ] {
        let input = owned(source);
        let prefixed = with_prefix(&input).unwrap();
        let reference = owned(expected);
        let equal = prefixed.encoded().unwrap() == reference.encoded().unwrap();
        assert!(equal);
    }
}

#[test]
fn relative_paths_read_the_same_file_as_std_without_changing_cwd() {
    let root = tempfile::tempdir_in(".").unwrap();
    let path = root.path().join("public Unicode ä fixture.txt");
    let expected = b"public fixture";
    std::fs::write(&path, expected).unwrap();
    let cwd = std::env::current_dir().unwrap();
    let mut protected = super::super::open_file(&path).unwrap();
    let mut reference = std::fs::File::open(&path).unwrap();
    let mut actual = crate::crypto::SecretBytes::zeroed(expected.len()).unwrap();
    let mut standard = vec![0; expected.len()];
    protected.read_exact(actual.expose_mut()).unwrap();
    reference.read_exact(&mut standard).unwrap();
    let equal = actual.expose() == standard;
    assert!(equal);
    assert_eq!(std::env::current_dir().unwrap(), cwd);
}

#[test]
fn long_native_paths_match_std_open_and_missing_file_errors() {
    let root = tempfile::tempdir().unwrap();
    let mut directory = root.path().to_path_buf();
    for _ in 0..6 {
        directory.push("public-long-component-123456789012345678901234567890");
    }
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("public fixture.txt");
    std::fs::write(&path, b"fixture").unwrap();
    let input = NativePath::from_path(&path).unwrap();
    let normalized = for_open(&input).unwrap().unwrap();
    assert!(normalized.encoded().unwrap().starts_with(VERBATIM));
    assert!(super::super::open_file(&path).is_ok());
    assert!(std::fs::File::open(&path).is_ok());
    let missing = directory.join("missing fixture");
    assert!(matches!(
        super::super::open_file(&missing),
        Err(Error::Io(std::io::ErrorKind::NotFound))
    ));
}

#[test]
fn native_adapters_reject_unterminated_and_interior_nul_input() {
    for input in [&[][..], &[65][..], &[65, 0, 66, 0][..]] {
        assert_eq!(
            pqkeep_platform::open_file_read(input).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        let mut output = [0; 8];
        assert_eq!(
            pqkeep_platform::absolute_path_into(input, &mut output)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
    assert_eq!(
        pqkeep_platform::absolute_path_into(&[65, 0], &mut [])
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
}
