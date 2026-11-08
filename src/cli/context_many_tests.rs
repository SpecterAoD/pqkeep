#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use super::{all_pqkf, container_default, container_target, resolve_action};
use crate::cli::many_text::many_texts;
use pqkeep::security::Lang;

#[test]
fn auto_decrypts_only_if_all_are_pqkf() {
    let enc = vec![PathBuf::from("/a/x.pqkf"), PathBuf::from("/a/y.PQKF.pqkf")];
    let mixed = vec![PathBuf::from("/a/x.pqkf"), PathBuf::from("/a/y.txt")];
    assert!(all_pqkf(&enc) && !all_pqkf(&mixed));
    assert_eq!(resolve_action("auto", &enc), "decrypt");
    assert_eq!(resolve_action("auto", &mixed), "encrypt");
    assert_eq!(resolve_action("encrypt", &enc), "encrypt");
}

#[test]
fn container_name_suggestion_and_free_names() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("Steuer 2026");
    std::fs::create_dir(&base).unwrap();
    let sources = vec![base.join("a.pdf"), base.join("b.pdf")];
    let m = many_texts(Lang::De);
    assert_eq!(container_default(&sources, m), "Steuer 2026.pqkf");
    std::fs::write(base.join("Steuer 2026.pqkf"), b"x").unwrap();
    assert_eq!(container_default(&sources, m), "Steuer 2026 (2).pqkf");
    let root = vec![
        PathBuf::from("/a.pdf"),
        PathBuf::from("/b.pdf"),
        PathBuf::from("/c"),
    ];
    assert_eq!(container_default(&root, m), "Auswahl (3 Einträge).pqkf");
}

#[test]
fn container_target_accepts_only_plain_names() {
    let dir = tempfile::tempdir().unwrap();
    let t = container_target(dir.path(), "  Belege  ").unwrap();
    assert_eq!(t, dir.path().join("Belege.pqkf"));
    let t = container_target(dir.path(), "Belege.PQKF").unwrap();
    assert_eq!(t, dir.path().join("Belege.PQKF"));
    std::fs::write(dir.path().join("x.pqkf"), b"x").unwrap();
    assert_eq!(
        container_target(dir.path(), "x").unwrap(),
        dir.path().join("x (2).pqkf")
    );
    for bad in ["", "  ", ".", "..", "a/b", "..\\b", "a\nb"] {
        assert!(container_target(dir.path(), bad).is_none(), "{bad:?}");
    }
}
