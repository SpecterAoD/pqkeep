#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use super::*;

const RANDOM: &str = "abcdefghijklmnopqrstuvwxyz.pqkf";

#[test]
fn cleanup_target_follows_the_source_for_random_names() {
    let random = Path::new("/daten").join(RANDOM);
    assert_eq!(cleanup_target(&random), Some(random.clone()));
    assert_eq!(
        cleanup_target(Path::new("/daten/brief.txt.pqkf")),
        Some(PathBuf::from("/daten/brief.txt"))
    );
}

#[test]
fn context_cleanup_matches_source_named_temporaries() {
    // DE: So benennt `fsutil::temp_path` die Reste beim Wiederherstellen (#315, Codex-Fund #323).
    // EN: This is how `fsutil::temp_path` names leftovers when restoring (#315, Codex finding #323).
    let name = format!(".{RANDOM}.tmp-ab0123456789abcdef");
    assert!(super::super::context_child::own_temp(&name, RANDOM, "ab"));
    assert!(!super::super::context_child::own_temp(
        &name,
        "brief.txt",
        "ab"
    ));
}

#[test]
fn random_shape_is_recognised_by_path() {
    assert!(is_random_path(&Path::new("x").join(RANDOM)));
    assert!(!is_random_path(Path::new("x/brief.txt.pqkf")));
}

#[test]
fn placeholder_cleans_only_own_random_temporaries() {
    use super::super::context_child::own_temp;
    let tag = "ab";
    let own = format!(".{RANDOM}.tmp-ab0123456789abcdef");
    assert!(own_temp(&own, ANY_RANDOM, tag));
    assert!(!own_temp(&own, ANY_RANDOM, "cd"));
    assert!(!own_temp(
        ".brief.txt.pqkf.tmp-ab0123456789abcdef",
        ANY_RANDOM,
        tag
    ));
    let dirs = [
        PathBuf::from("/a"),
        PathBuf::from("/a"),
        PathBuf::from("/b"),
    ];
    assert_eq!(any_random_targets(dirs).len(), 2);
}
