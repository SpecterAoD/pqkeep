#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

#[test]
fn base32_matches_rfc4648_vectors() {
    // DE: RFC 4648 „foobar“ ist kürzer; hier 16 Nullbytes und 16 × 0xff als feste Werte.
    // EN: RFC 4648 "foobar" is shorter; here 16 zero bytes and 16 × 0xff as fixed values.
    assert_eq!(base32(&[0u8; 16]), "a".repeat(26));
    assert_eq!(base32(&[0xffu8; 16]), format!("{}4", "7".repeat(25)));
}

#[test]
fn random_names_have_fixed_shape_and_differ() {
    let names: std::collections::BTreeSet<String> =
        (0..64).map(|_| random_name().unwrap()).collect();
    assert_eq!(names.len(), 64);
    for n in &names {
        assert_eq!(n.len(), RANDOM_NAME_LEN + 5);
        assert!(is_random_name(n), "{n}");
    }
}

#[test]
fn recognises_only_random_shapes() {
    assert!(is_random_name("abcdefghijklmnopqrstuvwxyz.pqkf"));
    assert!(!is_random_name("abcdefghijklmnopqrstuvwxy.pqkf"));
    assert!(!is_random_name("ABCDEFGHIJKLMNOPQRSTUVWXYZ.pqkf"));
    assert!(!is_random_name("abcdefghijklmnopqrstuvwx01.pqkf"));
    assert!(!is_random_name("abcdefghijklmnopqrstuvwxyz.txt"));
    assert!(!is_random_name("abcdefghijklmnopqrstuvwxyzpqkf"));
    assert!(!is_random_name("steuer-2026.pdf.pqkf"));
}

#[test]
fn random_target_is_free_and_in_dir() {
    let dir = tempfile::tempdir().unwrap();
    let p = random_target(dir.path()).unwrap();
    assert_eq!(p.parent(), Some(dir.path()));
    assert!(!p.exists());
}
