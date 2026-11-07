//! DE: Tests für Token-Datei und Client-Schlüssel des Wächters.
//! EN: Tests for the token file and the guard's client key.
#![cfg(feature = "api")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::IpAddr;

use pqc_keyforge::Error;
use pqc_keyforge::api::token::{self, TOKEN_PREFIX};
use pqc_keyforge::api::{TokenHash, client_key};
use pqc_keyforge::envelope::Overwrite;

#[test]
fn created_token_verifies_and_file_holds_only_hash() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.token");
    let tok = token::create(&path, Overwrite::No).unwrap();
    assert!(tok.starts_with(TOKEN_PREFIX));
    assert_eq!(tok.len(), TOKEN_PREFIX.len() + 43);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.starts_with("keyforge-token-v1 sha3-256 "));
    assert!(!text.contains(&tok[TOKEN_PREFIX.len()..]));
    let hash = TokenHash::load(&path).unwrap();
    assert!(hash.verify(&tok));
    assert!(!hash.verify(&format!("{}x", tok.as_str())));
    assert!(!hash.verify(""));
    assert!(!hash.verify(&"a".repeat(10_000)));
}

#[test]
fn tokens_are_unique() {
    let dir = tempfile::tempdir().unwrap();
    let a = token::create(&dir.path().join("a"), Overwrite::No).unwrap();
    let b = token::create(&dir.path().join("b"), Overwrite::No).unwrap();
    assert_ne!(a, b);
}

#[test]
fn existing_file_is_not_overwritten_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.token");
    let first = token::create(&path, Overwrite::No).unwrap();
    let err = token::create(&path, Overwrite::No).unwrap_err();
    assert_eq!(err, Error::Io(std::io::ErrorKind::AlreadyExists));
    assert!(TokenHash::load(&path).unwrap().verify(&first));
    let second = token::create(&path, Overwrite::Yes).unwrap();
    let hash = TokenHash::load(&path).unwrap();
    assert!(hash.verify(&second));
    assert!(!hash.verify(&first));
}

#[cfg(unix)]
#[test]
fn token_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.token");
    let _ = token::create(&path, Overwrite::No).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn malformed_token_files_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad");
    let good_hex = "ab".repeat(32);
    for content in [
        String::new(),
        "kf1_klartext-token".to_owned(),
        format!("keyforge-token-v2 sha3-256 {good_hex}"),
        format!("keyforge-token-v1 sha3-256 {}", "AB".repeat(32)),
        format!("keyforge-token-v1 sha3-256 {}", "ab".repeat(31)),
    ] {
        std::fs::write(&path, content).unwrap();
        assert!(TokenHash::load(&path).is_err());
    }
    std::fs::write(&path, format!("keyforge-token-v1 sha3-256 {good_hex}\n")).unwrap();
    assert!(TokenHash::load(&path).is_ok());
    let missing = TokenHash::load(&dir.path().join("fehlt")).err();
    assert_eq!(missing, Some(Error::Io(std::io::ErrorKind::NotFound)));
}

#[test]
fn client_key_groups_ipv6_by_prefix() {
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    assert_eq!(client_key(ip("192.0.2.7")), ip("192.0.2.7"));
    assert_eq!(client_key(ip("::ffff:192.0.2.7")), ip("192.0.2.7"));
    assert_eq!(
        client_key(ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd")),
        client_key(ip("2001:db8:1:2::1"))
    );
    assert_ne!(
        client_key(ip("2001:db8:1:2::1")),
        client_key(ip("2001:db8:1:3::1"))
    );
}
