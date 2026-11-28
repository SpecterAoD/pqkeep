//! DE: Geschütztes Framing gegen explizit öffentliche Referenzbytes prüfen.
//! EN: Compare protected framing with explicitly public reference bytes.
#![allow(clippy::unwrap_used)]

use super::*;
use sha3::Digest;

#[test]
fn words_and_trailers_match_public_reference_at_integer_boundaries() {
    for value in [0, 1, 255, 256, u64::from(u32::MAX) + 1, u64::MAX] {
        let mut bytes = SecretBytes::zeroed(8).unwrap();
        write_word(bytes.expose_mut(), value).unwrap();
        let equal = bytes.expose() == value.to_le_bytes();
        assert!(equal);
        assert_eq!(read_word(bytes.expose()).unwrap(), value);
        let tail = trailer(value, u64::MAX - value).unwrap();
        tail.assert_metadata_locked();
        crate::locked_owner_test_support::locked(tail.expose());
        let expected = [
            value.to_le_bytes().as_slice(),
            (u64::MAX - value).to_le_bytes().as_slice(),
            TRAILER_MAGIC,
        ]
        .concat();
        let equal = tail.expose() == expected;
        assert!(equal);
    }
    assert!(write_word(&mut [0; 7], 1).is_err());
    assert!(read_word(&[0; 9]).is_err());
}

#[test]
fn hidden_message_matches_public_reference_without_changing_domain_or_lengths() {
    let header = b"public header fixture";
    let plain_hash = Sha3_512::digest(b"public synthetic plaintext fixture");
    for (payload, pad) in [
        (0u64, 0u64),
        (1, 255),
        (u64::from(u32::MAX) + 1, u64::MAX),
        (u64::MAX, 0),
    ] {
        let output = message(header, &plain_hash, payload, pad).unwrap();
        output.assert_metadata_locked();
        crate::locked_owner_test_support::locked(output.expose());
        let expected = [
            DOMAIN_V4,
            b"sig/hidden\0",
            Sha3_512::digest(header).as_slice(),
            plain_hash.as_slice(),
            &payload.to_le_bytes(),
            &pad.to_le_bytes(),
        ]
        .concat();
        let equal = output.expose() == expected;
        assert!(equal);
    }
    assert!(matches!(
        message(header, &[0; 63], 0, 0),
        Err(Error::Crypto)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn framing_denial_and_unwind_preserve_parent_policy() {
    use rustix::process::{Resource, getrlimit};
    let before = getrlimit(Resource::Memlock);
    crate::locked_owner_test_support::isolated_test(
        "files::confidential_framing::tests::framing_denial_child",
        "PQKEEP_FRAMING_DENIAL_CHILD",
    );
    assert_eq!(getrlimit(Resource::Memlock), before);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "DE/EN: Nur eigenes begrenztes Kind / bounded owned child only"]
fn framing_denial_child() {
    use crate::hardening::memlock;
    use rustix::process::{Resource, getrlimit, setrlimit};
    assert_eq!(std::env::var("PQKEEP_FRAMING_DENIAL_CHILD").unwrap(), "1");
    let baseline = memlock::stats().locked_pages;
    let unwind = std::panic::catch_unwind(|| {
        let _message = message(b"public header", &[0; 64], 1234, 256).unwrap();
        let _trailer = trailer(1234, 256).unwrap();
        std::panic::resume_unwind(Box::new(()));
    });
    assert!(unwind.is_err());
    assert_eq!(memlock::stats().locked_pages, baseline);
    let mut limit = getrlimit(Resource::Memlock);
    limit.current = Some(0);
    setrlimit(Resource::Memlock, limit).unwrap();
    let failures = memlock::stats().failed_attempts;
    assert!(matches!(
        message(b"public header", &[0; 64], 1234, 256),
        Err(Error::MemoryLock)
    ));
    assert!(matches!(trailer(1234, 256), Err(Error::MemoryLock)));
    assert!(memlock::stats().failed_attempts >= failures + 2);
    assert_eq!(memlock::stats().locked_pages, baseline);
}
