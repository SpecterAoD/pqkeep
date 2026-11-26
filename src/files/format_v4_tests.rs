#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

#[test]
fn trailer_roundtrip_and_rejections() {
    let t = trailer(1234);
    assert!(check_trailer(&t, 1234).is_ok());
    assert!(check_trailer(&t, 1233).is_err());
    let mut padded = t;
    padded[8] = 1;
    assert!(check_trailer(&padded, 1234).is_err());
    let mut magic = t;
    magic[TRAILER_LEN - 1] = 1;
    assert!(check_trailer(&magic, 1234).is_err());
    assert!(check_trailer(&t[..TRAILER_LEN - 1], 1234).is_err());
}

#[test]
fn option_rules() {
    let v4 = |options| V4 {
        options,
        commit: [7; 32],
    };
    assert!(check_v4(Content::Stream, &v4(0), None).is_ok());
    for reserved in [OPT_PAD, OPT_ANON, OPT_HIDDEN_SENDER, 0x0010, 0x8000] {
        assert_eq!(
            check_v4(Content::Stream, &v4(reserved), None),
            Err(Error::Unsupported)
        );
    }
    assert!(check_v4(Content::File, &v4(0), None).is_err());
    assert!(check_v4(Content::Directory, &v4(0), None).is_err());
    assert!(check_v4(Content::Stream, &v4(OPT_SIGNED), None).is_err());
}

#[test]
fn commit_v4_differs_from_v3_and_checks() {
    let key = [9u8; 32];
    let c4 = commit_v4(&key).unwrap();
    assert_ne!(c4, super::super::signer_v3::commit(&key).unwrap());
    let v4 = V4 {
        options: 0,
        commit: c4,
    };
    assert!(check_commit_v4(&v4, &key).is_ok());
    assert_eq!(check_commit_v4(&v4, &[8u8; 32]), Err(Error::Decrypt));
}
