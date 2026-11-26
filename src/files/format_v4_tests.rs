#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

#[test]
fn trailer_roundtrip_and_rejections() {
    let t = trailer(1234, 0);
    assert_eq!(check_trailer(&t, 1234, false), Ok(1234));
    assert!(check_trailer(&t, 1233, false).is_err());
    assert!(
        check_trailer(&t, 1234, true).is_err(),
        "PAD verlangt Füllung / PAD needs padding"
    );
    let mut padded = t;
    padded[8] = 1;
    assert!(check_trailer(&padded, 1235, false).is_err());
    let mut magic = t;
    magic[TRAILER_LEN - 1] = 1;
    assert!(check_trailer(&magic, 1234, false).is_err());
    assert!(check_trailer(&t[..TRAILER_LEN - 1], 1234, false).is_err());
    // DE: Kanonische PADMÉ-Füllung. EN: Canonical PADMÉ padding.
    let pad = padding_for(1234, true).unwrap();
    let good = trailer(1234, pad);
    assert_eq!(check_trailer(&good, 1234 + pad, true), Ok(1234));
    let other = trailer(1234, pad + 1);
    assert!(check_trailer(&other, 1235 + pad, true).is_err());
}

#[test]
fn option_rules() {
    let v4 = |options| V4 {
        options,
        commit: [7; 32],
    };
    assert!(check_v4(Content::Stream, &v4(0), None).is_ok());
    for reserved in [OPT_ANON, OPT_HIDDEN_SENDER, 0x0010, 0x8000] {
        assert_eq!(
            check_v4(Content::Stream, &v4(reserved), None),
            Err(Error::Unsupported)
        );
    }
    assert!(check_v4(Content::File, &v4(0), None).is_err());
    assert!(check_v4(Content::File, &v4(OPT_PAD), None).is_ok());
    assert!(check_v4(Content::Directory, &v4(OPT_PAD), None).is_ok());
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

/// DE: Referenzwerte aus `scripts/v4_padme_reference.py` (unabhängige Python-Umsetzung, P06).
/// EN: Reference values from `scripts/v4_padme_reference.py` (independent Python version, P06).
#[test]
fn padme_reference_values() {
    for (len, padded) in PADME_VECTORS {
        assert_eq!(padme(*len).unwrap(), *padded, "{len}");
    }
    assert!(padme(u64::MAX).is_err());
}

/// DE: Mit `python3 scripts/v4_padme_reference.py` erzeugt und per `--check` abgeglichen.
/// EN: Generated with `python3 scripts/v4_padme_reference.py` and cross-checked via `--check`.
#[rustfmt::skip]
const PADME_VECTORS: &[(u64, u64)] = &[
    (24, 24),
    (25, 26),
    (31, 32),
    (1_000, 1_024),
    (1_024, 1_024),
    (65_560, 67_584),
    (1_000_000, 1_015_808),
    (123_456_789, 123_731_968),
    (1_099_511_627_777, 1_116_691_496_960),
    (4_611_686_018_427_400_249, 4_683_743_612_465_315_840),
];
