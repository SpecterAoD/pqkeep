//! DE: Private Positionsdaten nicht persistieren; öffentliche Diagnose erhalten.
//! EN: Do not retain private positions; preserve ordinary diagnostics.
#![allow(clippy::unwrap_used)]

use super::*;
use serde::de::IgnoredAny;

fn protected_error(input: &[u8]) -> serde_json::Error {
    let bytes = SecretBytes::from_slice(input).unwrap();
    let scratch = Vec::<u8>::with_capacity(input.len() + 128);
    let protection = ScratchLock::new(scratch.as_ptr().addr(), scratch.capacity()).unwrap();
    serde_json::de::from_slice_with_protection::<IgnoredAny>(
        bytes.expose(),
        scratch,
        Box::new(protection),
    )
    .err()
    .unwrap()
}

#[test]
fn private_syntax_positions_are_discarded_before_retention() {
    for input in [b"[\n  1,".as_slice(), b"{\n  x:1}", b"[1] false", b"[1,]"] {
        let ordinary = serde_json::from_slice::<IgnoredAny>(input).err().unwrap();
        assert!(ordinary.line() > 0 && ordinary.column() > 0);
        let private = protected_error(input);
        assert_eq!(private.classify(), ordinary.classify());
        assert_eq!((private.line(), private.column()), (0, 0));
        let restored = serde_json::from_slice::<IgnoredAny>(input).err().unwrap();
        assert_eq!(restored.to_string(), ordinary.to_string());
    }
}

#[test]
fn private_custom_error_does_not_restore_positions_after_redaction() {
    let bytes = SecretBytes::from_slice(b"\n  false").unwrap();
    let scratch = Vec::<u8>::with_capacity(bytes.expose().len() + 128);
    let protection = ScratchLock::new(scratch.as_ptr().addr(), scratch.capacity()).unwrap();
    let private = serde_json::de::from_slice_with_protection::<String>(
        bytes.expose(),
        scratch,
        Box::new(protection),
    )
    .err()
    .unwrap();
    assert!(private.is_data());
    assert_eq!((private.line(), private.column()), (0, 0));
    let ordinary = serde_json::from_slice::<String>(bytes.expose())
        .err()
        .unwrap();
    assert_eq!((ordinary.line(), ordinary.column()), (2, 7));
}
