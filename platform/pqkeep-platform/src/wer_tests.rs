//! DE: Fehlerpfade dürfen keine verifizierte WER-Fähigkeit vortäuschen.
//! EN: Failure paths must never manufacture a verified WER capability.
#![allow(clippy::unwrap_used)]

use super::*;
use std::cell::Cell;

#[test]
fn sets_only_noheap_and_preserves_existing_flags() {
    let flags = Cell::new(4u32);
    ensure_noheap(
        || Ok(WerFlags::Present(flags.get())),
        |value| {
            assert_eq!(value, 4 | NOHEAP);
            flags.set(value);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(flags.get(), 4 | NOHEAP);
}

#[test]
fn already_enabled_is_read_back_without_policy_write() {
    let reads = Cell::new(0);
    let writes = Cell::new(0);
    ensure_noheap(
        || {
            reads.set(reads.get() + 1);
            Ok(WerFlags::Present(NOHEAP | 4))
        },
        |_| {
            writes.set(writes.get() + 1);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(reads.get(), 2);
    assert_eq!(writes.get(), 0);
}

#[test]
fn initial_query_error_prevents_policy_write() {
    let writes = Cell::new(0);
    let result = ensure_noheap(
        || Err(io::ErrorKind::PermissionDenied.into()),
        |_| {
            writes.set(writes.get() + 1);
            Ok(())
        },
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(writes.get(), 0);
}

#[test]
fn set_error_does_not_attempt_or_claim_verification() {
    let reads = Cell::new(0);
    let result = ensure_noheap(
        || {
            reads.set(reads.get() + 1);
            Ok(WerFlags::Present(0))
        },
        |_| Err(io::ErrorKind::PermissionDenied.into()),
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(reads.get(), 1);
}

#[test]
fn missing_mitigation_or_lost_existing_flags_are_rejected() {
    for after in [0, 4, NOHEAP] {
        let reads = Cell::new(0);
        let result = ensure_noheap(
            || {
                let call = reads.get();
                reads.set(call + 1);
                Ok(WerFlags::Present(if call == 0 { 4 } else { after }))
            },
            |_| Ok(()),
        );
        assert!(result.is_err());
        assert_eq!(reads.get(), 2);
    }
}

#[test]
fn failed_readback_is_not_success() {
    let reads = Cell::new(0);
    let result = ensure_noheap(
        || {
            let call = reads.get();
            reads.set(call + 1);
            if call == 0 {
                Ok(WerFlags::Present(0))
            } else {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        },
        |_| Ok(()),
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
}

#[test]
fn explicit_absence_requires_initialization_and_actual_readback() {
    let state = Cell::new(WerFlags::Absent);
    ensure_noheap(
        || Ok(state.get()),
        |flags| {
            assert_eq!(flags, NOHEAP);
            state.set(WerFlags::Present(flags));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(state.get(), WerFlags::Present(NOHEAP));
}

#[test]
fn persistent_absence_after_initialization_is_rejected() {
    assert!(ensure_noheap(|| Ok(WerFlags::Absent), |_| Ok(())).is_err());
}
