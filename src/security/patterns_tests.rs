//! DE: Gesperrte Positionsmasken vor und nach Mustererkennung.
//! EN: Locked position masks before and after pattern detection.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock;

#[test]
fn fresh_mask_is_locked_before_marking_and_keeps_its_address() {
    let mut marked = mask(super::super::INPUT_LIMIT_CHARS).unwrap();
    let first = marked.expose().as_ptr().addr();
    let last = first + size_of_val(marked.expose()) - 1;
    assert!(memlock::is_locked(first));
    assert!(memlock::is_locked(last));
    assert!(marked.expose().iter().all(|value| !value));
    let chars: Vec<_> = std::iter::repeat_n('a', marked.expose().len()).collect();
    assert!(mark_runs(&chars, marked.expose_mut(), |a, b| a == b));
    assert!(marked.expose().iter().all(|value| *value));
    assert_eq!(marked.expose().as_ptr().addr(), first);
    assert!(memlock::is_locked(first));
    assert!(memlock::is_locked(last));
}

#[test]
fn returned_pattern_mask_stays_locked_and_empty_input_is_defined() {
    let chars: Vec<_> = std::iter::repeat_n('a', 32).collect();
    let found = find(&chars).unwrap();
    assert!(found.reasons.contains(&Reason::Repetition));
    assert!(found.marked.expose().iter().all(|value| *value));
    let first = found.marked.expose().as_ptr().addr();
    assert!(memlock::is_locked(first));
    assert!(memlock::is_locked(
        first + size_of_val(found.marked.expose()) - 1
    ));
    let empty = find(&[]).unwrap();
    assert_eq!(empty.marked.expose(), [] as [bool; 0]);
    assert_eq!(empty.reasons, [] as [Reason; 0]);
}
