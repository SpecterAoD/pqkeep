//! DE: Echte Besuchersperren und verschachtelte private Fehlerscopes.
//! EN: Actual visitor-time locks and nested private error scopes.
#![allow(clippy::unwrap_used)]

use super::*;
use serde::de::{self, Visitor};
use std::{cell::Cell, fmt};

thread_local! {
    static BOUNDS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    static FORMATTED: Cell<usize> = const { Cell::new(0) };
    static VISITED: Cell<bool> = const { Cell::new(false) };
}

struct AtVisitor;
impl Visitor<'_> for AtVisitor {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("public synthetic text")
    }
    fn visit_str<E: de::Error>(self, text: &str) -> Result<(), E> {
        BOUNDS.with(|bounds| {
            let (first, last) = bounds.get();
            for address in [first, last, text.as_ptr().addr()] {
                assert!(memlock::is_locked(address));
                #[cfg(target_os = "linux")]
                assert!(crate::locked_owner_test_support::own_mapping_locked(
                    address
                ));
            }
        });
        VISITED.with(|visited| visited.set(true));
        Ok(())
    }
}

struct Observed;
impl<'de> serde::Deserialize<'de> for Observed {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        de.deserialize_str(AtVisitor)?;
        Ok(Self)
    }
}

#[test]
fn actual_parser_and_borrowed_or_escaped_payload_stay_kernel_locked_inside_visitor() {
    for input in [br#""synthetic""#.as_slice(), br#""syn\u0074hetic""#] {
        let bytes = SecretBytes::from_slice(input).unwrap();
        let mut state = empty().unwrap();
        locked(&state.get().0);
        let first = std::ptr::from_ref(&state.get().0).addr();
        VISITED.with(|visited| visited.set(false));
        BOUNDS.with(|bounds| bounds.set((first, first + size_of_val(&state.get().0) - 1)));
        state
            .get_mut()
            .0
            .prepare_protected_scratch(input.len() + 128, protect)
            .unwrap();
        assert!(
            state
                .get_mut()
                .0
                .deserialize_protected_slice::<Observed>(bytes.expose())
                .is_ok()
        );
        assert!(VISITED.with(Cell::get));
    }
}

struct Detail;
impl fmt::Display for Detail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        FORMATTED.with(|count| count.set(count.get() + 1));
        f.write_str("public synthetic detail")
    }
}

struct Nested;
impl Visitor<'_> for Nested {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("synthetic nested input")
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        let bytes = SecretBytes::from_slice(b"null").map_err(|_| E::custom("lock unavailable"))?;
        assert!(decode::<IgnoredAny>(bytes.expose()).is_ok());
        Err(E::custom(Detail))
    }
}
impl<'de> serde::Deserialize<'de> for Nested {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        de.deserialize_str(Self)?;
        Ok(Self)
    }
}

#[test]
fn nested_protected_parser_preserves_outer_scope_and_restores_public_errors() {
    FORMATTED.with(|count| count.set(0));
    let bytes = SecretBytes::from_slice(br#""synthetic""#).unwrap();
    let mut state = empty().unwrap();
    state
        .get_mut()
        .0
        .prepare_protected_scratch(bytes.expose().len() + 128, protect)
        .unwrap();
    let private = state
        .get_mut()
        .0
        .deserialize_protected_slice::<Nested>(bytes.expose())
        .err()
        .unwrap();
    assert!(private.is_data());
    assert_eq!((private.line(), private.column()), (0, 0));
    assert_eq!(FORMATTED.with(Cell::get), 0);
    let ordinary = serde_json::from_slice::<Nested>(bytes.expose())
        .err()
        .unwrap();
    assert!(ordinary.is_data() && ordinary.line() > 0 && ordinary.column() > 0);
    assert_eq!(FORMATTED.with(Cell::get), 1);
}
