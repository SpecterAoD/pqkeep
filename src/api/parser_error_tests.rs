//! DE: Private Fehlermeldungen dürfen vor dem Verwerfen nicht formatiert werden.
//! EN: Private error details must never be formatted before being discarded.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock;
use serde::{
    Deserialize, Deserializer,
    de::{self, Visitor},
};
use std::{cell::Cell, fmt};

thread_local! { static FORMATTED: Cell<usize> = const { Cell::new(0) }; }

struct PrivateDetail<'a>(&'a str);
impl fmt::Display for PrivateDetail<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        FORMATTED.with(|count| count.set(count.get() + 1));
        f.write_str(self.0)
    }
}

struct Reject;
struct RejectVisitor;
impl Visitor<'_> for RejectVisitor {
    type Value = Reject;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a synthetic fixture")
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Reject, E> {
        Err(E::custom(PrivateDetail(value)))
    }
}
impl<'a> Deserialize<'a> for Reject {
    fn deserialize<D: Deserializer<'a>>(de: D) -> Result<Self, D::Error> {
        de.deserialize_str(RejectVisitor)
    }
}

fn ordinary_error_is_restored() {
    let error = serde_json::from_str::<Reject>(r#""synthetic""#)
        .err()
        .unwrap();
    assert!(error.to_string().contains("synthetic"));
    assert_eq!(FORMATTED.with(Cell::get), 1);
}

#[test]
fn protected_rejected_values_are_never_formatted_and_normal_errors_are_restored() {
    FORMATTED.with(|count| count.set(0));
    for input in [br#""synthetic""#.as_slice(), br#""syn\u0074hetic""#] {
        let bytes = SecretBytes::from_slice(input).unwrap();
        assert!(memlock::is_locked(bytes.expose().as_ptr().addr()));
        assert!(matches!(
            decode::<Reject>(bytes.expose()),
            Err(ApiError::BadRequest)
        ));
        assert_eq!(FORMATTED.with(Cell::get), 0);
    }
    let bytes = SecretBytes::from_slice(br#""synthetic""#).unwrap();
    assert!(decode::<de::IgnoredAny>(bytes.expose()).is_ok());
    ordinary_error_is_restored();
}

struct Unwind;
impl<'a> Deserialize<'a> for Unwind {
    fn deserialize<D: Deserializer<'a>>(_: D) -> Result<Self, D::Error> {
        std::panic::resume_unwind(Box::new("synthetic parser unwind"))
    }
}

#[test]
fn protected_error_scope_is_restored_on_unwind() {
    FORMATTED.with(|count| count.set(0));
    let bytes = SecretBytes::from_slice(br#""synthetic""#).unwrap();
    assert!(std::panic::catch_unwind(|| decode::<Unwind>(bytes.expose())).is_err());
    ordinary_error_is_restored();
}
