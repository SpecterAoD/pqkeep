//! DE: Lebender gesperrter Parser und kompatibles Deserialisieren.
//! EN: Actual locked parser ownership and compatible deserialization.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{crypto::SecretBytes, hardening::memlock, locked_owner_test_support::locked};
use serde::de::IgnoredAny;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

thread_local! { static VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

struct Counted;
impl<'de> serde::Deserialize<'de> for Counted {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        VISITS.with(|count| count.set(count.get() + 1));
        let _ = IgnoredAny::deserialize(de)?;
        Ok(Self)
    }
}

fn protect(
    address: usize,
    capacity: usize,
) -> Result<Box<dyn serde_json::de::ScratchProtection>, ApiError> {
    Ok(Box::new(ScratchLock::new(address, capacity)?))
}

#[test]
fn whole_parser_is_locked_before_scratch_allocation_and_stable_after_moves() {
    let bytes = SecretBytes::from_slice(br#""syn\u0074hetic""#).unwrap();
    let mut state = empty().unwrap();
    locked(&state.get().0);
    let address = std::ptr::from_ref(&state.get().0).addr();
    state
        .get_mut()
        .0
        .prepare_protected_scratch(bytes.expose().len() + 128, |ptr, cap| {
            assert!(memlock::is_locked(address));
            protect(ptr, cap)
        })
        .unwrap();
    let mut moved = Box::new(state);
    assert_eq!(std::ptr::from_ref(&moved.get().0).addr(), address);
    locked(&moved.get().0);
    let secret = moved
        .get_mut()
        .0
        .deserialize_protected_slice::<crate::api::secret_input::SecretInput>(bytes.expose())
        .unwrap();
    assert!(memlock::is_locked(secret.0.expose().as_ptr().addr()));
    locked(&moved.get().0);
    assert!(
        moved
            .get_mut()
            .0
            .deserialize_protected_slice::<IgnoredAny>(bytes.expose())
            .is_err()
    );
}

struct WipeProbe {
    inner: ScratchLock,
    parser: usize,
    wiped: Arc<AtomicBool>,
}

impl serde_json::de::ScratchProtection for WipeProbe {
    fn wipe(&mut self, scratch: &mut Vec<u8>) {
        assert!(memlock::is_locked(self.parser));
        locked(self.inner.range.get());
        assert!(scratch.iter().any(|byte| *byte != 0));
        serde_json::de::ScratchProtection::wipe(&mut self.inner, scratch);
        assert_eq!(scratch.len(), scratch.capacity());
        assert!(scratch.iter().all(|byte| *byte == 0));
        assert!(memlock::is_locked(scratch.as_ptr().addr()));
        self.wiped.store(true, Ordering::SeqCst);
    }
}

struct Unwind;
impl<'de> serde::Deserialize<'de> for Unwind {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let _secret = crate::api::secret_input::SecretInput::deserialize(de)?;
        std::panic::resume_unwind(Box::new(()))
    }
}

#[test]
fn prelocked_parser_wipes_live_scratch_on_success_error_and_unwind() {
    for mode in ["success", "error", "unwind"] {
        let input = if mode == "error" {
            br#""syn\u0074hetic" trailing"#.as_slice()
        } else {
            br#""syn\u0074hetic""#
        };
        let bytes = SecretBytes::from_slice(input).unwrap();
        let wiped = Arc::new(AtomicBool::new(false));
        let mut state = empty().unwrap();
        let parser = std::ptr::from_ref(&state.get().0).addr();
        state
            .get_mut()
            .0
            .prepare_protected_scratch(input.len() + 128, |ptr, cap| {
                Ok::<_, ApiError>(Box::new(WipeProbe {
                    inner: ScratchLock::new(ptr, cap)?,
                    parser,
                    wiped: Arc::clone(&wiped),
                })
                    as Box<dyn serde_json::de::ScratchProtection>)
            })
            .unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut state = state;
            if mode == "unwind" {
                let _ = state
                    .get_mut()
                    .0
                    .deserialize_protected_slice::<Unwind>(bytes.expose());
            } else {
                let parsed = state
                    .get_mut()
                    .0
                    .deserialize_protected_slice::<crate::api::secret_input::SecretInput>(
                        bytes.expose(),
                    );
                assert_eq!(parsed.is_ok(), mode == "success");
            }
        }));
        assert_eq!(result.is_err(), mode == "unwind");
        assert!(wiped.load(Ordering::SeqCst));
        let ordinary = serde_json::from_slice::<String>(b"\n false").err().unwrap();
        assert!(ordinary.line() > 0 && ordinary.column() > 0);
    }
}

#[test]
fn protected_parser_matches_public_synthetic_json_corpus() {
    let mut corpus = vec![
        b"null".to_vec(),
        b"true".to_vec(),
        b"[-1,1.25e2,\"\\uD834\\uDD1E\"]".to_vec(),
        b"{\"a\":[1,{\"b\":false}]}".to_vec(),
        b"[1] false".to_vec(),
        b"\"\xff\"".to_vec(),
        b"\"\\uD800\"".to_vec(),
    ];
    corpus.push(format!("\"{}\"", "\\u0061".repeat(1500)).into_bytes());
    for depth in [1, 127, 128, 129] {
        corpus.push(format!("{}0{}", "[".repeat(depth), "]".repeat(depth)).into_bytes());
    }
    for input in corpus {
        let ordinary = serde_json::from_slice::<serde_json::Value>(&input);
        let bytes = SecretBytes::from_slice(&input).unwrap();
        let private = decode::<serde_json::Value>(bytes.expose());
        assert_eq!(private.is_ok(), ordinary.is_ok());
        if let (Ok(private), Ok(ordinary)) = (private, ordinary) {
            assert_eq!(private, ordinary);
        }
    }
}

#[test]
fn iterative_ignored_containers_preserve_input_bound_above_recursion128() {
    let input = format!("{}0{}", "[".repeat(5000), "]".repeat(5000));
    assert!(serde_json::from_slice::<IgnoredAny>(input.as_bytes()).is_ok());
    let bytes = SecretBytes::from_slice(input.as_bytes()).unwrap();
    assert!(decode::<IgnoredAny>(bytes.expose()).is_ok());
}

#[test]
fn preparation_rejects_invalid_state_capacity_and_callback_denial_before_binding() {
    use serde_json::de::ProtectedScratchError::{Allocation, Protection, Unsupported};
    let mut state = empty().unwrap();
    assert!(
        state
            .get_mut()
            .0
            .deserialize_protected_slice::<Counted>(b"true")
            .is_err()
    );
    assert!(matches!(
        state.get_mut().0.prepare_protected_scratch(127, protect),
        Err(Unsupported)
    ));
    assert!(matches!(
        state
            .get_mut()
            .0
            .prepare_protected_scratch(usize::MAX, protect),
        Err(Allocation)
    ));
    assert!(matches!(
        state
            .get_mut()
            .0
            .prepare_protected_scratch(128, |_, _| Err::<
                Box<dyn serde_json::de::ScratchProtection>,
                _,
            >(ApiError::Busy)),
        Err(Protection(ApiError::Busy))
    ));
    assert!(
        state
            .get_mut()
            .0
            .deserialize_protected_slice::<Counted>(b"true")
            .is_err()
    );
    assert!(matches!(
        state.get_mut().0.prepare_protected_scratch(128, protect),
        Err(Unsupported)
    ));
    assert_eq!(VISITS.with(std::cell::Cell::get), 0);
}

#[test]
fn prepared_parser_refuses_repreparation_and_oversized_binding_without_losing_guard() {
    let mut oversized = Vec::new();
    let mut state = empty().unwrap();
    let mut actual = 0;
    state
        .get_mut()
        .0
        .prepare_protected_scratch(128, |ptr, cap| {
            actual = cap;
            protect(ptr, cap)
        })
        .unwrap();
    assert!(
        state
            .get_mut()
            .0
            .prepare_protected_scratch(128, protect)
            .is_err()
    );
    oversized.resize(actual + 1, b' ');
    assert!(
        state
            .get_mut()
            .0
            .deserialize_protected_slice::<Counted>(&oversized)
            .is_err()
    );
    assert_eq!(VISITS.with(std::cell::Cell::get), 0);
    assert!(
        state
            .get_mut()
            .0
            .deserialize_protected_slice::<IgnoredAny>(b"")
            .err()
            .unwrap()
            .is_eof()
    );
    assert!(
        state
            .get_mut()
            .0
            .deserialize_protected_slice::<IgnoredAny>(b"")
            .err()
            .unwrap()
            .is_io()
    );
    drop(state);
}

#[test]
fn protected_parser_numeric_mode_contract_matches_explicit_build_probe() {
    let expected =
        std::env::var("PQKEEP_PARSER_MODE_EXPECTED").unwrap_or_else(|_| "supported".into());
    assert!(matches!(expected.as_str(), "supported" | "unsupported"));
    let mut state = empty().unwrap();
    let result = state.get_mut().0.prepare_protected_scratch(132, protect);
    if expected == "supported" {
        result.unwrap();
        assert!(
            state
                .get_mut()
                .0
                .deserialize_protected_slice::<IgnoredAny>(b"true")
                .is_ok()
        );
    } else {
        assert!(matches!(
            result,
            Err(serde_json::de::ProtectedScratchError::Unsupported)
        ));
        assert!(
            state
                .get_mut()
                .0
                .deserialize_protected_slice::<Counted>(b"true")
                .err()
                .unwrap()
                .is_io()
        );
        assert_eq!(VISITS.with(std::cell::Cell::get), 0);
    }
}

#[cfg(target_os = "linux")]
#[path = "locked_parser_denial_tests.rs"]
mod denial;

#[path = "locked_parser_scope_tests.rs"]
mod scope;
