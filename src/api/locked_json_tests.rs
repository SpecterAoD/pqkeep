//! DE: Tatsächliche Parsergrenzen einschließlich Escape-Scratch prüfen.
//! EN: Inspect actual parser boundaries including escape scratch.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

struct Observed;
struct Observer;

impl Visitor<'_> for Observer {
    type Value = Observed;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("synthetic text")
    }
    fn visit_str<E: de::Error>(self, text: &str) -> Result<Observed, E> {
        assert!(memlock::is_locked(text.as_ptr().addr()));
        assert_eq!(text, "synthetic");
        Ok(Observed)
    }
}
impl<'de> Deserialize<'de> for Observed {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        de.deserialize_str(Observer)
    }
}

#[test]
fn borrowed_input_and_escaped_scratch_are_locked_at_the_visitor() {
    for input in [br#""synthetic""#.as_slice(), br#""syn\u0074hetic""#] {
        let bytes = SecretBytes::from_slice(input).unwrap();
        assert!(decode::<Observed>(bytes.expose()).is_ok());
    }
}

struct WipeProbe {
    inner: ScratchLock,
    wiped: Arc<AtomicBool>,
}
impl serde_json::de::ScratchProtection for WipeProbe {
    fn wipe(&mut self, scratch: &mut Vec<u8>) {
        assert!(memlock::is_locked(scratch.as_ptr().addr()));
        serde_json::de::ScratchProtection::wipe(&mut self.inner, scratch);
        assert_eq!(scratch.len(), scratch.capacity());
        assert!(scratch.iter().all(|b| *b == 0));
        assert!(memlock::is_locked(scratch.as_ptr().addr()));
        self.wiped.store(true, Ordering::SeqCst);
    }
}

#[test]
fn parser_wipes_complete_scratch_while_still_locked_on_success_and_error() {
    for input in [
        br#""syn\u0074hetic""#.as_slice(),
        br#""syn\u0074hetic" trailing"#,
    ] {
        let bytes = SecretBytes::from_slice(input).unwrap();
        let wiped = Arc::new(AtomicBool::new(false));
        let scratch = Vec::<u8>::with_capacity(input.len() + 128);
        let lock = memlock::lock_range(scratch.as_ptr().addr(), scratch.capacity());
        assert!(lock.complete(scratch.as_ptr().addr(), scratch.capacity()));
        let protection = WipeProbe {
            inner: ScratchLock { _lock: lock },
            wiped: wiped.clone(),
        };
        let mut parser = serde_json::Deserializer::from_slice_with_protection(
            bytes.expose(),
            scratch,
            Box::new(protection),
        )
        .unwrap();
        assert!(Observed::deserialize(&mut parser).is_ok());
        let _ = parser.end();
        drop(parser);
        assert!(wiped.load(Ordering::SeqCst));
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestFields {
    passphrase: crate::api::secret_input::SecretInput,
}

#[test]
fn request_secret_is_guarded_and_malformed_partial_requests_are_rejected() {
    let input = br#"{"passphrase":"synthetic"}"#;
    let bytes = SecretBytes::from_slice(input).unwrap();
    let fields = decode::<RequestFields>(bytes.expose()).unwrap();
    assert!(memlock::is_locked(
        fields.passphrase.0.expose().as_ptr().addr()
    ));
    for input in [
        br#"{"passphrase":"synthetic","unknown":1}"#.as_slice(),
        br#"{"passphrase":"synthetic","passphrase":"duplicate"}"#,
        br#"{"passphrase":"synthetic","unknown":"unfinished"#,
    ] {
        let bytes = SecretBytes::from_slice(input).unwrap();
        assert!(decode::<RequestFields>(bytes.expose()).is_err());
    }
}
