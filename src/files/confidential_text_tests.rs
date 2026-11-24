//! DE: Lebende private Namensdescriptoren und unveränderte Textverträge.
//! EN: Live private name descriptors and preserved text contracts.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock;

impl ConfidentialText {
    pub(crate) fn assert_owner_locked(&self) {
        crate::files::locked_owner_tests::locked(self.0.get());
        self.0.get().assert_metadata_locked();
        if !self.bytes().is_empty() {
            assert!(memlock::is_locked(self.bytes().as_ptr().addr()));
            assert!(memlock::is_locked(
                self.bytes().as_ptr().addr() + self.bytes().len() - 1
            ));
        }
    }
}

#[test]
fn owner_is_locked_before_private_fill_and_stable_after_moves() {
    let mut text = ConfidentialText::prepare().unwrap();
    text.assert_owner_locked();
    let owner = std::ptr::from_ref(text.0.get()).addr();
    let source = ConfidentialText::from_text("Ä/日本語").unwrap();
    text.copy_from(&source).unwrap();
    let moved = Box::new(text);
    assert!(std::ptr::from_ref(moved.0.get()).addr() == owner);
    moved.assert_owner_locked();
    assert_eq!(moved.expose().unwrap(), "Ä/日本語");
}

#[test]
fn text_order_borrow_redaction_and_duplicate_remain_compatible() {
    let text = ConfidentialText::from_text("Ä/name").unwrap();
    let duplicate = text.try_duplicate().unwrap();
    text.assert_owner_locked();
    duplicate.assert_owner_locked();
    assert_eq!(text, duplicate);
    assert!(!std::ptr::eq(
        text.bytes().as_ptr(),
        duplicate.bytes().as_ptr()
    ));
    let borrowed: &[u8] = text.borrow();
    assert_eq!(borrowed, "Ä/name".as_bytes());
    assert_eq!(format!("{text:?}"), "[REDACTED]");
    assert!(ConfidentialText::from_text("a").unwrap() < text);
}

#[test]
fn explicit_zeroize_preserves_empty_text_and_locked_owner() {
    let mut text = ConfidentialText::from_text("private metadata fixture").unwrap();
    let owner = std::ptr::from_ref(text.0.get()).addr();
    text.zeroize();
    text.assert_owner_locked();
    assert!(std::ptr::from_ref(text.0.get()).addr() == owner);
    assert_eq!(text.expose().unwrap(), "");
    let borrowed: &[u8] = text.borrow();
    assert_eq!(borrowed, b"");
    text.zeroize();
    text.copy_from(&ConfidentialText::from_text("next").unwrap())
        .unwrap();
    text.assert_owner_locked();
    assert_eq!(text.expose().unwrap(), "next");
}

#[test]
fn locked_transfer_keeps_bytes_and_rejects_invalid_utf8() {
    let bytes = SecretBytes::from_slice("Ä/name".as_bytes()).unwrap();
    let pointer = bytes.expose().as_ptr();
    let text = ConfidentialText::from_locked(bytes).unwrap();
    text.assert_owner_locked();
    assert!(std::ptr::eq(text.bytes().as_ptr(), pointer));
    assert!(matches!(
        ConfidentialText::from_locked(SecretBytes::from_slice(&[0xff]).unwrap()),
        Err(Error::InvalidInput { field: "path" })
    ));
}
