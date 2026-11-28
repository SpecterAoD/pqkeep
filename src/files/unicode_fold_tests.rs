//! DE: Öffentliche vollständige Unicode-Referenz und echte Mehrfachauswahl prüfen.
//! EN: Verify a public exhaustive Unicode oracle and actual multi-selection.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::{Error, crypto::SecretBytes};

#[test]
fn every_unicode_scalar_matches_existing_sigma_conservative_folding() {
    let mut target = SecretBytes::zeroed(12).unwrap();
    for scalar in 0..=0x0010_ffff {
        let Some(c) = char::from_u32(scalar) else {
            continue;
        };
        let expected: String = c
            .to_lowercase()
            .map(|v| if v == 'ς' { 'σ' } else { v })
            .collect();
        assert_eq!(size(c), expected.len());
        target.expose_mut().fill(0xa5);
        let written = write(c, target.expose_mut());
        assert_eq!(written, expected.len());
        assert_eq!(&target.expose()[..written], expected.as_bytes());
        assert!(target.expose()[written..].iter().all(|&v| v == 0xa5));
    }
    assert!(FOLD.windows(2).all(|pair| pair[0].0 < pair[1].0));
}

#[test]
fn actual_selection_rejects_names_that_its_archive_reader_would_reject() {
    for (left, right) in [("ΟΣ", "οσ"), ("ος", "οσ"), ("İ", "i\u{307}"), ("A", "a")] {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first");
        let second = root.path().join("second");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&second).unwrap();
        let a = first.join(left);
        let b = second.join(right);
        std::fs::write(&a, b"public fixture").unwrap();
        std::fs::write(&b, b"public fixture").unwrap();
        let rejected = matches!(
            super::super::walk::collect_many(&[&a, &b]),
            Err(Error::InvalidInput { field: "duplicate" })
        );
        assert!(rejected);
    }
}

#[test]
fn actual_selection_keeps_distinct_names_and_original_unicode_bytes() {
    let root = tempfile::tempdir().unwrap();
    let a = root.path().join("İ");
    let b = root.path().join("日本語");
    std::fs::write(&a, b"public fixture").unwrap();
    std::fs::write(&b, b"public fixture").unwrap();
    let (entries, skipped) = super::super::walk::collect_many(&[&b, &a]).unwrap();
    let no_skipped = skipped.is_empty();
    assert!(no_skipped);
    assert_eq!(entries.len(), 2);
    let equal = entries.get(0).unwrap().path().unwrap() == "İ"
        && entries.get(1).unwrap().path().unwrap() == "日本語";
    assert!(equal);
}
