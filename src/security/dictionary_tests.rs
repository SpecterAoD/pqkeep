//! DE: Lebende gesperrte Metadaten und Wörterbuchgrenzen mit öffentlichen Testdaten.
//! EN: Live locked metadata and dictionary boundaries using public test data.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock;

fn locked<T: Zeroize>(buffer: &SecretWorkspace<T>)
where
    crate::crypto::secret_buffer::SecretBuffer<T>: zeroize::ZeroizeOnDrop,
{
    buffer.assert_metadata_locked();
    let slice = buffer.expose();
    if !slice.is_empty() {
        let first = slice.as_ptr().addr();
        assert!(memlock::is_locked(first));
        assert!(memlock::is_locked(first + size_of_val(slice) - 1));
    }
}

#[test]
fn word_span_owner_is_locked_before_population_and_after_explicit_wiping() {
    let mut spans = SecretWorkspace::<WordSpan>::with_capacity(1).unwrap();
    spans.assert_metadata_locked();
    spans
        .push_preallocated(WordSpan { start: 3, end: 8 })
        .unwrap();
    locked(&spans);
    assert_eq!(spans.expose()[0].range(), 3..8);
    spans.zeroize();
    assert!(spans.expose().is_empty());
    spans.assert_metadata_locked();
}

#[test]
fn utf8_offsets_are_locked_with_exact_character_boundaries() {
    let chars: Vec<_> = "aä🦀中".chars().collect();
    let (text, offsets) = encode(&chars).unwrap();
    assert!(text.is_locked());
    locked(&offsets);
    assert_eq!(text.expose(), "aä🦀中".as_bytes());
    assert_eq!(offsets.expose(), &[0, 1, 3, 7, 10]);
    let (empty, offsets) = encode(&[]).unwrap();
    assert_eq!(empty.expose(), [] as [u8; 0]);
    locked(&offsets);
    assert_eq!(offsets.expose(), &[0]);
}

#[test]
fn dictionary_spans_preserve_unicode_positions_and_marked_exclusion() {
    let chars: Vec<_> = "abandon🦀abandon".chars().collect();
    let found = find(&chars, &vec![false; chars.len()]).unwrap();
    locked(&found);
    let ranges: Vec<_> = found.expose().iter().map(WordSpan::range).collect();
    assert_eq!(ranges, [0..7, 8..15]);
    assert!(
        find(&chars, &vec![true; chars.len()])
            .unwrap()
            .expose()
            .is_empty()
    );
    assert!(find(&[], &[]).unwrap().expose().is_empty());
}

#[test]
fn maximum_nonoverlapping_span_capacity_is_filled_and_locked() {
    let chars: Vec<_> = "able"
        .repeat(super::super::INPUT_LIMIT_CHARS / 4)
        .chars()
        .collect();
    let found = find(&chars, &vec![false; chars.len()]).unwrap();
    locked(&found);
    assert_eq!(found.expose().len(), chars.len() / MIN_WORD_CHARS);
    for (index, span) in found.expose().iter().enumerate() {
        assert_eq!(span.range(), index * 4..index * 4 + 4);
    }
    let mut span = WordSpan { start: 3, end: 8 };
    span.zeroize();
    assert_eq!(span.range(), 0..0);
}
