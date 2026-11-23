//! DE: Byte-Gegenproben zur gepinnten Normalisierung und lebende Workspace-Sperren.
//! EN: Byte differential checks against pinned normalization and live workspace locks.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock;
use unicode_normalization::UnicodeNormalization;

fn compare(input: &str) {
    // DE: Ausschließlich generierte öffentliche Testdaten, keine echten Passphrasen.
    // EN: Generated public test data only, never real passphrases.
    let expected: String = input.nfkc().collect();
    let (actual, count) = nfkc(input).unwrap();
    assert_eq!(actual.expose(), expected.as_bytes());
    assert_eq!(count, expected.chars().count());
    assert!(actual.is_locked());
}

#[test]
fn every_unicode_scalar_matches_the_pinned_provider_in_bounded_batches() {
    let mut input = String::new();
    let mut covered = 0;
    for value in 0..=0x0010_ffff {
        if let Some(ch) = char::from_u32(value) {
            input.push(ch);
            input.push('\0');
            covered += 1;
            if covered % 256 == 0 {
                compare(&input);
                input.clear();
            }
        }
    }
    compare(&input);
    assert_eq!(covered, 1_112_064);
}

#[test]
fn combining_blocking_hangul_and_compatibility_sequences_match() {
    let fixtures = [
        "a\u{0315}\u{0300}\u{05ae}\u{0301}",
        "\u{0301}\u{0315}\u{0300}a\u{0308}",
        "a\u{0301}\u{0300}\u{0327}\u{0308}",
        "\u{1100}\u{1161}\u{11a8}\u{ac01}\u{fb03}\u{fdfa}",
        "\u{212b}\u{1e9b}\u{0323}\u{0344}\u{ff76}\u{ff9e}",
    ];
    for fixture in fixtures {
        compare(fixture);
    }
    let mut long = String::from("a");
    for _ in 0..2048 {
        long.push('\u{0315}');
        long.push('\u{0300}');
    }
    compare(&long);
}

#[test]
fn deterministic_mixed_sequences_match_without_changing_equal_class_order() {
    let alphabet = [
        'a', 'e', '\u{0300}', '\u{0301}', '\u{0327}', '\u{0315}', '\u{0345}', '\u{1100}',
        '\u{1161}', '\u{11a8}', '\u{fdfa}', '\u{fb03}',
    ];
    let mut state = 1u64;
    for _ in 0..1024 {
        let mut text = String::new();
        for _ in 0..64 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let index = usize::try_from(state % u64::try_from(alphabet.len()).unwrap()).unwrap();
            text.push(alphabet[index]);
        }
        compare(&text);
    }
}

#[test]
fn actual_decomposition_and_sort_workspaces_are_locked_and_stable() {
    let mut chars = decompose("a\u{0315}\u{0300}\u{0327}").unwrap();
    let mut scratch = SecretBuffer::new(vec!['\0'; chars.expose().len()]).unwrap();
    let mut counts = SecretBuffer::new(vec![0usize; 256]).unwrap();
    let addresses = [
        chars.expose().as_ptr().addr(),
        scratch.expose().as_ptr().addr(),
        counts.expose().as_ptr().addr(),
    ];
    for address in addresses {
        assert!(memlock::is_locked(address));
    }
    let ends = [
        addresses[0] + size_of_val(chars.expose()) - 1,
        addresses[1] + size_of_val(scratch.expose()) - 1,
        addresses[2] + size_of_val(counts.expose()) - 1,
    ];
    for end in ends {
        assert!(memlock::is_locked(end));
    }
    order_run(
        chars.expose_mut(),
        scratch.expose_mut(),
        counts.expose_mut(),
    );
    assert_eq!(chars.expose().as_ptr().addr(), addresses[0]);
    for address in addresses {
        assert!(memlock::is_locked(address));
    }
    assert_eq!(chars.expose(), &['a', '\u{0327}', '\u{0300}', '\u{0315}']);
}

#[test]
fn input_bound_is_preserved_and_empty_core_normalization_is_defined() {
    compare("");
    let boundary = "a".repeat(super::super::INPUT_LIMIT_CHARS * 4);
    compare(&boundary);
    assert!(matches!(
        nfkc(&(boundary + "a")),
        Err(Error::InvalidInput {
            field: "passphrase"
        })
    ));
}

fn decode_field(field: &str) -> String {
    field
        .split_whitespace()
        .map(|value| char::from_u32(u32::from_str_radix(value, 16).unwrap()).unwrap())
        .collect()
}

#[test]
fn official_unicode18_nfkc_conformance_covers_all_five_columns() {
    assert_eq!(unicode_normalization::UNICODE_VERSION, (18, 0, 0));
    let corpus = include_str!("../../tests/fixtures/unicode18/NormalizationTest.txt");
    assert!(corpus.starts_with("# NormalizationTest-18.0.0.txt"));
    let mut rows = 0;
    for line in corpus.lines() {
        let data = line.split('#').next().unwrap().trim();
        if data.is_empty() || data.starts_with('@') {
            continue;
        }
        let columns: Vec<_> = data.split(';').take(5).collect();
        assert_eq!(columns.len(), 5);
        let expected = decode_field(columns[3]);
        for column in columns {
            let input = decode_field(column);
            assert_eq!(input.nfkc().collect::<String>(), expected);
            let (actual, count) = nfkc(&input).unwrap();
            assert_eq!(actual.expose(), expected.as_bytes(), "corpus row {rows}");
            assert_eq!(count, expected.chars().count());
        }
        rows += 1;
    }
    assert!(rows > 20_000);
}
