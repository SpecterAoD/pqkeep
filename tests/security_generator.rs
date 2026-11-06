//! DE: Generator: gültig, verschieden, Länge, Klassen, Gleichverteilung, Grenzen.
//! EN: Generator: valid, distinct, length, classes, uniformity, bounds.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{HashMap, HashSet};

use pqc_keyforge::Error;
use pqc_keyforge::security::generator::{self, AMBIGUOUS, MAX_LEN, MIN_LEN, Options};

const RUNS: usize = 1000;

fn text(options: &Options) -> String {
    let p = generator::generate(options).unwrap();
    p.as_ref().expose_str().to_owned()
}

#[test]
fn many_runs_valid_distinct_and_complete() {
    let options = Options::default();
    let mut seen = HashSet::with_capacity(RUNS);
    for _ in 0..RUNS {
        let p = generator::generate(&options).unwrap();
        let s = p.as_ref().expose_str().to_owned();
        assert_eq!(s.chars().count(), 24);
        assert!(s.chars().any(|c| c.is_ascii_lowercase()));
        assert!(s.chars().any(|c| c.is_ascii_uppercase()));
        assert!(s.chars().any(|c| c.is_ascii_digit()));
        assert!(s.chars().any(|c| c.is_ascii_punctuation()));
        assert!(s.chars().all(|c| c.is_ascii_graphic()));
        assert!(p.as_ref().assess().is_strong());
        assert!(p.entropy_bits() >= 80.0);
        assert!(seen.insert(s), "doppelt / duplicate");
    }
}

#[test]
fn ambiguous_characters_excluded_on_request() {
    let options = Options {
        exclude_ambiguous: true,
        ..Options::default()
    };
    for _ in 0..200 {
        let s = text(&options);
        assert!(!s.chars().any(|c| AMBIGUOUS.contains(c)), "{s}");
    }
}

#[test]
fn length_bounds() {
    for length in [MIN_LEN, 40, MAX_LEN] {
        let options = Options {
            length,
            ..Options::default()
        };
        assert_eq!(text(&options).chars().count(), length);
    }
    for length in [0, MIN_LEN - 1, MAX_LEN + 1] {
        let options = Options {
            length,
            ..Options::default()
        };
        let err = generator::generate(&options).err();
        assert_eq!(
            err,
            Some(Error::InvalidInput { field: "length" }),
            "{length}"
        );
    }
}

#[test]
fn characters_roughly_uniform() {
    // DE: 2000 × 24 = 48 000 Zeichen auf 94 Symbole, Erwartung ≈ 511 je Symbol.
    //     Sehr großzügige Grenzen (> 7 Standardabweichungen), damit der Test nie zufällig
    //     scheitert, grobe Verzerrungen aber auffallen.
    // EN: 2000 × 24 = 48,000 characters over 94 symbols, ≈ 511 expected each.
    //     Very generous bounds (> 7 standard deviations) so the test never fails by
    //     chance while gross bias is still detected.
    let options = Options::default();
    let mut counts: HashMap<char, usize> = HashMap::new();
    for _ in 0..2000 {
        for c in text(&options).chars() {
            *counts.entry(c).or_default() += 1;
        }
    }
    assert_eq!(counts.len(), 94);
    for (c, n) in counts {
        assert!((350..=680).contains(&n), "{c}: {n}");
    }
}
