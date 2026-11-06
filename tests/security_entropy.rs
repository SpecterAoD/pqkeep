//! DE: Entropieschätzung: Formel log2(Vorrat) × Länge, Klassen, Mindestwert.
//! EN: Entropy estimate: formula log2(pool) × length, classes, minimum.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use pqc_keyforge::security::generator::Options;
use pqc_keyforge::security::{MIN_ENTROPY_BITS, Reason, formula_bits};

fn bits(text: &str) -> f64 {
    common::passphrase(text).assess().entropy_bits
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9
}

#[test]
fn formula_matches_specification() {
    assert!(close(formula_bits(94, 24), 94f64.log2() * 24.0));
    assert!(close(formula_bits(2, 128), 128.0));
    assert!(close(formula_bits(1, 50), 0.0));
    assert!(close(formula_bits(0, 50), 0.0));
}

#[test]
fn all_ascii_classes_give_pool_95() {
    // DE: 26 + 26 + 10 + 33 = 95. EN: 26 + 26 + 10 + 33 = 95.
    assert!(close(bits("Bm7#qLx2!Vp9$Kd4"), 95f64.log2() * 16.0));
}

#[test]
fn single_class_pool() {
    assert!(close(bits("kxvmqpwhgjdbnfsy"), 26f64.log2() * 16.0));
    assert!(close(bits("KXVMQPWHGJDBNFSY"), 26f64.log2() * 16.0));
}

#[test]
fn non_ascii_extends_pool() {
    // DE: Kleinbuchstaben (26) + Nicht-ASCII (100). EN: lowercase (26) + non-ASCII (100).
    assert!(close(bits("kxvmqpwhgjdbnfsä"), 126f64.log2() * 16.0));
}

#[test]
fn low_entropy_reported_with_bits() {
    // DE: Nur 4 Zeichen zählen (Rest ist Wiederholung). EN: Only 4 characters count.
    let text = "Bm7#aaaaaaaaaaaa";
    let expected = formula_bits(95, 4);
    assert!(close(bits(text), expected));
    let reasons = common::passphrase(text).assess().reasons;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let floor = expected.floor() as u32;
    assert!(
        reasons.contains(&Reason::LowEntropy { bits: floor }),
        "{reasons:?}"
    );
}

#[test]
fn minimum_is_80_bits() {
    assert!(close(MIN_ENTROPY_BITS, 80.0));
}

#[test]
fn generator_entropy_values() {
    let default = Options::default();
    assert!(close(default.entropy_bits(), 94f64.log2() * 24.0));
    assert!(default.entropy_bits() >= 128.0);
    let no_ambiguous = Options {
        exclude_ambiguous: true,
        ..Options::default()
    };
    assert_eq!(no_ambiguous.alphabet().len(), 85);
    assert!(no_ambiguous.entropy_bits() >= 128.0);
}
