//! DE: Entropieschätzung: Formel log2(Vorrat) × Länge, Klassen, Mindestwert.
//! EN: Entropy estimate: formula log2(pool) × length, classes, minimum.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use pqkeep::security::generator::Options;
use pqkeep::security::{GENERIC_WORD_BITS, LIST_WORD_BITS, MIN_ENTROPY_BITS, Reason, formula_bits};

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

fn per(pool: f64) -> f64 {
    pool.log2()
}

#[test]
fn random_characters_follow_the_formula() {
    // DE: Keine Buchstabenfolge > 2, keine Ziffern, alle Sonderzeichen verschieden:
    //     reine Formel log2(85) × 16 (Klein 26 + Groß 26 + Sonder 33).
    // EN: No letter run > 2, no digits, all specials distinct: pure formula.
    assert!(close(bits("Bm#qL!Vp$Kd&Wn%x"), per(85.0) * 16.0));
}

#[test]
fn digits_count_log2_10() {
    let expected = per(95.0) * 15.0 + 10f64.log2();
    assert!(close(bits("Bm#qL!Vp$Kd&Wn%7"), expected));
}

#[test]
fn repeated_separator_counts_one_bit() {
    // DE: 10 Buchstaben (Folgen à 2) + erstes „-“ voll + 3 Wiederholungen à 1 Bit.
    // EN: 10 letters (runs of 2) + first "-" in full + 3 repeats at 1 bit each.
    let expected = per(85.0) * 11.0 + 3.0;
    assert!(close(bits("Ab-Cd-Ef-Gh-Ij"), expected));
}

#[test]
fn unknown_letter_run_counts_like_words() {
    // DE: 16 Buchstaben ohne Listenwort → höchstens 2 unbekannte Wörter à 18 Bit.
    // EN: 16 letters without a listed word → at most 2 unknown words at 18 bits.
    assert!(close(bits("kxvmqpwhgjdbnfsy"), 2.0 * GENERIC_WORD_BITS));
}

#[test]
fn listed_words_count_as_list_entries() {
    assert!(close(bits("battery"), LIST_WORD_BITS));
    assert!(close(bits("Battery"), LIST_WORD_BITS + 1.0));
    assert!(close(bits("correcthorse"), 2.0 * LIST_WORD_BITS));
    assert!(pqkeep::security::dictionary::contains("abarbeiten"));
    assert!(pqkeep::security::dictionary::len() > 30_000);
}

#[test]
fn non_ascii_extends_pool() {
    // DE: Kleinbuchstaben (26) + Nicht-ASCII (100), Folge aus 2 Zeichen.
    // EN: lowercase (26) + non-ASCII (100), run of 2 characters.
    assert!(close(bits("kä"), per(126.0) * 2.0));
}

#[test]
fn compound_words_are_weak() {
    for weak in [
        "FIPS-140-validiert",
        "Sommer2026!Urlaub",
        "Hund-Katze-Maus-2024!",
    ] {
        let a = common::passphrase(weak).assess();
        assert!(
            a.entropy_bits < MIN_ENTROPY_BITS,
            "{weak}: {}",
            a.entropy_bits
        );
        assert!(
            a.reasons.contains(&Reason::DictionaryWords),
            "{weak}: {:?}",
            a.reasons
        );
    }
}

#[test]
fn long_sentences_and_random_strings_are_strong() {
    for strong in [
        "Kaffee Tasse Wolke Garten Fenster Brot Lampe Regen Stuhl Insel 7!",
        "Grüne Wiese, 7 Kühe & 3 Pferde am Bach unter der alten Linde!",
        "zH8%rN2^eQ6*uJ4(wTb5)mX7@",
    ] {
        let a = common::passphrase(strong).assess();
        assert!(
            a.is_strong(),
            "{strong}: {:?} {}",
            a.reasons,
            a.entropy_bits
        );
    }
}

#[test]
fn low_entropy_reported_with_bits() {
    // DE: „Bm“ + „7“ + „#“, die Wiederholung zählt nicht. EN: "Bm" + "7" + "#", repetition not counted.
    let text = "Bm7#aaaaaaaaaaaa";
    let expected = per(95.0) * 3.0 + 10f64.log2();
    assert!(close(bits(text), expected));
    let reasons = common::passphrase(text).assess().reasons;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let floor = expected.floor() as u32;
    assert!(
        reasons.contains(&Reason::LowEntropy {
            bits: floor,
            min: 128
        }),
        "{reasons:?}"
    );
}

#[test]
fn minimum_is_80_bits() {
    assert!(close(MIN_ENTROPY_BITS, 128.0));
}

#[test]
fn generator_entropy_values() {
    let default = Options::default();
    assert!(close(default.entropy_bits(), 94f64.log2() * 32.0));
    assert!(default.entropy_bits() >= 128.0);
    let no_ambiguous = Options {
        exclude_ambiguous: true,
        ..Options::default()
    };
    assert_eq!(no_ambiguous.alphabet().len(), 85);
    assert!(no_ambiguous.entropy_bits() >= 128.0);
}
