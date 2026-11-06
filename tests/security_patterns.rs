//! DE: Muster: Wiederholungen, Folgen, Tastaturreihen, Blocklist (inkl. Leetspeak).
//! EN: Patterns: repetitions, sequences, keyboard rows, blocklist (incl. leetspeak).

mod common;

use pqc_keyforge::security::Reason;

/// DE: Starke, musterfreie Basis. EN: Strong, pattern-free base.
const BASE: &str = "Bm7#qLx2!Vp9$Kd4";

fn reasons(text: &str) -> Vec<Reason> {
    common::passphrase(text).assess().reasons
}

fn assert_reason(insert: &str, reason: Reason) {
    let text = format!("{BASE}{insert}");
    let found = reasons(&text);
    assert!(found.contains(&reason), "{insert}: {found:?}");
}

#[test]
fn base_has_no_patterns() {
    assert!(reasons(BASE).is_empty(), "{:?}", reasons(BASE));
}

#[test]
fn repetitions() {
    for insert in ["aaaa", "1111", "!!!!", "AaAa", "ääää"] {
        assert_reason(insert, Reason::Repetition);
    }
    assert!(!reasons(&format!("{BASE}aaa")).contains(&Reason::Repetition));
}

#[test]
fn sequences() {
    for insert in ["1234", "abcd", "dcba", "9876", "WXYZ", "mnop"] {
        assert_reason(insert, Reason::Sequence);
    }
    for harmless in ["abce", "aceg", "1357"] {
        let found = reasons(&format!("{BASE}{harmless}"));
        assert!(!found.contains(&Reason::Sequence), "{harmless}: {found:?}");
    }
}

#[test]
fn keyboard_rows() {
    for insert in ["qwer", "wert", "trewq", "yxcv", "zxcv", "hjkl", "ölkj"] {
        assert_reason(insert, Reason::KeyboardPattern);
    }
}

#[test]
fn blocklisted_words_dominating() {
    for text in [
        "Passwort#2O26!x",
        "P@ssw0rt#Kq7Lm",
        "Sommer!Winter7X",
        "I1oveYou&Schatz9",
    ] {
        let found = reasons(text);
        assert!(found.contains(&Reason::Blocklisted), "{text}: {found:?}");
    }
}

#[test]
fn short_common_word_in_long_sentence_is_tolerated() {
    // DE: „Test“ macht weniger als ein Drittel aus: keine Ablehnung, nur Abzug.
    // EN: "Test" is less than a third: no rejection, only a deduction.
    let text = "Mein Test: 7 Kühe, 3 Pferde & Hund!";
    let a = common::passphrase(text).assess();
    assert!(!a.reasons.contains(&Reason::Blocklisted), "{:?}", a.reasons);
    assert!(a.is_strong(), "{:?}", a.reasons);
}

#[test]
fn patterns_do_not_add_entropy() {
    // DE: Musterzeichen zählen nicht – gleicher Vorrat, gleiche Bits.
    // EN: Pattern characters do not count – same pool, same bits.
    let base = common::passphrase(BASE).assess().entropy_bits;
    for insert in ["aaaa", "abcd", "qwer"] {
        let more = common::passphrase(&format!("{BASE}{insert}"))
            .assess()
            .entropy_bits;
        assert!((more - base).abs() < 1e-9, "{insert}: {more} vs {base}");
    }
}
