//! DE: Unicode: NFKC-Normalisierung, Zählen von Zeichen statt Bytes.
//! EN: Unicode: NFKC normalisation, counting characters instead of bytes.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use pqkeep::security::Reason;

fn bytes(text: &str) -> Vec<u8> {
    common::passphrase(text).expose().to_vec()
}

#[test]
fn nfkc_compatibility_forms() {
    assert_eq!(bytes("ﬁ"), b"fi");
    assert_eq!(bytes("Ａｂｃ１"), b"Abc1");
    assert_eq!(bytes("x²"), b"x2");
}

#[test]
fn composed_and_decomposed_are_equal() {
    // DE: „é“ als ein Zeichen bzw. „e“ + Kombinationsakzent.
    // EN: "é" as one character vs. "e" + combining accent.
    assert_eq!(bytes("Caf\u{e9}"), bytes("Cafe\u{301}"));
    assert_eq!(bytes("\u{c4}pfel"), bytes("A\u{308}pfel"));
}

#[test]
fn characters_not_bytes_are_counted() {
    let p = common::passphrase("äöüß");
    assert_eq!(p.char_count(), 4);
    assert_eq!(p.expose().len(), 8);
    assert_eq!(common::passphrase("👍").char_count(), 1);
    // DE: Emoji-Familie aus 5 Unicode-Zeichen (3 Personen + 2 Verbinder).
    // EN: Emoji family of 5 Unicode characters (3 people + 2 joiners).
    assert_eq!(common::passphrase("👨\u{200d}👩\u{200d}👧").char_count(), 5);
}

#[test]
fn sixteen_unicode_characters_are_enough() {
    let text = "Ä7#qL!xÖ2pV$kÜ9d";
    let p = common::passphrase(text);
    assert_eq!(p.char_count(), 16);
    assert!(p.expose().len() > 16);
    let a = p.assess();
    assert!(
        !a.reasons
            .iter()
            .any(|r| matches!(r, Reason::TooShort { .. }))
    );
    assert!(a.is_strong(), "{:?}", a.reasons);
}

#[test]
fn umlauts_count_as_letters_not_special() {
    let a = common::passphrase("Grünkohl7Äpfelmus").assess();
    assert!(
        a.reasons.contains(&Reason::MissingSpecial),
        "{:?}",
        a.reasons
    );
    assert!(!a.reasons.contains(&Reason::MissingLowercase));
}

#[test]
fn space_counts_as_special() {
    let a = common::passphrase("Grünkohl 7 Äpfelmus").assess();
    assert!(
        !a.reasons.contains(&Reason::MissingSpecial),
        "{:?}",
        a.reasons
    );
}

#[test]
fn fullwidth_sequence_detected_after_normalisation() {
    let a = common::passphrase("Bm7#qLx2!Vp9$Kd4１２３４").assess();
    assert!(a.reasons.contains(&Reason::Sequence), "{:?}", a.reasons);
}

#[test]
fn from_string_normalises_like_new() {
    let p = pqkeep::security::Passphrase::from_string("Ａｂｃ１".to_owned()).unwrap();
    assert_eq!(p.expose(), b"Abc1");
}
