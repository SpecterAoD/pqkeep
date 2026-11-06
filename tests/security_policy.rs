//! DE: Pflichtregeln: jede Ablehnung mit Grund, mehrere Gründe, starke Passphrasen,
//! zweisprachige Meldungen. Schwache Beispielwerte nur als Negativ-Testdaten.
//! EN: Mandatory rules: each rejection with reason, several reasons, strong
//! passphrases, bilingual messages. Weak example values only as negative test data.

mod common;

use pqc_keyforge::Error;
use pqc_keyforge::security::{Lang, MAX_CHARS, Passphrase, Reason, StrongPassphrase};

/// DE: Musterfreie Beispielwerte mit allen Klassen. EN: Pattern-free examples with all classes.
const STRONG: [&str; 3] = [
    "Bm7#qLx2!Vp9$Kd4",
    "Grüne Wiese, 7 Kühe & 3 Pferde!",
    "zH8%rN2^eQ6*uJ4(wT",
];

fn reasons(text: &str) -> Vec<Reason> {
    common::passphrase(text).assess().reasons
}

#[test]
fn strong_examples_accepted() {
    for text in STRONG {
        let a = common::passphrase(text).assess();
        assert!(a.is_strong(), "{text}: {:?}", a.reasons);
        assert!(StrongPassphrase::try_from(common::passphrase(text)).is_ok());
    }
}

#[test]
fn too_short_reports_length() {
    assert!(reasons("Ab1!").contains(&Reason::TooShort { chars: 4 }));
    assert!(
        !reasons(STRONG[0])
            .iter()
            .any(|r| matches!(r, Reason::TooShort { .. }))
    );
}

#[test]
fn too_long_rejected_with_reason() {
    let text: String = STRONG[0].chars().cycle().take(MAX_CHARS + 1).collect();
    assert!(reasons(&text).contains(&Reason::TooLong {
        chars: MAX_CHARS + 1
    }));
    let ok: String = STRONG[0].chars().cycle().take(MAX_CHARS).collect();
    assert!(
        !reasons(&ok)
            .iter()
            .any(|r| matches!(r, Reason::TooLong { .. }))
    );
}

#[test]
fn each_missing_class_reported() {
    let base = STRONG[0];
    let cases = [
        (base.to_uppercase(), Reason::MissingLowercase),
        (base.to_lowercase(), Reason::MissingUppercase),
        (
            base.replace(|c: char| c.is_ascii_digit(), "w"),
            Reason::MissingDigit,
        ),
        (
            base.replace(|c: char| !c.is_alphanumeric(), "k"),
            Reason::MissingSpecial,
        ),
    ];
    for (text, reason) in cases {
        let found = reasons(&text);
        assert!(found.contains(&reason), "{text}: {found:?}");
    }
}

#[test]
fn control_characters_rejected() {
    for ctrl in ['\u{7}', '\n', '\t', '\u{1b}'] {
        let text = format!("{}{ctrl}", STRONG[0]);
        assert!(
            reasons(&text).contains(&Reason::ControlCharacter),
            "{ctrl:?}"
        );
    }
}

#[test]
fn all_reasons_reported_at_once() {
    let found = reasons("aaaa");
    for expected in [
        Reason::TooShort { chars: 4 },
        Reason::MissingUppercase,
        Reason::MissingDigit,
        Reason::MissingSpecial,
        Reason::Repetition,
    ] {
        assert!(found.contains(&expected), "{expected:?} in {found:?}");
    }
    assert!(found.iter().any(|r| matches!(r, Reason::LowEntropy { .. })));
}

#[test]
fn rejection_converts_and_displays() {
    let rejection = StrongPassphrase::try_from(common::passphrase("aaaa"))
        .err()
        .unwrap();
    let text = rejection.to_string();
    assert!(text.contains("abgelehnt") && text.contains("rejected"));
    assert_eq!(text.lines().count(), rejection.reasons.len() + 1);
    assert_eq!(Error::from(rejection), Error::WeakPassphrase);
}

#[test]
fn messages_bilingual_and_distinct() {
    let all = [
        Reason::TooShort { chars: 3 },
        Reason::TooLong { chars: 2000 },
        Reason::MissingLowercase,
        Reason::MissingUppercase,
        Reason::MissingDigit,
        Reason::MissingSpecial,
        Reason::ControlCharacter,
        Reason::Repetition,
        Reason::Sequence,
        Reason::KeyboardPattern,
        Reason::Blocklisted,
        Reason::LowEntropy { bits: 42 },
    ];
    for r in all {
        let (de, en) = (r.message(Lang::De), r.message(Lang::En));
        assert!(!de.is_empty() && !en.is_empty());
        assert_ne!(de, en, "{r:?}");
        assert_eq!(r.to_string(), format!("{de} / {en}"));
    }
}

#[test]
fn empty_and_oversized_input_rejected() {
    let field = Error::InvalidInput {
        field: "passphrase",
    };
    assert_eq!(Passphrase::new("").err(), Some(field.clone()));
    let huge = "x".repeat(pqc_keyforge::security::INPUT_LIMIT_CHARS + 1);
    assert_eq!(Passphrase::new(&huge).err(), Some(field));
}
