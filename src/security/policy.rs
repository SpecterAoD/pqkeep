//! DE: Regeln für starke Passphrasen und zweisprachige Ablehnungsgründe.
//! EN: Rules for strong passphrases and bilingual rejection reasons.

use std::fmt;

use zeroize::Zeroizing;

use super::{Lang, entropy, patterns};

/// DE: Mindestlänge in Unicode-Zeichen (nach NFKC). EN: Minimum length in Unicode characters.
pub const MIN_CHARS: usize = 16;
/// DE: Höchstlänge in Unicode-Zeichen. EN: Maximum length in Unicode characters.
pub const MAX_CHARS: usize = 1024;
/// DE: Mindestwert der geschätzten Entropie. EN: Minimum estimated entropy.
pub const MIN_ENTROPY_BITS: f64 = 80.0;

/// DE: Grund für die Ablehnung einer Passphrase. EN: Reason for rejecting a passphrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    /// DE: Zu kurz. EN: Too short.
    TooShort {
        /// DE: Tatsächliche Zeichenzahl. EN: Actual number of characters.
        chars: usize,
    },
    /// DE: Zu lang. EN: Too long.
    TooLong {
        /// DE: Tatsächliche Zeichenzahl. EN: Actual number of characters.
        chars: usize,
    },
    /// DE: Kein Kleinbuchstabe. EN: No lowercase letter.
    MissingLowercase,
    /// DE: Kein Großbuchstabe. EN: No uppercase letter.
    MissingUppercase,
    /// DE: Keine Ziffer. EN: No digit.
    MissingDigit,
    /// DE: Kein Sonderzeichen. EN: No special character.
    MissingSpecial,
    /// DE: Steuerzeichen enthalten. EN: Contains control characters.
    ControlCharacter,
    /// DE: Wiederholung (z. B. „aaaa“). EN: Repetition (e.g. "aaaa").
    Repetition,
    /// DE: Folge (z. B. „1234“, „abcd“). EN: Sequence (e.g. "1234", "abcd").
    Sequence,
    /// DE: Tastaturmuster (z. B. „qwertz“). EN: Keyboard pattern (e.g. "qwerty").
    KeyboardPattern,
    /// DE: Enthält ein häufiges Passwort/Muster. EN: Contains a common password/pattern.
    Blocklisted,
    /// DE: Besteht überwiegend aus Wörtern (zu wenige für die nötige Stärke).
    /// EN: Consists mostly of words (too few for the required strength).
    DictionaryWords,
    /// DE: Geschätzte Entropie zu gering. EN: Estimated entropy too low.
    LowEntropy {
        /// DE: Geschätzte Bits (abgerundet). EN: Estimated bits (rounded down).
        bits: u32,
    },
}

impl Reason {
    /// DE: Meldung in der gewählten Sprache. EN: Message in the chosen language.
    #[must_use]
    pub fn message(&self, lang: Lang) -> String {
        let min = MIN_CHARS;
        let (de, en) = match *self {
            Self::TooShort { chars } => (
                format!("zu kurz: {chars} Zeichen, mindestens {min}"),
                format!("too short: {chars} characters, at least {min}"),
            ),
            Self::TooLong { chars } => (
                format!("zu lang: {chars} Zeichen, höchstens {MAX_CHARS}"),
                format!("too long: {chars} characters, at most {MAX_CHARS}"),
            ),
            Self::MissingLowercase => s("kein Kleinbuchstabe", "no lowercase letter"),
            Self::MissingUppercase => s("kein Großbuchstabe", "no uppercase letter"),
            Self::MissingDigit => s("keine Ziffer", "no digit"),
            Self::MissingSpecial => s(
                "kein Sonderzeichen (z. B. Leer- oder Satzzeichen)",
                "no special character (e.g. space or punctuation)",
            ),
            Self::ControlCharacter => s("enthält Steuerzeichen", "contains control characters"),
            Self::Repetition => s(
                "enthält Wiederholungen (z. B. „aaaa“)",
                "contains repetitions (e.g. \"aaaa\")",
            ),
            Self::Sequence => s(
                "enthält Folgen (z. B. „1234“, „abcd“)",
                "contains sequences (e.g. \"1234\", \"abcd\")",
            ),
            Self::KeyboardPattern => s(
                "enthält Tastaturmuster (z. B. „qwertz“)",
                "contains keyboard patterns (e.g. \"qwerty\")",
            ),
            Self::Blocklisted => s(
                "enthält ein häufig verwendetes Passwort oder Wort",
                "contains a commonly used password or word",
            ),
            Self::DictionaryWords => s(
                "besteht überwiegend aus Wörtern – mehr Wörter (etwa 6) oder zufällige Zeichen verwenden",
                "consists mostly of words – use more words (about 6) or random characters",
            ),
            Self::LowEntropy { bits } => (
                format!("geschätzte Stärke {bits} Bit, mindestens {MIN_ENTROPY_BITS} Bit"),
                format!("estimated strength {bits} bits, at least {MIN_ENTROPY_BITS} bits"),
            ),
        };
        match lang {
            Lang::De => de,
            Lang::En => en,
        }
    }
}

fn s(de: &str, en: &str) -> (String, String) {
    (de.to_owned(), en.to_owned())
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} / {}", self.message(Lang::De), self.message(Lang::En))
    }
}

/// DE: Ablehnung mit allen Gründen (enthält keine Geheimnisse).
/// EN: Rejection with all reasons (contains no secrets).
#[derive(Debug, Clone, PartialEq)]
pub struct Rejection {
    /// DE: Alle zutreffenden Gründe. EN: All applicable reasons.
    pub reasons: Vec<Reason>,
    /// DE: Geschätzte Entropie in Bit. EN: Estimated entropy in bits.
    pub entropy_bits: f64,
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Passphrase abgelehnt / passphrase rejected:")?;
        for reason in &self.reasons {
            write!(f, "\n- {reason}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Rejection {}

/// DE: Prädikat für eine Zeichenklasse. EN: Predicate for a character class.
pub(super) type CharPred = fn(char) -> bool;

/// DE: Prüft alle Regeln und liefert Gründe sowie geschätzte Entropie.
/// EN: Checks all rules and returns reasons and estimated entropy.
pub(super) fn assess(text: &str) -> (Vec<Reason>, f64) {
    // DE: Zeichenkopie der Passphrase – wird beim Verlassen genullt.
    // EN: Character copy of the passphrase – zeroed when leaving scope.
    let chars: Zeroizing<Vec<char>> = Zeroizing::new(text.chars().collect());
    let mut reasons = Vec::new();
    if chars.len() < MIN_CHARS {
        reasons.push(Reason::TooShort { chars: chars.len() });
    }
    if chars.len() > MAX_CHARS {
        reasons.push(Reason::TooLong { chars: chars.len() });
    }
    let has = |pred: CharPred| chars.iter().any(|&c| pred(c));
    let checks: [(CharPred, Reason); 4] = [
        (|c| c.is_lowercase(), Reason::MissingLowercase),
        (|c| c.is_uppercase(), Reason::MissingUppercase),
        (|c| c.is_numeric(), Reason::MissingDigit),
        (is_special, Reason::MissingSpecial),
    ];
    for (pred, reason) in checks {
        if !has(pred) {
            reasons.push(reason);
        }
    }
    if has(char::is_control) {
        reasons.push(Reason::ControlCharacter);
    }
    let found = patterns::find(&chars);
    reasons.extend(found.reasons.iter().copied());
    let low: Zeroizing<Vec<char>> =
        Zeroizing::new(chars.iter().map(|&c| patterns::lower(c)).collect());
    let estimate = entropy::estimate(&chars, &low, &found.marked);
    let bits = estimate.bits;
    if bits < MIN_ENTROPY_BITS && estimate.word_model {
        reasons.push(Reason::DictionaryWords);
    }
    if bits < MIN_ENTROPY_BITS {
        // DE: Abrunden für die Anzeige; Werte sind klein und nicht negativ.
        // EN: Round down for display; values are small and non-negative.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        reasons.push(Reason::LowEntropy {
            bits: bits.floor() as u32,
        });
    }
    (reasons, bits)
}

/// DE: Sonderzeichen = weder Buchstabe/Ziffer noch Steuerzeichen (inkl. Leerzeichen).
/// EN: Special = neither letter/digit nor control character (incl. space).
pub(super) fn is_special(c: char) -> bool {
    !c.is_alphanumeric() && !c.is_control()
}
