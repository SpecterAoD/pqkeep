//! DE: Wörterbuch aus eingebundenen Wortlisten (EFF, BIP-39, deutsche Diceware-Listen;
//! Quellen und Lizenzen: `data/wordlists/README.md`, `NOTICE`). Sucht in der
//! (kleingeschriebenen) Passphrase von links nach rechts jeweils das längste Wort mit
//! mindestens 4 Zeichen. Gefundene Wörter zählen bei der Entropie nur wie ein Wort
//! aus einer Liste (siehe `entropy`).
//!
//! EN: Dictionary from bundled word lists (EFF, BIP-39, German diceware lists;
//! sources and licences: `data/wordlists/README.md`, `NOTICE`). Searches the
//! (lowercased) passphrase from left to right for the longest word of at least 4
//! characters. Found words only count like one word from a list (see `entropy`).

use std::collections::HashSet;
use std::ops::Range;
use std::sync::OnceLock;

use crate::crypto::SecretBytes;
use crate::crypto::secret_workspace::SecretWorkspace;
use crate::{Error, Result};
use zeroize::Zeroize;

// DE: Konkreter Buffer-Drop löscht beide Offsets und seine volle frühere Allokation.
// EN: The concrete buffer destructor wipes both offsets and its full former allocation.
impl zeroize::ZeroizeOnDrop for crate::crypto::secret_buffer::SecretBuffer<WordSpan> {}

#[cfg(test)]
#[path = "dictionary_tests.rs"]
mod tests;

/// DE: Interner vertraulicher Zeichenbereich. EN: Internal confidential character span.
pub(super) struct WordSpan {
    pub start: usize,
    pub end: usize,
}

impl WordSpan {
    pub(super) fn range(&self) -> Range<usize> {
        self.start..self.end
    }
}

impl Zeroize for WordSpan {
    fn zeroize(&mut self) {
        self.start.zeroize();
        self.end.zeroize();
    }
}

/// DE: Kürzeste berücksichtigte Wortlänge (Zeichen). EN: Shortest word length considered.
pub(super) const MIN_WORD_CHARS: usize = 4;
/// DE: Längste Wortlänge in den Listen. EN: Longest word length in the lists.
const MAX_WORD_CHARS: usize = 19;

const LISTS: [&str; 18] = [
    include_str!("../../data/wordlists/eff_large.txt"),
    include_str!("../../data/wordlists/eff_short_1.txt"),
    include_str!("../../data/wordlists/eff_short_2.txt"),
    include_str!("../../data/wordlists/bip39_english.txt"),
    include_str!("../../data/wordlists/bip39_french.txt"),
    include_str!("../../data/wordlists/bip39_italian.txt"),
    include_str!("../../data/wordlists/bip39_spanish.txt"),
    include_str!("../../data/wordlists/bip39_portuguese.txt"),
    include_str!("../../data/wordlists/bip39_czech.txt"),
    include_str!("../../data/wordlists/bip39_japanese.txt"),
    include_str!("../../data/wordlists/bip39_korean.txt"),
    include_str!("../../data/wordlists/bip39_chinese_simplified.txt"),
    include_str!("../../data/wordlists/bip39_chinese_traditional.txt"),
    include_str!("../../data/wordlists/dys2p_de_7776.txt"),
    include_str!("../../data/wordlists/dys2p_de_2048.txt"),
    include_str!("../../data/wordlists/dys2p_de_1626.txt"),
    include_str!("../../data/wordlists/dys2p_de_1296.txt"),
    include_str!("../../data/wordlists/bjoernalbers_german.txt"),
];

fn words() -> &'static HashSet<&'static str> {
    static WORDS: OnceLock<HashSet<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        LISTS
            .iter()
            .flat_map(|list| list.lines())
            .map(str::trim)
            .filter(|w| w.chars().count() >= MIN_WORD_CHARS)
            .collect()
    })
}

/// DE: Ist das (kleingeschriebene) Wort in einer Liste? EN: Is the (lowercase) word in a list?
#[must_use]
pub fn contains(word: &str) -> bool {
    words().contains(word)
}

/// DE: Anzahl Wörter (≥ 4 Zeichen) im Wörterbuch. EN: Number of words (≥ 4 chars) in the dictionary.
#[must_use]
pub fn len() -> usize {
    words().len()
}

fn encode(low: &[char]) -> Result<(SecretBytes, SecretWorkspace<usize>)> {
    // DE: Auch positionsgenaue Metadaten vor erster Befüllung sperren.
    // EN: Lock per-character metadata too, before its first write.
    let capacity = low.iter().map(|c| c.len_utf8()).sum();
    let mut text = SecretBytes::zeroed(capacity)?;
    let mut offsets = SecretWorkspace::zeroed(low.len() + 1)?;
    let mut written = 0;
    for (index, &c) in low.iter().enumerate() {
        offsets.expose_mut()[index] = written;
        let n = c.len_utf8();
        c.encode_utf8(&mut text.expose_mut()[written..written + n]);
        written += n;
    }
    offsets.expose_mut()[low.len()] = written;
    Ok((text, offsets))
}

/// DE: Längste nicht überlappende Wörter; markierte Zeichen überspringen.
/// EN: Longest non-overlapping words, skipping marked characters.
pub(super) fn find(low: &[char], marked: &[bool]) -> Result<SecretWorkspace<WordSpan>> {
    let (text, offsets) = encode(low)?;
    let offsets = offsets.expose();
    let text = std::str::from_utf8(text.expose()).map_err(|_| Error::Crypto)?;
    // DE: Nicht überlappende Wörter verbrauchen jeweils mindestens vier Zeichen.
    // EN: Every non-overlapping word consumes at least four characters.
    let mut found = SecretWorkspace::with_capacity(low.len() / MIN_WORD_CHARS)?;
    let mut i = 0;
    while i < low.len() {
        let longest = (MIN_WORD_CHARS..=MAX_WORD_CHARS.min(low.len() - i))
            .rev()
            .find(|&n| {
                !marked[i..i + n].iter().any(|m| *m) && contains(&text[offsets[i]..offsets[i + n]])
            });
        match longest {
            Some(n) => {
                found.push_preallocated(WordSpan {
                    start: i,
                    end: i + n,
                })?;
                i += n;
            }
            None => i += 1,
        }
    }
    Ok(found)
}
