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

use zeroize::Zeroizing;

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

/// DE: Findet Wörter in `low` (Kleinbuchstaben); markierte Zeichen (Muster) werden
/// übersprungen. Ergebnis: nicht überlappende Zeichenbereiche.
/// EN: Finds words in `low` (lowercase); marked characters (patterns) are skipped.
/// Result: non-overlapping character ranges.
pub(super) fn find(low: &[char], marked: &[bool]) -> Vec<Range<usize>> {
    // DE: Zusammenhängender Text mit Byte-Grenzen je Zeichen; wird beim Verlassen genullt.
    // EN: Contiguous text with byte offsets per character; zeroed when leaving scope.
    let capacity = low.iter().map(|c| c.len_utf8()).sum();
    let mut text = Zeroizing::new(String::with_capacity(capacity));
    let mut offsets = Vec::with_capacity(low.len() + 1);
    for &c in low {
        offsets.push(text.len());
        text.push(c);
    }
    offsets.push(text.len());

    let mut found = Vec::new();
    let mut i = 0;
    while i < low.len() {
        let longest = (MIN_WORD_CHARS..=MAX_WORD_CHARS.min(low.len() - i))
            .rev()
            .find(|&n| {
                !marked[i..i + n].iter().any(|m| *m) && contains(&text[offsets[i]..offsets[i + n]])
            });
        match longest {
            Some(n) => {
                found.push(i..i + n);
                i += n;
            }
            None => i += 1,
        }
    }
    found
}
