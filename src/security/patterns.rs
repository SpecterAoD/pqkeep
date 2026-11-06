//! DE: Erkennung schwacher Muster: Wiederholungen, Folgen, Tastaturreihen und
//! Wörter aus der Blocklist (auch in Leetspeak). Erkannte Zeichen werden markiert
//! und zählen bei der Entropieschätzung nicht mit.
//!
//! EN: Detection of weak patterns: repetitions, sequences, keyboard rows and
//! blocklisted words (also in leetspeak). Matched characters are marked and do
//! not count towards the entropy estimate.

use zeroize::Zeroizing;

use super::Reason;
use super::blocklist::{BLOCKLIST, KEYBOARD_ROWS};

/// DE: Mindestlänge eines Musters. EN: Minimum length of a pattern.
pub(super) const MIN_RUN: usize = 4;

/// DE: Gefundene Muster. EN: Patterns found.
pub(super) struct Found {
    /// DE: Pro Zeichen: Teil eines Musters? EN: Per character: part of a pattern?
    pub marked: Vec<bool>,
    /// DE: Gründe in fester Reihenfolge. EN: Reasons in fixed order.
    pub reasons: Vec<Reason>,
}

/// DE: Kleinbuchstabe (erstes Zeichen von `to_lowercase`, damit Indizes passen).
/// EN: Lowercase (first char of `to_lowercase`, so that indices line up).
fn lower(c: char) -> char {
    c.to_lowercase().next().unwrap_or(c)
}

/// DE: Leetspeak zurückwandeln. EN: Undo leetspeak.
fn unleet(c: char) -> char {
    match c {
        '0' => 'o',
        '1' | '!' | '|' => 'i',
        '3' => 'e',
        '4' | '@' => 'a',
        '5' | '$' => 's',
        '7' => 't',
        '8' => 'b',
        '9' => 'g',
        other => other,
    }
}

/// DE: Sucht alle Muster. EN: Searches all patterns.
pub(super) fn find(chars: &[char]) -> Found {
    // DE: Abgeleitete Kopien der Passphrase – werden beim Verlassen genullt.
    // EN: Derived copies of the passphrase – zeroed when leaving scope.
    let low: Zeroizing<Vec<char>> = Zeroizing::new(chars.iter().map(|&c| lower(c)).collect());
    let leet: Zeroizing<Vec<char>> = Zeroizing::new(low.iter().map(|&c| unleet(c)).collect());
    let mut marked = vec![false; chars.len()];
    let repetition = mark_runs(&low, &mut marked, |a, b| a == b);
    let sequence = mark_runs(&low, &mut marked, |a, b| {
        a.is_alphanumeric() && b.is_alphanumeric() && (a as u32).abs_diff(b as u32) == 1
    });
    let keyboard = mark_substrings(&low, KEYBOARD_ROWS, true, &mut marked);
    // DE: Blocklist-Wörter mindern immer die Entropie; abgelehnt wird erst, wenn sie
    //     mindestens ein Drittel ausmachen (sonst träfe es normale Sätze wie „… Test …“).
    // EN: Blocklisted words always reduce entropy; rejection only if they make up at
    //     least a third (otherwise ordinary sentences such as "... test ..." would fail).
    let mut words = vec![false; chars.len()];
    mark_substrings(&low, BLOCKLIST, false, &mut words);
    mark_substrings(&leet, BLOCKLIST, false, &mut words);
    let covered = words.iter().filter(|w| **w).count();
    let blocklisted = covered > 0 && covered * 3 >= chars.len();
    marked.iter_mut().zip(&words).for_each(|(m, w)| *m |= *w);
    let reasons = [
        (repetition, Reason::Repetition),
        (sequence, Reason::Sequence),
        (keyboard, Reason::KeyboardPattern),
        (blocklisted, Reason::Blocklisted),
    ]
    .into_iter()
    .filter_map(|(hit, reason)| hit.then_some(reason))
    .collect();
    Found { marked, reasons }
}

/// DE: Markiert Läufe ≥ `MIN_RUN`, in denen benachbarte Zeichen `rel` erfüllen.
/// EN: Marks runs ≥ `MIN_RUN` where adjacent characters satisfy `rel`.
fn mark_runs(s: &[char], marked: &mut [bool], rel: impl Fn(char, char) -> bool) -> bool {
    let mut hit = false;
    let mut start = 0;
    for i in 1..=s.len() {
        let continues = i < s.len() && rel(s[i - 1], s[i]) && same_direction(s, start, i);
        if !continues {
            if i - start >= MIN_RUN {
                marked[start..i].iter_mut().for_each(|m| *m = true);
                hit = true;
            }
            start = i;
        }
    }
    hit
}

/// DE: Folgen müssen in eine Richtung laufen (abc, nicht aba).
/// EN: Sequences must run in one direction (abc, not aba).
fn same_direction(s: &[char], start: usize, i: usize) -> bool {
    if i < start + 2 {
        return true;
    }
    let step = |a: char, b: char| i64::from(b as u32) - i64::from(a as u32);
    step(s[i - 2], s[i - 1]) == step(s[i - 1], s[i])
}

/// DE: Markiert Vorkommen von Teilstücken (≥ `MIN_RUN`) der Muster; bei
/// `fragments` auch Teilstücke und Umkehrungen (Tastaturreihen).
/// EN: Marks occurrences of the patterns (≥ `MIN_RUN`); with `fragments` also
/// sub-slices and reversals (keyboard rows).
fn mark_substrings(s: &[char], list: &[&str], fragments: bool, marked: &mut [bool]) -> bool {
    let mut hit = false;
    for entry in list {
        let fwd: Vec<char> = entry.chars().collect();
        let rev: Vec<char> = fwd.iter().rev().copied().collect();
        let variants = if fragments { vec![fwd, rev] } else { vec![fwd] };
        for pattern in &variants {
            let min = if fragments { MIN_RUN } else { pattern.len() };
            for len in (min..=pattern.len()).rev() {
                for piece in pattern.windows(len) {
                    hit |= mark_piece(s, piece, marked);
                }
            }
        }
    }
    hit
}

fn mark_piece(s: &[char], piece: &[char], marked: &mut [bool]) -> bool {
    let mut hit = false;
    if piece.is_empty() || piece.len() > s.len() {
        return false;
    }
    for start in 0..=s.len() - piece.len() {
        if &s[start..start + piece.len()] == piece {
            marked[start..start + piece.len()]
                .iter_mut()
                .for_each(|m| *m = true);
            hit = true;
        }
    }
    hit
}
