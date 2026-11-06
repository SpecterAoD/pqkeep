//! DE: Interner Test des Rejection Samplings: für jede Alphabetgröße 1..=256 wird
//! jeder der 256 Bytewerte geprüft. Jeder Index muss gleich oft getroffen werden
//! (kein Modulo-Bias), verworfene Bytes liegen genau oberhalb der Grenze.
//!
//! EN: Internal test of rejection sampling: for every alphabet size 1..=256 each
//! of the 256 byte values is checked. Every index must be hit equally often (no
//! modulo bias); rejected bytes lie exactly above the limit.

use super::uniform_index;

#[test]
fn rejection_sampling_is_exactly_uniform() {
    for n in 1..=256usize {
        let mut counts = vec![0usize; n];
        let mut rejected = 0usize;
        for byte in 0..=u8::MAX {
            match uniform_index(byte, n) {
                Some(i) => counts[i] += 1,
                None => rejected += 1,
            }
        }
        let expected = 256 / n;
        assert!(counts.iter().all(|&c| c == expected), "n = {n}");
        assert_eq!(rejected, 256 % n, "n = {n}");
    }
}

#[test]
fn invalid_alphabet_sizes_rejected() {
    assert_eq!(uniform_index(0, 0), None);
    assert_eq!(uniform_index(0, 257), None);
}
