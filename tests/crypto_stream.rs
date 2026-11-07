//! DE: Streaming-AEAD: Roundtrip an Blockgrenzen und Manipulation einzelner
//! Blöcke (kippen, vertauschen, entfernen, abschneiden, anhängen).
//! EN: Streaming AEAD: round trip at chunk boundaries and tampering with single
//! chunks (flip, swap, remove, truncate, append).

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use pqkeep::Error;
use pqkeep::crypto::aead::TAG_LEN;
use pqkeep::crypto::stream::{self, CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE, PREFIX_LEN};
use pqkeep::crypto::{aead, rng};

const AAD: &[u8] = b"header-hash";

struct Setup {
    key: Vec<u8>,
    prefix: [u8; PREFIX_LEN],
}

fn setup() -> Setup {
    Setup {
        key: aead::generate_key().unwrap().expose().to_vec(),
        prefix: rng::array::<PREFIX_LEN>().unwrap(),
    }
}

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

fn enc(s: &Setup, plain: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let n = stream::encrypt(&s.key, s.prefix, AAD, &mut &plain[..], &mut out).unwrap();
    assert_eq!(n, plain.len() as u64);
    out
}

fn dec(s: &Setup, ct: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    stream::decrypt(&s.key, s.prefix, AAD, &mut &ct[..], &mut out)?;
    Ok(out)
}

#[test]
fn roundtrip_at_chunk_boundaries() {
    let s = setup();
    for len in [
        0,
        1,
        CHUNK_SIZE - 1,
        CHUNK_SIZE,
        CHUNK_SIZE + 1,
        2 * CHUNK_SIZE,
        3 * CHUNK_SIZE + 5,
    ] {
        let plain = data(len);
        let ct = enc(&s, &plain);
        let chunks = len.div_ceil(CHUNK_SIZE).max(1);
        assert_eq!(ct.len(), len + chunks * TAG_LEN, "len {len}");
        assert_eq!(dec(&s, &ct).unwrap(), plain, "len {len}");
    }
}

#[test]
fn large_input_streams() {
    let s = setup();
    let plain = data(5 * 1024 * 1024 + 123);
    assert_eq!(dec(&s, &enc(&s, &plain)).unwrap(), plain);
}

#[test]
fn flipped_byte_in_any_chunk() {
    let s = setup();
    let ct = enc(&s, &data(2 * CHUNK_SIZE + 10));
    for pos in [
        0,
        ENCRYPTED_CHUNK_SIZE - 1,
        ENCRYPTED_CHUNK_SIZE + 7,
        ct.len() - 1,
    ] {
        let mut bad = ct.clone();
        bad[pos] ^= 1;
        assert_eq!(dec(&s, &bad).err(), Some(Error::Decrypt), "pos {pos}");
    }
}

#[test]
fn swapped_and_removed_chunks() {
    let s = setup();
    let ct = enc(&s, &data(3 * CHUNK_SIZE + 10));
    let c =
        |i: usize| &ct[i * ENCRYPTED_CHUNK_SIZE..((i + 1) * ENCRYPTED_CHUNK_SIZE).min(ct.len())];
    let swapped = [c(1), c(0), c(2), c(3)].concat();
    let removed_middle = [c(0), c(2), c(3)].concat();
    let removed_last = [c(0), c(1), c(2)].concat();
    let duplicated = [c(0), c(0), c(1), c(2), c(3)].concat();
    for (name, bad) in [
        ("swap", swapped),
        ("remove middle", removed_middle),
        ("remove last", removed_last),
        ("duplicate", duplicated),
    ] {
        assert_eq!(dec(&s, &bad).err(), Some(Error::Decrypt), "{name}");
    }
}

#[test]
fn truncated_and_appended() {
    let s = setup();
    let ct = enc(&s, &data(CHUNK_SIZE + 100));
    for len in [
        0,
        1,
        TAG_LEN - 1,
        TAG_LEN,
        ENCRYPTED_CHUNK_SIZE,
        ct.len() - 1,
    ] {
        assert_eq!(dec(&s, &ct[..len]).err(), Some(Error::Decrypt), "len {len}");
    }
    let mut appended = ct.clone();
    appended.push(0);
    assert_eq!(dec(&s, &appended).err(), Some(Error::Decrypt));
    // DE: Vollständiger zweiter Strom angehängt. EN: Complete second stream appended.
    let twice = [ct.clone(), ct].concat();
    assert_eq!(dec(&s, &twice).err(), Some(Error::Decrypt));
}

#[test]
fn exact_multiple_cannot_be_cut_at_boundary() {
    // DE: Bei genau 2 Blöcken ist der erste nicht als „letzter“ markiert.
    // EN: With exactly 2 chunks the first one is not marked "last".
    let s = setup();
    let ct = enc(&s, &data(2 * CHUNK_SIZE));
    assert_eq!(
        dec(&s, &ct[..ENCRYPTED_CHUNK_SIZE]).err(),
        Some(Error::Decrypt)
    );
}

#[test]
fn wrong_key_prefix_or_aad() {
    let s = setup();
    let ct = enc(&s, &data(1000));
    let other_key = Setup {
        key: aead::generate_key().unwrap().expose().to_vec(),
        prefix: s.prefix,
    };
    assert_eq!(dec(&other_key, &ct).err(), Some(Error::Decrypt));
    let mut prefix = s.prefix;
    prefix[0] ^= 1;
    let other_prefix = Setup {
        key: s.key.clone(),
        prefix,
    };
    assert_eq!(dec(&other_prefix, &ct).err(), Some(Error::Decrypt));
    let mut out = Vec::new();
    let err = stream::decrypt(&s.key, s.prefix, b"other", &mut &ct[..], &mut out).err();
    assert_eq!(err, Some(Error::Decrypt));
}

#[test]
fn same_input_gives_different_ciphertext_with_new_key() {
    let plain = data(500);
    assert_ne!(enc(&setup(), &plain), enc(&setup(), &plain));
}

#[test]
fn invalid_key_length() {
    let mut out = Vec::new();
    let err = stream::encrypt(&[0u8; 16], [0; PREFIX_LEN], AAD, &mut &b"x"[..], &mut out).err();
    assert_eq!(err, Some(Error::InvalidInput { field: "key" }));
}
