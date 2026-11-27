#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::crypto::stream::EncryptWriter;
use crate::files::format_v4::TRAILER_MAGIC;

/// DE: Korrekt verschlüsselter Strom mit frei gewähltem Klartext (wie ein Empfänger ihn bauen kann).
/// EN: Correctly encrypted stream with chosen plaintext (as a recipient could build it).
fn sealed(plain: &[u8]) -> Vec<u8> {
    let mut enc = EncryptWriter::new(&[7u8; 32], [1u8; PREFIX_LEN], b"aad", Vec::new()).unwrap();
    enc.push(plain).unwrap();
    enc.finish().unwrap().0
}

fn reader(sealed: &[u8]) -> DecryptReader<&[u8]> {
    DecryptReader::new(&[7u8; 32], [1u8; PREFIX_LEN], b"aad", sealed).unwrap()
}

fn payload_of(plain: &[u8], padded: bool) -> (Result<(u64, u64)>, Vec<u8>) {
    let bytes = sealed(plain);
    let mut out = Vec::new();
    let r = copy_payload(reader(&bytes), &mut out, padded);
    (r, out)
}

/// DE: Nutzdaten ‖ Füllung (Nullbytes) ‖ Trailer. EN: payload ‖ padding (zero bytes) ‖ trailer.
fn framed(data: &[u8], padded: bool) -> Vec<u8> {
    let pad = padding_for(data.len() as u64, padded).unwrap();
    let zeros = vec![0u8; usize::try_from(pad).unwrap()];
    [data, &zeros, &trailer(data.len() as u64, pad)].concat()
}

#[test]
fn valid_trailer_releases_payload_and_padding_is_counted() {
    for padded in [false, true] {
        for len in [
            0usize,
            1,
            CHUNK_SIZE - TRAILER_LEN,
            CHUNK_SIZE,
            2 * CHUNK_SIZE + 3,
        ] {
            let data: Vec<u8> = (0..len).map(|i| u8::try_from(i % 7).unwrap()).collect();
            let (r, out) = payload_of(&framed(&data, padded), padded);
            let (payload, written) = r.unwrap();
            assert_eq!(payload, len as u64);
            assert_eq!(&out[..len], &data[..]);
            assert_eq!(usize::try_from(written).unwrap(), out.len());
            assert!(out[len..].iter().all(|b| *b == 0));
        }
    }
}

#[test]
fn tampered_trailers_and_padding_are_rejected() {
    let data = vec![5u8; 1001];
    let good = trailer(1001, 0);
    let mut wrong_len = good;
    wrong_len[0] ^= 1;
    let mut magic = good;
    magic[TRAILER_LEN - 2] ^= 1;
    let pad = padding_for(1001, true).unwrap();
    let mut dirty = framed(&data, true);
    dirty[1001 + 3] = 1;
    let off_by_one = [&data[..], &[0u8; 25], &trailer(1001, 25)].concat();
    let cases: Vec<(Vec<u8>, bool)> = vec![
        ([&data[..], &wrong_len].concat(), false),
        ([&data[..], &magic].concat(), false),
        ([&data[..], &good, b"x"].concat(), false),
        (data[..10].to_vec(), false),
        (TRAILER_MAGIC.to_vec(), false),
        (Vec::new(), false),
        (framed(&data, false), true),
        (framed(&data, true), false),
        (dirty, true),
        (off_by_one, true),
        ([&data[..], &[0u8; 24], &trailer(1001, pad)].concat(), true),
    ];
    for (i, (plain, padded)) in cases.iter().enumerate() {
        let (r, _) = payload_of(plain, *padded);
        assert!(
            matches!(r, Err(Error::InvalidInput { field }) if field == "trailer" || field == "padding"),
            "Fall / case {i}: {r:?}"
        );
    }
}

#[test]
fn archive_tail_accepts_only_zero_padding_after_the_archive() {
    let archive = vec![9u8; 500];
    for padded in [false, true] {
        let plain = {
            let pad = padding_for(500, padded).unwrap();
            let zeros = vec![0u8; usize::try_from(pad).unwrap()];
            [&archive[..], &zeros, &trailer(500, pad)].concat()
        };
        let sealed_plain = sealed(&plain);
        let mut dec = reader(&sealed_plain);
        let mut head = vec![0u8; 500];
        dec.read_exact(&mut head).unwrap();
        assert!(finish_tail(dec, 500, padded).is_ok(), "padded={padded}");
    }
    // DE: Füllung mit Nicht-Null-Byte oder falscher Archivlänge. EN: non-zero padding or wrong length.
    let pad = padding_for(500, true).unwrap();
    let mut zeros = vec![0u8; usize::try_from(pad).unwrap()];
    zeros[0] = 1;
    let bad = sealed(&[&archive[..], &zeros, &trailer(500, pad)].concat());
    let mut dec = reader(&bad);
    let mut head = vec![0u8; 500];
    dec.read_exact(&mut head).unwrap();
    assert!(finish_tail(dec, 500, true).is_err());
    let short = sealed(&[&archive[..], &trailer(499, 0)].concat());
    let mut dec = reader(&short);
    dec.read_exact(&mut head).unwrap();
    assert!(finish_tail(dec, 500, false).is_err());
}
