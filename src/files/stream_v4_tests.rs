#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::crypto::stream::EncryptWriter;
use crate::files::format_v4::TRAILER_MAGIC;

/// DE: Korrekt verschlüsselter Strom mit frei gewähltem Klartext (wie ein Empfänger ihn bauen kann).
/// EN: Correctly encrypted stream with chosen plaintext (as a recipient could build it).
fn payload_of(plain: &[u8]) -> (Result<u64>, Vec<u8>) {
    let key = [7u8; 32];
    let prefix = [1u8; PREFIX_LEN];
    let mut enc = EncryptWriter::new(&key, prefix, b"aad", Vec::new()).unwrap();
    enc.push(plain).unwrap();
    let sealed = enc.finish().unwrap().0;
    let dec = DecryptReader::new(&key, prefix, b"aad", &sealed[..]).unwrap();
    let mut out = Vec::new();
    let r = copy_payload(dec, &mut out);
    (r, out)
}

#[test]
fn valid_trailer_releases_exact_payload() {
    for len in [
        0usize,
        1,
        CHUNK_SIZE - TRAILER_LEN,
        CHUNK_SIZE,
        2 * CHUNK_SIZE + 3,
    ] {
        let data: Vec<u8> = (0..len).map(|i| u8::try_from(i % 7).unwrap()).collect();
        let (r, out) = payload_of(&[&data[..], &trailer(len as u64)].concat());
        assert_eq!(r.unwrap(), len as u64);
        assert_eq!(out, data);
    }
}

#[test]
fn tampered_trailers_are_rejected() {
    let data = vec![5u8; 1000];
    let good = trailer(1000);
    let mut wrong_len = good;
    wrong_len[0] ^= 1;
    let mut padding = good;
    padding[8] = 1;
    let mut magic = good;
    magic[TRAILER_LEN - 2] ^= 1;
    let cases: Vec<Vec<u8>> = vec![
        [&data[..], &wrong_len].concat(),
        [&data[..], &padding].concat(),
        [&data[..], &magic].concat(),
        [&data[..], &good, b"x"].concat(),
        data[..10].to_vec(),
        TRAILER_MAGIC.to_vec(),
        Vec::new(),
    ];
    for (i, plain) in cases.iter().enumerate() {
        let (r, _) = payload_of(plain);
        assert_eq!(
            r,
            Err(Error::InvalidInput { field: "trailer" }),
            "Fall / case {i}"
        );
    }
}
