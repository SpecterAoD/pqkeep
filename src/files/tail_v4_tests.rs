#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::crypto::stream::EncryptWriter;
use crate::crypto::stream::PREFIX_LEN;
use crate::files::Signer;
use crate::files::format_v4::TRAILER_MAGIC;
use crate::files::format_v4::{padding_for, trailer};

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

fn tail(padded: bool) -> TailRead {
    TailRead {
        padded,
        hidden: None,
    }
}

fn payload_of(plain: &[u8], padded: bool) -> (Result<(u64, u64)>, Vec<u8>) {
    let bytes = sealed(plain);
    let mut out = Vec::new();
    let r = copy_payload(reader(&bytes), &mut out, &tail(padded));
    (r, out)
}

/// DE: Nutzdaten ‖ Füllung (Nullbytes) ‖ Trailer. EN: payload ‖ padding (zero bytes) ‖ trailer.
fn framed(data: &[u8], padded: bool) -> Vec<u8> {
    let pad = padding_for(data.len() as u64, padded, TRAILER_LEN).unwrap();
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
    let pad = padding_for(1001, true, TRAILER_LEN).unwrap();
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
            let pad = padding_for(500, padded, TRAILER_LEN).unwrap();
            let zeros = vec![0u8; usize::try_from(pad).unwrap()];
            [&archive[..], &zeros, &trailer(500, pad)].concat()
        };
        let sealed_plain = sealed(&plain);
        let mut dec = reader(&sealed_plain);
        let mut head = vec![0u8; 500];
        dec.read_exact(&mut head).unwrap();
        assert!(
            finish_tail(dec, 500, &tail(padded)).is_ok(),
            "padded={padded}"
        );
    }
    // DE: Füllung mit Nicht-Null-Byte oder falscher Archivlänge. EN: non-zero padding or wrong length.
    let pad = padding_for(500, true, TRAILER_LEN).unwrap();
    let mut zeros = vec![0u8; usize::try_from(pad).unwrap()];
    zeros[0] = 1;
    let bad = sealed(&[&archive[..], &zeros, &trailer(500, pad)].concat());
    let mut dec = reader(&bad);
    let mut head = vec![0u8; 500];
    dec.read_exact(&mut head).unwrap();
    assert!(finish_tail(dec, 500, &tail(true)).is_err());
    let short = sealed(&[&archive[..], &trailer(499, 0)].concat());
    let mut dec = reader(&short);
    dec.read_exact(&mut head).unwrap();
    assert!(finish_tail(dec, 500, &tail(false)).is_err());
}

/// DE: Klartext mit verborgenem Absender; `signed` = (Nutzlänge, Füllung) in der Signatur.
/// EN: Plaintext with hidden sender; `signed` = (payload, padding) inside the signature.
fn hidden_plain(kp: &dsa::DsaKeyPair, data: &[u8], header: &[u8], signed: (u64, u64)) -> Vec<u8> {
    use sha3::{Digest, Sha3_512};
    let pad = padding_for(data.len() as u64, true, trailer_len(true)).unwrap();
    let zeros = vec![0u8; usize::try_from(pad).unwrap()];
    let hash = Sha3_512::digest([data, &zeros].concat());
    let msg = hidden_message(header, &hash, signed.0, signed.1).unwrap();
    let sig = dsa::sign(
        SIGNER_DSA,
        kp.seed().expose(),
        msg.expose(),
        FILE_SIG_CONTEXT,
    )
    .unwrap();
    let block = [&[SIGNER_ML_DSA_87][..], &kp.public_key, &sig].concat();
    [data, &zeros, &block, &trailer(data.len() as u64, pad)].concat()
}

/// DE: Wie `hidden_plain`, aber mit frei gewählter Füllung. EN: Like `hidden_plain` with chosen padding.
fn hidden_plain_with_pad(kp: &dsa::DsaKeyPair, data: &[u8], pad: u64) -> Vec<u8> {
    use sha3::{Digest, Sha3_512};
    let zeros = vec![0u8; usize::try_from(pad).unwrap()];
    let hash = Sha3_512::digest([data, &zeros].concat());
    let msg = hidden_message(b"H", &hash, data.len() as u64, pad).unwrap();
    let sig = dsa::sign(
        SIGNER_DSA,
        kp.seed().expose(),
        msg.expose(),
        FILE_SIG_CONTEXT,
    )
    .unwrap();
    let block = [&[SIGNER_ML_DSA_87][..], &kp.public_key, &sig].concat();
    [data, &zeros, &block, &trailer(data.len() as u64, pad)].concat()
}

fn hidden_check(plain: &[u8], header: &[u8]) -> (Result<(u64, u64)>, Option<SignedBy>) {
    let bytes = sealed(plain);
    let mut dec = reader(&bytes);
    dec.start_hash().unwrap();
    let result = HiddenResult::new().unwrap();
    let t = TailRead {
        padded: true,
        hidden: Some((header.to_vec(), result.clone())),
    };
    let r = copy_payload(dec, &mut Vec::new(), &t);
    let signed = result.take();
    (r, signed)
}

#[test]
fn hidden_sender_block_is_verified_and_tampering_rejected() {
    let kp = dsa::generate(SIGNER_DSA).unwrap();
    let data = vec![3u8; 1500];
    let pad = padding_for(1500, true, trailer_len(true)).unwrap();
    // DE: PADMÉ über Nutzdaten und ganzen Trailer (Codex-Fund #342): 1500 + 472 + 7244 = 9216.
    // EN: PADMÉ over payload and the whole trailer (Codex finding #342).
    assert_eq!(1500 + pad + trailer_len(true) as u64, 9216);
    let good = hidden_plain(&kp, &data, b"H", (1500, pad));
    let (r, signed) = hidden_check(&good, b"H");
    assert_eq!(r.unwrap().0, 1500);
    let id = Signer {
        public_key: kp.public_key.clone(),
        commit: [0; 32],
    }
    .key_id();
    assert_eq!(signed.unwrap().key_id(), id);
    // DE: Anderer Header, verschobene Grenze in der Signatur, gekippte Signatur, geänderte Daten.
    // EN: Other header, shifted boundary in the signature, flipped signature, altered data.
    assert_eq!(hidden_check(&good, b"X").0, Err(Error::InvalidSignature));
    let shifted = hidden_plain(&kp, &data, b"H", (1499, pad + 1));
    assert_eq!(hidden_check(&shifted, b"H").0, Err(Error::InvalidSignature));
    let mut flipped = good.clone();
    let at = good.len() - TRAILER_LEN - 10;
    flipped[at] ^= 1;
    assert_eq!(hidden_check(&flipped, b"H").0, Err(Error::InvalidSignature));
    let mut altered = good.clone();
    altered[7] ^= 1;
    assert_eq!(hidden_check(&altered, b"H").0, Err(Error::InvalidSignature));
    let mut kind = good.clone();
    kind[1500 + usize::try_from(pad).unwrap()] = 0x7f;
    assert_eq!(hidden_check(&kind, b"H").0, Err(Error::Unsupported));
    // DE: Füllung nur für den kurzen Trailer berechnet. EN: Padding computed for the short trailer.
    let short_pad = padding_for(1500, true, TRAILER_LEN).unwrap();
    let wrong = hidden_plain_with_pad(&kp, &data, short_pad);
    assert!(hidden_check(&wrong, b"H").0.is_err());
    // DE: Ohne Absenderblock (nur Trailer) zu kurz. EN: Without the sender block too short.
    let (r, signed) = hidden_check(&framed(&data, true), b"H");
    assert!(r.is_err() && signed.is_none());
}
