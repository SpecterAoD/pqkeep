//! DE: Header des Dateiformats v2 im Rust-Core, bytegenau gegen die Python-Referenz
//! (`scripts/v2_reference.py`): dieselben Fälle V01–V06 wie `scripts/test_v2_spec.py`, dazu
//! gemeinsame Sollwerte (SHA3-256), die beide Seiten unabhängig prüfen (`test_V02_shared_digests`).
//! EN: Header of file format v2 in the Rust core, byte-exact against the Python reference
//! (`scripts/v2_reference.py`): the same cases V01–V06 as `scripts/test_v2_spec.py`, plus shared
//! expected values (SHA3-256) checked independently by both sides (`test_V02_shared_digests`).

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Cursor;

use common::v2_header::{KEMS, header, mixed, nonce, pslot, rslot, salt};
use pqkeep::Error;
use pqkeep::crypto::kdf::KdfParams;
use pqkeep::crypto::v2::Domain;
use pqkeep::files::Content;
use pqkeep::files::format_v2::{self, HEADER_LIMIT, HeaderV2, MAX_ENCODED_LEN, Slot, check_slots};
use sha3::{Digest, Sha3_256};

const BAD: Error = Error::InvalidInput { field: "header" };

fn sha3(data: &[u8]) -> String {
    hex::encode(Sha3_256::digest(data))
}

fn parse(bytes: &[u8]) -> Result<HeaderV2, Error> {
    HeaderV2::read(&mut Cursor::new(bytes))
}

#[test]
fn v01_slot_bytes() {
    let expected = format!(
        "010100000100030000000100000020{}{}",
        hex::encode(salt()),
        hex::encode(nonce())
    );
    assert_eq!(hex::encode(pslot(true).encode().unwrap()), expected);
    assert_eq!(pslot(false).encode().unwrap()[1], 0);
    for (kem, (_, size)) in KEMS.iter().enumerate() {
        let bytes = rslot(1, kem).encode().unwrap();
        assert_eq!(bytes.len(), 1 + 1 + 32 + size + 12);
        assert_eq!(bytes[..3], [2, u8::try_from(kem).unwrap() + 1, 1]);
    }
}

/// DE: Passphrase-Zugang mit eigenen Parametern und Salt. EN: Passphrase slot with given values.
fn passphrase_with(memory_kib: u32, iterations: u32, parallelism: u32, salt: Vec<u8>) -> Slot {
    let params = KdfParams {
        memory_kib,
        iterations,
        parallelism,
    };
    Slot::Passphrase {
        factor: true,
        params,
        salt,
        nonce: nonce(),
    }
}

#[test]
fn v01_invalid_slot_values() {
    for len in [0, 1567, 1569, 1088] {
        let mut slot = rslot(1, 2);
        if let Slot::Recipient { kem_ciphertext, .. } = &mut slot {
            *kem_ciphertext = vec![0; len];
        }
        assert_eq!(slot.encode().err(), Some(BAD), "{len}");
    }
    for len in [0, 15, 65] {
        let slot = passphrase_with(65536, 3, 1, vec![0; len]);
        assert_eq!(slot.encode().err(), Some(BAD), "{len}");
    }
    for (m, t, p) in [
        (65535, 3, 1),
        (1_048_577, 3, 1),
        (65536, 2, 1),
        (65536, 11, 1),
        (65536, 3, 0),
        (65536, 3, 17),
    ] {
        let slot = passphrase_with(m, t, p, salt());
        assert_eq!(slot.encode().err(), Some(Error::KdfParams), "{m} {t} {p}");
    }
    assert!(
        passphrase_with(1_048_576, 10, 16, vec![0; 64])
            .encode()
            .is_ok()
    );
}

#[test]
fn v01_invalid_factor_and_kem_codes() {
    // DE: Faktorbyte und KEM-Code lassen sich nur im Parser falsch angeben.
    // EN: Factor byte and KEM code can only be wrong in the parser.
    let base = header(Content::File, [0; 7], vec![pslot(true)])
        .encode()
        .unwrap();
    let mut changed = base.clone();
    changed[24] = 2;
    assert_eq!(parse(&changed).err(), Some(BAD));
    let base = header(Content::File, [0; 7], vec![rslot(1, 2)])
        .encode()
        .unwrap();
    for code in [0, 4, 255] {
        let mut changed = base.clone();
        changed[24] = code;
        assert_eq!(parse(&changed).err(), Some(Error::Unsupported), "{code}");
    }
}

#[test]
fn v02_metadata_bytes() {
    let one = header(Content::File, [0, 1, 2, 3, 4, 5, 6], vec![pslot(true)]);
    let head = "50514b46454e430002000100000100000102030405060 1".replace(' ', "");
    let slot = hex::encode(pslot(true).encode().unwrap());
    assert_eq!(hex::encode(one.metadata().unwrap()), head + &slot);
}

#[test]
fn v02_shared_digests_and_roundtrip() {
    let header = mixed();
    let (meta, full) = (header.metadata().unwrap(), header.encode().unwrap());
    assert_eq!((meta.len(), full.len()), (3644, 3836));
    assert_eq!(
        sha3(&meta),
        "5925f33cd2bae61bce5cc87f7b4631ec23ae35c729f9a9374165fed6e98b5425"
    );
    assert_eq!(
        hex::encode(header.stream_aad().unwrap()),
        "2ec08e1891cf6491066fee1bbd158476605bc7b3be07c7b87dae898214b6f471"
    );
    assert_eq!(
        sha3(&header.wrap_aad(3).unwrap()),
        "2d0755aefd77e20c590465cc412f0d28259b5e23672003f4ddb0410d1f1d306a"
    );
    assert_eq!(parse(&full).unwrap(), header);
    // DE: Der Parser liest genau den Header, nicht mehr. EN: The parser reads exactly the header.
    let mut cursor = Cursor::new([full.clone(), vec![0xff; 100]].concat());
    assert_eq!(HeaderV2::read(&mut cursor).unwrap(), header);
    assert_eq!(usize::try_from(cursor.position()).unwrap(), full.len());
}

#[test]
fn v03_slot_rules() {
    let ok = [
        vec![pslot(true)],
        vec![rslot(1, 2)],
        vec![pslot(false), rslot(1, 2), rslot(2, 2)],
    ];
    for slots in ok {
        check_slots(&slots).unwrap();
        let header = header(Content::File, [0; 7], slots);
        assert_eq!(parse(&header.encode().unwrap()).unwrap(), header);
    }
    let bad = [
        ("empty", vec![]),
        ("two passphrases", vec![pslot(true), pslot(true)]),
        ("passphrase not first", vec![rslot(1, 2), pslot(true)]),
        ("unsorted", vec![rslot(2, 2), rslot(1, 2)]),
        ("duplicate", vec![rslot(1, 2), rslot(1, 2)]),
    ];
    for (name, slots) in bad {
        assert_eq!(check_slots(&slots).err(), Some(BAD), "{name}");
        let header = header(Content::File, [0; 7], slots.clone());
        assert_eq!(header.metadata().err(), Some(BAD), "{name}");
        assert_eq!(header.encode().err(), Some(BAD), "{name}");
        assert_eq!(header.stream_aad().err(), Some(BAD), "{name}");
        // DE: Dieselbe Liste als Bytes: auch der Parser lehnt ab. EN: Same list as bytes.
        let mut bytes = b"PQKFENC\0\x02\x00\x01\x00\x00\x01\x00".to_vec();
        bytes.extend_from_slice(&[0; 7]);
        bytes.push(u8::try_from(slots.len()).unwrap());
        for slot in &slots {
            bytes.extend_from_slice(&slot.encode().unwrap());
        }
        bytes.extend_from_slice(&vec![0; 48 * slots.len()]);
        assert_eq!(parse(&bytes).err(), Some(BAD), "{name}");
    }
}

#[test]
fn v03_reserved_and_unknown_slot_types() {
    let base = header(Content::File, [0; 7], vec![pslot(true)])
        .encode()
        .unwrap();
    for kind in [0, 3, 4, 5, 9, 255] {
        let mut changed = base.clone();
        changed[23] = kind;
        assert_eq!(parse(&changed).err(), Some(Error::Unsupported), "{kind}");
        // DE: Auch ohne weitere Bytes: abgelehnt, bevor etwas abgeleitet werden könnte.
        // EN: Also without further bytes: rejected before anything could be derived.
        assert_eq!(
            parse(&changed[..24]).err(),
            Some(Error::Unsupported),
            "{kind}"
        );
    }
}

#[test]
fn v04_recipient_and_header_limits() {
    let many: Vec<Slot> = (1..=64).map(|i| rslot(i, 0)).collect();
    check_slots(&many).unwrap();
    check_slots(&[vec![pslot(true)], many.clone()].concat()).unwrap();
    let too_many = [many.clone(), vec![rslot(200, 0)]].concat();
    assert_eq!(check_slots(&too_many).err(), Some(BAD));
    assert_eq!(
        header(Content::File, [0; 7], too_many).encode().err(),
        Some(BAD)
    );
    let two_pass = [vec![pslot(true), pslot(true)], many].concat();
    assert_eq!(check_slots(&two_pass).err(), Some(BAD));

    // DE: Größter zulässiger Header: 64-Byte-Salt, 64 × ML-KEM-1024. EN: Largest valid header.
    let longest = passphrase_with(65536, 3, 1, vec![7; 64]);
    let big: Vec<Slot> = (1..=64).map(|i| rslot(i, 2)).collect();
    let mut largest = header(Content::Directory, [0; 7], [vec![longest], big].concat());
    let full = largest.encode().unwrap();
    assert_eq!(full.len(), MAX_ENCODED_LEN);
    assert_eq!((MAX_ENCODED_LEN, HEADER_LIMIT), (106_530, 262_144));
    assert_eq!(parse(&full).unwrap(), largest);

    // DE: Falsche Hüllenzahl. EN: Wrong number of wraps.
    largest.wraps.pop();
    assert_eq!(largest.encode().err(), Some(BAD));
    assert_eq!(largest.stream_aad().err(), Some(BAD));
    largest.wraps.extend([[0; 48], [0; 48]]);
    assert_eq!(largest.encode().err(), Some(BAD));
}

#[test]
fn v05_wrap_aad_binds_header_and_index() {
    let header = header(Content::File, [0; 7], vec![pslot(true), rslot(1, 2)]);
    let meta = header.metadata().unwrap();
    let base = header.wrap_aad(0).unwrap();
    let expected = [
        b"PQKeep/file/v2\0aad/wrap\0".to_vec(),
        1696u32.to_le_bytes().to_vec(),
        meta.clone(),
        vec![0],
    ];
    assert_eq!(base, expected.concat());
    assert_eq!(base, format_v2::wrap_aad(Domain::File, &meta, 0).unwrap());
    assert_ne!(base, header.wrap_aad(1).unwrap());
    assert_ne!(base, format_v2::wrap_aad(Domain::Key, &meta, 0).unwrap());
    for i in 0..meta.len() {
        let mut changed = meta.clone();
        changed[i] ^= 1;
        assert_ne!(
            format_v2::wrap_aad(Domain::File, &changed, 0).unwrap(),
            base,
            "{i}"
        );
    }
    // DE: Index ohne Zugang bzw. über 64; zu großes M. EN: Index without slot / above 64; M too big.
    assert_eq!(header.wrap_aad(2).err(), Some(BAD));
    assert!(format_v2::wrap_aad(Domain::File, &meta, 64).is_ok());
    assert_eq!(
        format_v2::wrap_aad(Domain::File, &meta, 65).err(),
        Some(BAD)
    );
    assert!(format_v2::wrap_aad(Domain::File, &vec![0; HEADER_LIMIT], 0).is_ok());
    assert_eq!(
        format_v2::wrap_aad(Domain::File, &vec![0; HEADER_LIMIT + 1], 0).err(),
        Some(BAD)
    );
}

#[test]
fn v06_stream_aad_binds_every_wrap() {
    let mut header = header(Content::File, [0; 7], vec![pslot(true), rslot(1, 2)]);
    let base = header.stream_aad().unwrap();
    for wrap in 0..2 {
        for i in 0..48 {
            header.wraps[wrap][i] ^= 1;
            assert_ne!(header.stream_aad().unwrap(), base, "{wrap} {i}");
            header.wraps[wrap][i] ^= 1;
        }
    }
    header.wraps.swap(0, 1);
    assert_ne!(header.stream_aad().unwrap(), base);
}
