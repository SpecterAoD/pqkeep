//! DE: Begrenzter Header-v2-Parser (C05 aus `docs/V2_TESTS.md`): Kürzen an jeder Position, jedes
//! einzelne veränderte Byte, Längen- und Zahlenfelder bis zum Höchstwert, Lesebudget. Der Parser
//! darf nie in Panik geraten, nie mehr als den größten zulässigen Header lesen und nimmt nur an,
//! was sich bytegleich wieder kodieren lässt.
//! EN: Bounded header v2 parser (C05 in `docs/V2_TESTS.md`): truncation at every position, every
//! single changed byte, length and number fields up to their maximum, read budget. The parser
//! must never panic, never read more than the largest valid header, and only accepts what
//! re-encodes to the same bytes.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::{Cursor, Read};

use common::v2_header::{header, mixed, pslot, rslot};
use pqkeep::Error;
use pqkeep::files::format_v2::{HeaderV2, MAX_ENCODED_LEN};
use pqkeep::files::{Content, FileHeader};

const BAD: Error = Error::InvalidInput { field: "header" };

fn parse(bytes: &[u8]) -> Result<HeaderV2, Error> {
    HeaderV2::read(&mut Cursor::new(bytes))
}

fn passphrase_only() -> Vec<u8> {
    header(Content::File, [9; 7], vec![pslot(true)])
        .encode()
        .unwrap()
}

#[test]
fn c05_truncation_at_every_position() {
    let small = header(Content::File, [9; 7], vec![pslot(false), rslot(1, 0)]);
    for full in [small.encode().unwrap(), mixed().encode().unwrap()] {
        for len in 0..full.len() {
            assert_eq!(parse(&full[..len]).err(), Some(BAD), "{len}");
        }
        assert!(parse(&full).is_ok());
    }
}

#[test]
fn c05_every_changed_byte_is_rejected_or_canonical() {
    let full = header(Content::File, [9; 7], vec![pslot(true), rslot(1, 0)])
        .encode()
        .unwrap();
    for i in 0..full.len() {
        for value in [full[i] ^ 1, full[i] ^ 0x80, 0, 255] {
            let mut changed = full.clone();
            changed[i] = value;
            if let Ok(header) = parse(&changed) {
                assert_eq!(header.encode().unwrap(), changed, "{i}");
            }
        }
    }
}

#[test]
fn c05_fixed_fields() {
    let full = passphrase_only();
    let set = |at: usize, bytes: &[u8]| {
        let mut changed = full.clone();
        changed[at..at + bytes.len()].copy_from_slice(bytes);
        parse(&changed).err()
    };
    assert_eq!(set(0, b"PQKFENC\x01"), Some(BAD));
    for version in [0u16, 1, 3, u16::MAX] {
        assert_eq!(
            set(8, &version.to_le_bytes()),
            Some(Error::Unsupported),
            "{version}"
        );
    }
    for content in [0, 3, 255] {
        assert_eq!(set(10, &[content]), Some(BAD), "{content}");
    }
    for chunk in [0u32, 65535, 65537, u32::MAX] {
        assert_eq!(set(11, &chunk.to_le_bytes()), Some(BAD), "{chunk}");
    }
    for count in [0, 66, 255] {
        assert_eq!(set(22, &[count]), Some(BAD), "{count}");
    }
    // DE: Zähler größer als vorhandene Zugänge: Die Hülle (Nullbytes) wird als Zugang mit
    //     unbekanntem Typ 0 gelesen. EN: Count beyond the slots: the wrap (zero bytes) is read as
    //     a slot of unknown type 0.
    assert_eq!(set(22, &[2]), Some(Error::Unsupported));
    assert_eq!(set(22, &[65]), Some(Error::Unsupported));
}

#[test]
fn c05_numbers_and_lengths_up_to_maximum() {
    let full = passphrase_only();
    let set = |at: usize, bytes: &[u8]| {
        let mut changed = full.clone();
        changed[at..at + bytes.len()].copy_from_slice(bytes);
        parse(&changed).err()
    };
    // DE: m, t, p ab Byte 25/29/33; Salt-Länge in Byte 37. EN: m, t, p at 25/29/33; salt length at 37.
    for (at, values) in [
        (25, [0u32, 65535, 1_048_577, u32::MAX]),
        (29, [0, 2, 11, u32::MAX]),
        (33, [0, 17, 1 << 31, u32::MAX]),
    ] {
        for value in values {
            assert_eq!(
                set(at, &value.to_le_bytes()),
                Some(Error::KdfParams),
                "{at} {value}"
            );
        }
    }
    for salt_len in [0, 15, 65, 255] {
        assert_eq!(set(37, &[salt_len]), Some(BAD), "{salt_len}");
    }
    // DE: Gültige, aber andere Salt-Länge verschiebt alles: zu kurz. EN: Other valid length: too short.
    assert_eq!(set(37, &[64]), Some(BAD));
}

/// DE: Endlose Quelle, die mitzählt. EN: Endless source that counts.
struct Endless {
    byte: u8,
    read: usize,
}

impl Read for Endless {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        buf.fill(self.byte);
        self.read += buf.len();
        Ok(buf.len())
    }
}

#[test]
fn c05_read_budget_on_endless_input() {
    // DE: Gültiger Anfang mit 65 Zugängen, danach endlos Bytes: Der Parser hört von selbst auf.
    // EN: Valid start with 65 slots, then endless bytes: the parser stops on its own.
    for byte in [0u8, 1, 2, 3, 255] {
        let mut start = passphrase_only()[..22].to_vec();
        start.push(65);
        let mut source = Cursor::new(start).chain(Endless { byte, read: 0 });
        assert!(HeaderV2::read(&mut source).is_err(), "{byte}");
        let (_, endless) = source.into_inner();
        assert!(endless.read <= MAX_ENCODED_LEN, "{byte}: {}", endless.read);
    }
}

#[test]
fn c05_versions_do_not_mix() {
    // DE: Der v1-Leser lehnt v2 als „nicht unterstützt“ ab – und umgekehrt (Versionsfeld).
    // EN: The v1 reader rejects v2 as "unsupported" – and vice versa (version field).
    let v2 = passphrase_only();
    assert_eq!(
        FileHeader::read(&mut Cursor::new(&v2)).err(),
        Some(Error::Unsupported)
    );
    let mut v1 = v2;
    v1[8] = 1;
    assert_eq!(parse(&v1).err(), Some(Error::Unsupported));
}
