//! DE: Manipulierte v2-Dateien (C04 aus `docs/V2_TESTS.md`): jedes Header- und Hüllenbyte,
//! Strombytes, Kürzen und Anhängen, entfernte oder vertauschte Zugänge und Hüllen. Immer Fehler,
//! nie eine Ausgabe, nie Panik – auch wenn der veränderte Zugang nicht der eigene ist.
//! EN: Tampered v2 files (C04 in `docs/V2_TESTS.md`): every header and wrap byte, stream bytes,
//! truncation and appending, removed or swapped slots and wraps. Always an error, never any
//! output, never a panic – even if the changed slot is not one's own.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::v2_files::{self as v2, KEMS, Workspace};
use pqkeep::Error;
use pqkeep::crypto::factor::Factor;
use pqkeep::envelope::UnlockedKey;
use pqkeep::files::{self, HeaderV2, PassphraseAccess, Protection, Unlock};
use pqkeep::security::StrongPassphrase;

/// DE: Datei mit Passphrase + Faktordatei und zwei Empfängern; `keys` in Dateireihenfolge (nach
/// ID sortiert), also Zugang 1 und 2. EN: Passphrase + factor and two recipients; `keys` in file
/// order (sorted by ID), i.e. slots 1 and 2.
struct Fixture {
    w: Workspace,
    file: Vec<u8>,
    header_len: usize,
    pass: StrongPassphrase,
    factor: Factor,
    keys: [UnlockedKey; 2],
}

fn fixture() -> Fixture {
    let w = v2::workspace();
    let pass = common::random_passphrase();
    let factor = v2::factor();
    let (first, first_key) = v2::kem_key(KEMS[0]);
    let (second, second_key) = v2::kem_key(KEMS[1]);
    let target = w.dir.path().join("ziel.pqkf");
    let protection = Protection::Slots {
        passphrase: Some(PassphraseAccess {
            passphrase: &pass,
            params: common::min_params(),
            factor: Some(&factor),
        }),
        recipients: &[&first, &second],
    };
    files::encrypt(&w.source, &target, &protection).unwrap();
    let file = std::fs::read(&target).unwrap();
    let keys = if first.key_id() < second.key_id() {
        [first_key, second_key]
    } else {
        [second_key, first_key]
    };
    Fixture {
        header_len: v2::header_len(&file),
        file,
        w,
        pass,
        factor,
        keys,
    }
}

impl Fixture {
    fn with_key(&self, index: usize, bytes: &[u8]) -> Result<(), Error> {
        v2::try_decrypt(&self.w.work, bytes, &Unlock::Key(&self.keys[index]))
    }

    fn with_passphrase(&self, bytes: &[u8]) -> Result<(), Error> {
        let unlock = Unlock::PassphraseWithFactor {
            passphrase: self.pass.as_ref(),
            factor: &self.factor,
        };
        v2::try_decrypt(&self.w.work, bytes, &unlock)
    }

    /// DE: Neuer Header vor dem unveränderten Strom. EN: New header before the unchanged stream.
    fn rebuilt(&self, change: impl FnOnce(&mut HeaderV2)) -> Vec<u8> {
        let mut header = HeaderV2::read(&mut &self.file[..]).unwrap();
        change(&mut header);
        let mut out = header.encode().unwrap();
        out.extend_from_slice(&self.file[self.header_len..]);
        out
    }
}

#[test]
fn unchanged_file_opens_for_every_slot() {
    let f = fixture();
    assert_eq!(f.with_key(0, &f.file), Ok(()));
    assert_eq!(f.with_key(1, &f.file), Ok(()));
    assert_eq!(f.with_passphrase(&f.file), Ok(()));
    assert_eq!(f.rebuilt(|_| {}), f.file);
}

#[test]
fn c04_every_header_and_wrap_byte_matters() {
    let f = fixture();
    // DE: 23 Byte fester Teil, Passphrase-Zugang 59, Empfänger 2+32+768+12 und 2+32+1088+12,
    //     drei Hüllen. EN: 23 fixed bytes, passphrase slot 59, two recipients, three wraps.
    assert_eq!(f.header_len, 23 + 59 + 814 + 1134 + 3 * 48);
    for pos in 0..f.header_len {
        let changed = common::flip(&f.file, pos);
        assert!(f.with_key(0, &changed).is_err(), "Byte {pos}");
    }
    // DE: Stichprobe mit dem zweiten Empfänger (jedes 11. Byte und alle Hüllen).
    // EN: Sample with the second recipient (every 11th byte and all wraps).
    let wraps = f.header_len - 3 * 48;
    for pos in (0..wraps).step_by(11).chain(wraps..f.header_len) {
        let changed = common::flip(&f.file, pos);
        assert!(f.with_key(1, &changed).is_err(), "Byte {pos}");
    }
}

#[test]
fn c04_passphrase_slot_bytes_matter() {
    let f = fixture();
    // DE: Stichprobe (Argon2id je Versuch): Zugang ab Byte 23, eigene Hülle, fremde Hülle.
    // EN: Sample (Argon2id per attempt): slot from byte 23, own wrap, another slot's wrap.
    let wraps = f.header_len - 3 * 48;
    let positions = [10, 15, 22, 24, 25, 29, 33, 37, 38, 69, 70, 81, 100, 900];
    for pos in positions
        .into_iter()
        .chain([wraps, wraps + 47, wraps + 48, f.header_len - 1])
    {
        let changed = common::flip(&f.file, pos);
        assert!(f.with_passphrase(&changed).is_err(), "Byte {pos}");
    }
    // DE: Faktor-Kennzeichen gelöscht: Fehler vor der Ableitung. EN: Factor flag cleared.
    let mut cleared = f.file.clone();
    cleared[24] = 0;
    let unused = Error::InvalidInput {
        field: "factor_unused",
    };
    assert_eq!(f.with_passphrase(&cleared).err(), Some(unused));
}

#[test]
fn c04_stream_bytes_truncation_and_appending() {
    let f = fixture();
    for pos in f.header_len..f.file.len() {
        let changed = common::flip(&f.file, pos);
        assert_eq!(f.with_key(0, &changed).err(), Some(Error::Decrypt), "{pos}");
    }
    for len in [
        0,
        9,
        10,
        23,
        f.header_len - 1,
        f.header_len,
        f.file.len() - 1,
    ] {
        assert!(
            f.with_key(1, &f.file[..len]).is_err(),
            "Länge / length {len}"
        );
    }
    let mut longer = f.file.clone();
    longer.push(0);
    assert!(f.with_key(0, &longer).is_err());
}

#[test]
fn c04_removed_slots_do_not_open() {
    let f = fixture();
    // DE: Jeden Zugang samt Hülle entfernen; die übrigen öffnen danach nicht mehr.
    // EN: Remove each slot with its wrap; the remaining ones no longer open.
    for removed in 0..3 {
        let changed = f.rebuilt(|header| {
            header.slots.remove(removed);
            header.wraps.remove(removed);
        });
        assert_eq!(
            v2::header_len(&changed),
            changed.len() - (f.file.len() - f.header_len)
        );
        for key in 0..2 {
            let expected = if removed == key + 1 {
                // DE: Eigener Zugang fehlt. EN: Own slot is gone.
                Error::InvalidInput { field: "recipient" }
            } else {
                Error::Decrypt
            };
            assert_eq!(
                f.with_key(key, &changed).err(),
                Some(expected),
                "{removed}/{key}"
            );
        }
    }
    let without_recipient = f.rebuilt(|header| {
        header.slots.pop();
        header.wraps.pop();
    });
    assert_eq!(
        f.with_passphrase(&without_recipient).err(),
        Some(Error::Decrypt)
    );
}

#[test]
fn c04_swapped_slots_and_wraps_do_not_open() {
    let f = fixture();
    // DE: Nur die Hüllen vertauscht: Header bleibt gültig, das Öffnen scheitert.
    // EN: Only the wraps swapped: header stays valid, opening fails.
    let wraps_swapped = f.rebuilt(|header| header.wraps.swap(1, 2));
    assert_eq!(f.with_key(0, &wraps_swapped).err(), Some(Error::Decrypt));
    assert_eq!(f.with_key(1, &wraps_swapped).err(), Some(Error::Decrypt));
    let first_two = f.rebuilt(|header| header.wraps.swap(0, 1));
    assert_eq!(f.with_passphrase(&first_two).err(), Some(Error::Decrypt));

    // DE: Zugänge samt Hüllen vertauscht: nicht mehr kanonisch, der Parser lehnt ab. Die Bytes
    //     dafür von Hand umstellen, weil `encode` die Regel selbst prüft.
    // EN: Slots swapped together with wraps: no longer canonical, the parser rejects. Rearrange
    //     the bytes by hand because `encode` checks the rule itself.
    let first = HeaderV2::read(&mut &f.file[..]).unwrap().slots[1]
        .encode()
        .unwrap();
    let (a, wraps) = (23 + 59, f.header_len - 3 * 48);
    let b = a + first.len();
    let mut swapped = f.file[..a].to_vec();
    swapped.extend_from_slice(&f.file[b..wraps]);
    swapped.extend_from_slice(&f.file[a..b]);
    swapped.extend_from_slice(&f.file[wraps..wraps + 48]);
    swapped.extend_from_slice(&f.file[wraps + 96..wraps + 144]);
    swapped.extend_from_slice(&f.file[wraps + 48..wraps + 96]);
    swapped.extend_from_slice(&f.file[f.header_len..]);
    assert_eq!(swapped.len(), f.file.len());
    let header = Error::InvalidInput { field: "header" };
    assert_eq!(f.with_key(0, &swapped).err(), Some(header));
}
