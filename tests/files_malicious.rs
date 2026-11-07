//! DE: Bösartige, aber KORREKT für den Empfänger verschlüsselte Archive (jeder mit
//! dem öffentlichen Schlüssel kann solche bauen). Alles muss abgewiesen werden,
//! ohne Ziel, ohne Reste und ohne Dateien außerhalb des Ziels.
//! EN: Malicious but CORRECTLY encrypted archives for the recipient (anyone with
//! the public key can build them). Everything must be rejected – no target, no
//! leftovers and no files outside the target.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

use pqkeep::crypto::stream::EncryptWriter;
use pqkeep::crypto::wrap::{self, Wrapped};
use pqkeep::crypto::{KemAlgorithm, KeyAlgorithm, aead, rng};
use pqkeep::envelope::{KeyFile, UnlockedKey};
use pqkeep::files::{self, Content, FileHeader, HeaderMode, Unlock};
use sha3::{Digest, Sha3_256};

/// DE: Rohes Archiv: Einträge als (Tag, Pfad, Inhalt, Prüfsumme korrekt?).
/// EN: Raw archive: entries as (tag, path, content, checksum correct?).
fn dir_entry(path: &str) -> Vec<u8> {
    let mut v = vec![1u8];
    v.extend_from_slice(&u16::try_from(path.len()).unwrap().to_le_bytes());
    v.extend_from_slice(path.as_bytes());
    v
}

fn file_entry(path: &str, data: &[u8], good_hash: bool) -> Vec<u8> {
    let mut v = vec![2u8];
    v.extend_from_slice(&u16::try_from(path.len()).unwrap().to_le_bytes());
    v.extend_from_slice(path.as_bytes());
    v.extend_from_slice(&(data.len() as u64).to_le_bytes());
    v.extend_from_slice(data);
    let mut hash = Sha3_256::digest(data).to_vec();
    if !good_hash {
        hash[0] ^= 1;
    }
    v.extend_from_slice(&hash);
    v
}

fn end(count: u64) -> Vec<u8> {
    let mut v = vec![0u8];
    v.extend_from_slice(&count.to_le_bytes());
    v
}

struct Key {
    file: KeyFile,
    unlocked: UnlockedKey,
}

fn key() -> Key {
    let (file, pass) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    let unlocked = file.unlock(pass.as_ref()).unwrap();
    Key { file, unlocked }
}

/// DE: Verschlüsselt rohe Archivbytes korrekt für den Empfänger.
/// EN: Correctly encrypts raw archive bytes for the recipient.
fn build(key: &Key, content: Content, plaintext: &[u8], out: &Path) {
    let file_key = aead::generate_key().unwrap();
    let recipient_id: [u8; 32] = key.file.key_id().try_into().unwrap();
    let mut header = FileHeader {
        content,
        prefix: rng::array().unwrap(),
        mode: HeaderMode::Recipient {
            algorithm: KemAlgorithm::MlKem768,
            recipient_id,
            kem_ciphertext: Vec::new(),
        },
        wrapped: Wrapped {
            nonce: [0; 12],
            ciphertext: Vec::new(),
        },
    };
    let aad = header.wrap_aad();
    let r = wrap::wrap_for_recipient(
        KemAlgorithm::MlKem768,
        key.file.public_key(),
        &recipient_id,
        file_key.expose(),
        &aad,
    )
    .unwrap();
    header.mode = HeaderMode::Recipient {
        algorithm: KemAlgorithm::MlKem768,
        recipient_id,
        kem_ciphertext: r.kem_ciphertext,
    };
    header.wrapped = r.wrapped;
    let mut bytes = header.encode();
    let mut enc = EncryptWriter::new(
        file_key.expose(),
        header.prefix,
        &header.stream_aad(),
        Vec::new(),
    )
    .unwrap();
    enc.push(plaintext).unwrap();
    bytes.extend(enc.finish().unwrap().0);
    std::fs::write(out, bytes).unwrap();
}

fn assert_rejected(key: &Key, content: Content, plaintext: &[u8], what: &str) {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("arbeit");
    std::fs::create_dir(&work).unwrap();
    let enc = dir.path().join("evil.pqkf");
    build(key, content, plaintext, &enc);
    let target = work.join("ziel");
    let result = files::decrypt(&enc, &target, &Unlock::Key(&key.unlocked));
    assert!(result.is_err(), "{what}: angenommen / accepted");
    assert_eq!(
        common::dir_names(&work),
        Vec::<String>::new(),
        "{what}: Reste / leftovers"
    );
    assert_eq!(
        common::dir_names(dir.path()),
        vec!["arbeit", "evil.pqkf"],
        "{what}: außerhalb / outside"
    );
}

#[test]
fn control_case_is_accepted() {
    // DE: Gegenprobe: dasselbe Werkzeug baut gültige Archive.
    // EN: Cross-check: the same tool builds valid archives.
    let key = key();
    let dir = tempfile::tempdir().unwrap();
    let enc = dir.path().join("ok.pqkf");
    let plain = [dir_entry("a"), file_entry("a/b.txt", b"hi", true), end(2)].concat();
    build(&key, Content::Directory, &plain, &enc);
    let out = dir.path().join("ok");
    files::decrypt(&enc, &out, &Unlock::Key(&key.unlocked)).unwrap();
    assert_eq!(std::fs::read(out.join("a").join("b.txt")).unwrap(), b"hi");
}

#[test]
fn path_traversal_and_absolute_paths() {
    let key = key();
    for evil in [
        "../evil.txt",
        "a/../../evil.txt",
        "/etc/evil",
        "C:\\evil.txt",
        "C:/evil.txt",
        "\\\\server\\share\\x",
        "a\\..\\evil",
        "CON",
        "aux.txt",
        "a/./b",
        "",
        "trailing.",
    ] {
        let plain = [file_entry(evil, b"x", true), end(1)].concat();
        assert_rejected(&key, Content::Directory, &plain, evil);
    }
}

#[test]
fn duplicates_and_conflicts() {
    let key = key();
    let cases = [
        (
            "dup",
            [
                file_entry("a.txt", b"1", true),
                file_entry("a.txt", b"2", true),
                end(2),
            ]
            .concat(),
        ),
        (
            "case",
            [
                file_entry("a.txt", b"1", true),
                file_entry("A.TXT", b"2", true),
                end(2),
            ]
            .concat(),
        ),
        (
            "below file",
            [
                file_entry("a", b"1", true),
                file_entry("a/b", b"2", true),
                end(2),
            ]
            .concat(),
        ),
        ("dir dup", [dir_entry("d"), dir_entry("D"), end(2)].concat()),
    ];
    for (what, plain) in cases {
        assert_rejected(&key, Content::Directory, &plain, what);
    }
}

#[test]
fn structural_errors() {
    let key = key();
    let mut bad_tag = file_entry("a.txt", b"x", true);
    bad_tag[0] = 9;
    let mut non_utf8 = file_entry("ab", b"x", true);
    non_utf8[3] = 0xFF;
    let cases = [
        (
            "checksum",
            [file_entry("a.txt", b"data", false), end(1)].concat(),
        ),
        ("count", [file_entry("a.txt", b"x", true), end(5)].concat()),
        ("no end", file_entry("a.txt", b"x", true)),
        (
            "trailing",
            [file_entry("a.txt", b"x", true), end(1), vec![0u8; 3]].concat(),
        ),
        ("unknown tag", [bad_tag, end(1)].concat()),
        ("non-utf8", [non_utf8, end(1)].concat()),
        ("size too big", {
            let mut v = file_entry("a.txt", b"x", true);
            v[8..16].copy_from_slice(&1_000u64.to_le_bytes());
            [v, end(1)].concat()
        }),
        ("empty", Vec::new()),
    ];
    for (what, plain) in cases {
        assert_rejected(&key, Content::Directory, &plain, what);
    }
}

#[test]
fn single_file_content_rules() {
    let key = key();
    let cases = [
        ("dir in file", [dir_entry("a"), end(1)].concat()),
        (
            "two files",
            [
                file_entry("a", b"1", true),
                file_entry("b", b"2", true),
                end(2),
            ]
            .concat(),
        ),
        (
            "bad name",
            [file_entry("../a", b"1", true), end(1)].concat(),
        ),
        (
            "bad checksum",
            [file_entry("a", b"1", false), end(1)].concat(),
        ),
    ];
    for (what, plain) in cases {
        assert_rejected(&key, Content::File, &plain, what);
    }
}
