//! DE: Manipulierte .pqkf-Dateien (Header- und Strombytes, Abschneiden, Anhängen)
//! und falsche Schlüssel. Immer Fehler, nie Teilausgabe, nie Panik.
//! EN: Tampered .pqkf files (header and stream bytes, truncation, appending) and
//! wrong keys. Always an error, never partial output, never a panic.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use pqc_keyforge::Error;
use pqc_keyforge::crypto::{DsaAlgorithm, KemAlgorithm, KeyAlgorithm};
use pqc_keyforge::envelope::UnlockedKey;
use pqc_keyforge::files::{self, Protection, Unlock};

struct Fixture {
    _dir: tempfile::TempDir,
    work: PathBuf,
    enc: Vec<u8>,
    unlocked: UnlockedKey,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("baum");
    std::fs::create_dir(&src).unwrap();
    common::write_sample_tree(&src);
    let (key_file, pass) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    let enc_path = dir.path().join("baum.pqkf");
    files::encrypt(&src, &enc_path, &Protection::Recipient(&key_file)).unwrap();
    let work = dir.path().join("arbeit");
    std::fs::create_dir(&work).unwrap();
    Fixture {
        enc: std::fs::read(&enc_path).unwrap(),
        unlocked: key_file.unlock(pass.as_ref()).unwrap(),
        work,
        _dir: dir,
    }
}

fn try_decrypt(f: &Fixture, bytes: &[u8]) -> Result<(), Error> {
    let input = f.work.join("in.pqkf");
    std::fs::write(&input, bytes).unwrap();
    let result = files::decrypt(&input, &f.work.join("out"), &Unlock::Key(&f.unlocked));
    std::fs::remove_file(&input).unwrap();
    if result.is_err() {
        assert_eq!(
            common::dir_names(&f.work),
            Vec::<String>::new(),
            "Reste / leftovers"
        );
    } else {
        std::fs::remove_dir_all(f.work.join("out")).unwrap();
    }
    result.map(|_| ())
}

#[test]
fn unchanged_file_works() {
    let f = fixture();
    assert!(try_decrypt(&f, &f.enc).is_ok());
}

#[test]
fn every_header_byte_matters() {
    let f = fixture();
    // DE: Header im Empfänger-Modus (ML-KEM-768): 8+2+1+1+4+7+1+32+2+1088+12+48 Byte.
    // EN: Header in recipient mode (ML-KEM-768): 8+2+1+1+4+7+1+32+2+1088+12+48 bytes.
    let header_len = 8 + 2 + 1 + 1 + 4 + 7 + 1 + 32 + 2 + 1088 + 12 + 48;
    for pos in (0..header_len).step_by(7).chain([header_len - 1]) {
        let mut bad = f.enc.clone();
        bad[pos] ^= 0x01;
        assert!(
            try_decrypt(&f, &bad).is_err(),
            "Header-Byte / header byte {pos}"
        );
    }
}

#[test]
fn stream_tampering() {
    let f = fixture();
    let len = f.enc.len();
    for pos in [1300, len / 2, len - 17, len - 1] {
        let mut bad = f.enc.clone();
        bad[pos] ^= 0x80;
        assert_eq!(
            try_decrypt(&f, &bad).err(),
            Some(Error::Decrypt),
            "pos {pos}"
        );
    }
    for cut in [len - 1, len - 16, len / 2, 1300, 10, 0] {
        assert!(try_decrypt(&f, &f.enc[..cut]).is_err(), "cut {cut}");
    }
    let mut appended = f.enc.clone();
    appended.extend_from_slice(&[0u8; 20]);
    assert_eq!(try_decrypt(&f, &appended).err(), Some(Error::Decrypt));
}

fn encrypt_with_passphrase(dir: &Path) -> (PathBuf, pqc_keyforge::security::StrongPassphrase) {
    let src = dir.join("a.txt");
    std::fs::write(&src, b"geheim / secret").unwrap();
    let pass = common::random_passphrase();
    let enc = dir.join("a.pqkf");
    let protection = Protection::Passphrase {
        passphrase: &pass,
        params: common::min_params(),
    };
    files::encrypt(&src, &enc, &protection).unwrap();
    (enc, pass)
}

#[test]
fn wrong_passphrase_and_key_kind() {
    let dir = tempfile::tempdir().unwrap();
    let (enc, _pass) = encrypt_with_passphrase(dir.path());
    let other = common::random_passphrase();
    let out = dir.path().join("out.txt");
    let err = files::decrypt(&enc, &out, &Unlock::Passphrase(other.as_ref())).err();
    assert_eq!(err, Some(Error::Decrypt));
    let (key_file, kp) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    let unlocked = key_file.unlock(kp.as_ref()).unwrap();
    let err = files::decrypt(&enc, &out, &Unlock::Key(&unlocked)).err();
    assert_eq!(err, Some(Error::InvalidInput { field: "key_kind" }));
    assert!(!out.exists());
}

#[test]
fn wrong_recipient_and_non_kem_keys() {
    let f = fixture();
    let (other, pass) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    let other = other.unlock(pass.as_ref()).unwrap();
    let input = f.work.join("in.pqkf");
    std::fs::write(&input, &f.enc).unwrap();
    let out = f.work.join("out");
    let err = files::decrypt(&input, &out, &Unlock::Key(&other)).err();
    assert_eq!(err, Some(Error::InvalidInput { field: "recipient" }));
    let p = common::random_passphrase();
    let err = files::decrypt(&input, &out, &Unlock::Passphrase(p.as_ref())).err();
    assert_eq!(err, Some(Error::InvalidInput { field: "key_kind" }));

    let src = f.work.join("x.txt");
    std::fs::write(&src, b"x").unwrap();
    for alg in [
        KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa65),
        KeyAlgorithm::Aes256,
    ] {
        let (kf, _) = common::key_file(alg);
        let err = files::encrypt(&src, &f.work.join("x.pqkf"), &Protection::Recipient(&kf)).err();
        assert_eq!(
            err,
            Some(Error::InvalidInput { field: "recipient" }),
            "{alg:?}"
        );
    }
    assert!(!f.work.join("x.pqkf").exists());
}
