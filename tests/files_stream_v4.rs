//! DE: Format v4, Inhalt „Strom“ (#316 Schritt 1, #83): Rundläufe (Größen an Blockgrenzen,
//! Passphrase, Empfänger, mehrere Zugänge, signiert), Downgrade, Abschneiden, Anhängen, ältere
//! Leser, kein Originalname. Testkatalog P02–P04 in `docs/V4_DRAFT.md`.
//! EN: Format v4, content "stream" (#316 step 1, #83): round trips (sizes at chunk boundaries,
//! passphrase, recipient, several slots, signed), downgrade, truncation, appending, older readers,
//! no original name. Test catalogue P02–P04 in `docs/V4_DRAFT.md`.

// DE: Tests dürfen unwrap/expect nutzen. EN: Tests may use unwrap/expect.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use pqkeep::Error;
use pqkeep::crypto::{DsaAlgorithm, KemAlgorithm, KeyAlgorithm};
use pqkeep::envelope::UnlockedKey;
use pqkeep::files::{self, Content, PassphraseAccess, Protection, Unlock};
use pqkeep::security::StrongPassphrase;

const CHUNK: usize = 64 * 1024;

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

fn pass_protection(pass: &StrongPassphrase) -> Protection<'_> {
    Protection::Passphrase {
        passphrase: pass,
        params: common::min_params(),
    }
}

/// DE: Verschlüsselt `plain` als Strom in eine Datei. EN: Encrypts `plain` as a stream into a file.
fn sealed(dir: &Path, plain: &[u8], p: &Protection<'_>, signer: Option<&UnlockedKey>) -> PathBuf {
    let enc = dir.join("strom.pqkf");
    let _ = std::fs::remove_file(&enc);
    let report = files::encrypt_stream_to(
        &mut &plain[..],
        &enc,
        p,
        signer,
        files::EncryptOptions::default(),
    )
    .unwrap();
    assert_eq!(report.bytes, plain.len() as u64);
    enc
}

fn opened(enc: &Path, unlock: &Unlock<'_>) -> pqkeep::Result<Vec<u8>> {
    let out = enc.with_file_name("klar.bin");
    let _ = std::fs::remove_file(&out);
    files::decrypt(enc, &out, unlock).map(|_| std::fs::read(&out).unwrap())
}

#[test]
fn passphrase_roundtrip_at_chunk_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let pass = common::random_passphrase();
    let unlock = Unlock::Passphrase(pass.as_ref());
    for len in [
        0,
        1,
        CHUNK - 25,
        CHUNK - 24,
        CHUNK,
        CHUNK + 1,
        3 * CHUNK + 5,
    ] {
        let plain = data(len);
        let enc = sealed(dir.path(), &plain, &pass_protection(&pass), None);
        let header = files::inspect_v2(&enc).unwrap();
        assert_eq!((header.version(), header.content), (4, Content::Stream));
        assert_eq!(
            opened(&enc, &unlock).unwrap(),
            plain,
            "Länge / length {len}"
        );
        assert_eq!(files::check(&enc, &unlock).unwrap().bytes, len as u64);
    }
}

#[test]
fn recipients_and_signature_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let (anna, anna_pass) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem1024));
    let (ben, ben_pass) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    let (sig, sig_pass) = common::key_file(KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87));
    let signer = sig.unlock(sig_pass.as_ref()).unwrap();
    let (pa, pb) = (anna.public_part().unwrap(), ben.public_part().unwrap());
    let own = common::random_passphrase();
    let access = PassphraseAccess {
        passphrase: &own,
        params: common::min_params(),
        factor: None,
    };
    let recipients = [&pa, &pb];
    let p = Protection::Slots {
        passphrase: Some(access),
        recipients: &recipients,
    };
    let plain = data(2 * CHUNK + 7);
    let enc = sealed(dir.path(), &plain, &p, Some(&signer));
    for (key, pass) in [(&anna, &anna_pass), (&ben, &ben_pass)] {
        let unlocked = key.unlock(pass.as_ref()).unwrap();
        assert_eq!(opened(&enc, &Unlock::Key(&unlocked)).unwrap(), plain);
    }
    let report = files::check(&enc, &Unlock::Passphrase(own.as_ref())).unwrap();
    assert!(report.signer.is_some());
    let other = files::check_with(
        &enc,
        &Unlock::Passphrase(own.as_ref()),
        Some(&pa), // DE: kein ML-DSA-Schlüssel. EN: not an ML-DSA key.
    );
    assert!(other.is_err());
}

/// DE: Byte `at` ändern, danach darf nichts entstehen. EN: Change byte `at`, nothing may appear.
fn rejected(enc: &Path, bytes: &[u8], unlock: &Unlock<'_>, what: &str) -> Error {
    let bad = enc.with_file_name("kaputt.pqkf");
    std::fs::write(&bad, bytes).unwrap();
    let err = opened(&bad, unlock).expect_err(what);
    assert!(!bad.with_file_name("klar.bin").exists(), "{what}");
    assert!(files::check(&bad, unlock).is_err(), "{what}");
    err
}

#[test]
fn downgrade_truncation_and_appending_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let pass = common::random_passphrase();
    let unlock = Unlock::Passphrase(pass.as_ref());
    let enc = sealed(
        dir.path(),
        &data(2 * CHUNK + 3),
        &pass_protection(&pass),
        None,
    );
    let good = std::fs::read(&enc).unwrap();
    // DE: Magic 8 | Version 2 | Inhalt 1 | Blockgröße 4 | Präfix 7 | Optionen 2.
    // EN: magic 8 | version 2 | content 1 | chunk size 4 | prefix 7 | options 2.
    let edit = |at: usize, value: u8| {
        let mut b = good.clone();
        b[at] = value;
        b
    };
    for v in [1u8, 2, 3, 5] {
        rejected(&enc, &edit(8, v), &unlock, "Version / version");
    }
    for c in [1u8, 2, 4] {
        rejected(&enc, &edit(10, c), &unlock, "Inhalt / content");
    }
    for bit in [0x01u8, 0x02, 0x04, 0x08, 0x10] {
        rejected(&enc, &edit(22, bit), &unlock, "Optionen / options");
    }
    assert_eq!(
        rejected(
            &enc,
            &edit(22, 0x08),
            &unlock,
            "HIDDEN_SENDER (reserviert / reserved)"
        ),
        Error::Unsupported
    );
    // DE: Chiffrat = 2 volle Blöcke + letzter Block (3 B + Trailer 24 B + Tag 16 B).
    // EN: Ciphertext = 2 full chunks + last chunk (3 B + trailer 24 B + tag 16 B).
    let last = 3 + 24 + 16;
    let cipher = 2 * (CHUNK + 16) + last;
    for cut in [1, 16, last, last + CHUNK + 16, cipher - 1] {
        rejected(
            &enc,
            &good[..good.len() - cut],
            &unlock,
            "abgeschnitten / truncated",
        );
    }
    let mut longer = good.clone();
    longer.push(0);
    rejected(&enc, &longer, &unlock, "angehängt / appended");
}

#[test]
fn older_v1_reader_and_original_name_refuse_streams() {
    let dir = tempfile::tempdir().unwrap();
    let pass = common::random_passphrase();
    let enc = sealed(dir.path(), b"x", &pass_protection(&pass), None);
    assert_eq!(files::inspect(&enc), Err(Error::Unsupported));
    let same = |p: &Path| Some(p.to_path_buf());
    let r = files::decrypt_original(
        &enc,
        dir.path(),
        &Unlock::Passphrase(pass.as_ref()),
        None,
        &same,
    );
    assert!(matches!(
        r,
        Err(Error::InvalidInput {
            field: "original_name"
        })
    ));
}
