//! DE: Anonyme Empfänger (Format v4, Bit ANON, experimentell, #316/#340; Katalog P07): richtiger
//! Schlüssel an jeder Position, fremder Schlüssel erst nach allen Versuchen abgewiesen, nur
//! ML-KEM-1024, keine IDs im Header, Downgrade, Kombination mit Passphrase, Signatur und Füllung.
//! EN: Anonymous recipients (format v4, bit ANON, experimental, #316/#340; catalogue P07): right
//! key at every position, a foreign key rejected only after all attempts, ML-KEM-1024 only, no IDs
//! in the header, downgrade, combination with passphrase, signature and padding.

// DE: Tests dürfen unwrap/expect nutzen. EN: Tests may use unwrap/expect.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

use pqkeep::Error;
use pqkeep::crypto::{DsaAlgorithm, KemAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{KeyFile, PublicKeyFile};
use pqkeep::files::format_v4::{OPT_ANON, OPT_PAD};
use pqkeep::files::{self, EncryptOptions, PassphraseAccess, Protection, Slot, Unlock};
use pqkeep::security::StrongPassphrase;

const ANON: EncryptOptions = EncryptOptions {
    pad: false,
    anonymous: true,
};
const KEM1024: KeyAlgorithm = KeyAlgorithm::Kem(KemAlgorithm::MlKem1024);

fn keys(n: usize) -> Vec<(KeyFile, StrongPassphrase, PublicKeyFile)> {
    (0..n)
        .map(|_| {
            let (file, pass) = common::key_file(KEM1024);
            let public = file.public_part().unwrap();
            (file, pass, public)
        })
        .collect()
}

fn opens(enc: &Path, key: &KeyFile, pass: &StrongPassphrase) -> pqkeep::Result<Vec<u8>> {
    let unlocked = key.unlock(pass.as_ref()).unwrap();
    let out = enc.with_file_name("klar.bin");
    let _ = std::fs::remove_file(&out);
    files::decrypt(enc, &out, &Unlock::Key(&unlocked)).map(|_| std::fs::read(&out).unwrap())
}

#[test]
fn every_recipient_opens_and_header_has_no_ids() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("brief.txt");
    std::fs::write(&src, b"geheim").unwrap();
    let all = keys(5);
    let publics: Vec<&PublicKeyFile> = all.iter().map(|(_, _, p)| p).collect();
    let p = Protection::Slots {
        passphrase: None,
        recipients: &publics,
    };
    let enc = dir.path().join("a.pqkf");
    files::encrypt_with_options(&src, &enc, &p, None, ANON).unwrap();
    let header = files::inspect_v2(&enc).unwrap();
    assert_eq!(header.v4.as_ref().unwrap().options & OPT_ANON, OPT_ANON);
    assert!(
        header
            .slots
            .iter()
            .all(|s| matches!(s, Slot::Anonymous { .. }))
    );
    let bytes = std::fs::read(&enc).unwrap();
    for (_, _, public) in &all {
        let id = <sha3::Sha3_256 as sha3::Digest>::digest(public.public_key());
        let found = bytes.windows(id.len()).any(|w| w == id.as_slice());
        assert!(!found, "ID im Header / ID in header");
    }
    for (file, pass, _) in &all {
        assert_eq!(opens(&enc, file, pass).unwrap(), b"geheim");
    }
    // DE: Fremder ML-KEM-1024-Schlüssel: klare Meldung nach allen Versuchen.
    // EN: Foreign ML-KEM-1024 key: clear message after all attempts.
    let (other, other_pass, _) = keys(1).pop().unwrap();
    assert_eq!(
        opens(&enc, &other, &other_pass),
        Err(Error::InvalidInput {
            field: "anonymous_recipient"
        })
    );
    assert!(!dir.path().join("klar.bin").exists());
}

#[test]
fn only_ml_kem_1024_and_downgrade_fails() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("x.txt");
    std::fs::write(&src, b"x").unwrap();
    let (k768, _) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    let public = k768.public_part().unwrap();
    let enc = dir.path().join("x.pqkf");
    let r = files::encrypt_with_options(&src, &enc, &Protection::Recipient(&public), None, ANON);
    assert_eq!(
        r.unwrap_err(),
        Error::InvalidInput {
            field: "anonymous_kem"
        }
    );
    assert!(!enc.exists());
    let all = keys(1);
    let (file, pass, public) = &all[0];
    files::encrypt_with_options(&src, &enc, &Protection::Recipient(public), None, ANON).unwrap();
    let mut bytes = std::fs::read(&enc).unwrap();
    bytes[22] &= !0x02; // DE/EN: ANON-Bit löschen / clear the ANON bit
    let bad = dir.path().join("bad.pqkf");
    std::fs::write(&bad, &bytes).unwrap();
    assert!(opens(&bad, file, pass).is_err());
}

#[test]
fn combines_with_passphrase_signature_and_padding() {
    let dir = tempfile::tempdir().unwrap();
    let plain = vec![4u8; 3000];
    let all = keys(3);
    let publics: Vec<&PublicKeyFile> = all.iter().map(|(_, _, p)| p).collect();
    let own = common::random_passphrase();
    let access = PassphraseAccess {
        passphrase: &own,
        params: common::min_params(),
        factor: None,
    };
    let p = Protection::Slots {
        passphrase: Some(access),
        recipients: &publics,
    };
    let (sig, sig_pass) = common::key_file(KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87));
    let signer = sig.unlock(sig_pass.as_ref()).unwrap();
    let options = EncryptOptions {
        pad: true,
        anonymous: true,
    };
    let enc = dir.path().join("s.pqkf");
    files::encrypt_stream_to(&mut &plain[..], &enc, &p, Some(&signer), options).unwrap();
    let v4 = files::inspect_v2(&enc).unwrap().v4.unwrap();
    assert_eq!(v4.options & (OPT_ANON | OPT_PAD), OPT_ANON | OPT_PAD);
    let (file, pass, _) = &all[2];
    assert_eq!(opens(&enc, file, pass).unwrap(), plain);
    let report = files::check(&enc, &Unlock::Passphrase(own.as_ref())).unwrap();
    assert!(report.signer.is_some());
}
