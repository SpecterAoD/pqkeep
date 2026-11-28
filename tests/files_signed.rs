//! DE: Absender-Signatur in `.pqkf` (Format v3, #44, `docs/V3_SIGNED.md`): gültige Signaturen mit
//! Passphrase, Empfängern und Faktordatei; unsignierte Dateien bleiben v1/v2; entfernte,
//! abgeschnittene, veränderte und angehängte Signaturen, getauschter Absender, Rückbau auf v2 und
//! veränderter Inhalt scheitern ohne Ausgabe; ein verlangter Absender wird vor der Ableitung geprüft.
//! EN: Sender signature inside `.pqkf` (format v3, #44, `docs/V3_SIGNED.md`): valid signatures with
//! passphrase, recipients and factor file; unsigned files stay v1/v2; stripped, truncated, altered
//! and appended signatures, a swapped sender, rewriting to v2 and altered content fail without
//! output; a required sender is checked before deriving.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::v2_files::{self as v2, CONTENT, KEMS, Workspace};
use pqkeep::Error;
use pqkeep::crypto::{DsaAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{PublicKeyFile, UnlockedKey};
use pqkeep::files::{self, PassphraseAccess, Protection, Unlock};

const ML_DSA_87: KeyAlgorithm = KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87);
const SIG_LEN: usize = 4627;

fn signer() -> (UnlockedKey, PublicKeyFile) {
    let (file, pass) = common::key_file(ML_DSA_87);
    (
        file.unlock(pass.as_ref()).unwrap(),
        file.public_part().unwrap(),
    )
}

fn signed(w: &Workspace, protection: &Protection<'_>, key: &UnlockedKey) -> Vec<u8> {
    let target = w.dir.path().join("signiert.pqkf");
    files::encrypt_signed(&w.source, &target, protection, key).unwrap();
    let bytes = std::fs::read(&target).unwrap();
    std::fs::remove_file(&target).unwrap();
    bytes
}

/// DE: Entschlüsselt mit optional verlangtem Absender; prüft Inhalt und dass nichts übrig bleibt.
/// EN: Decrypts with an optionally required sender; checks content and that nothing is left.
fn open(
    w: &Workspace,
    bytes: &[u8],
    unlock: &Unlock<'_>,
    expect: Option<&PublicKeyFile>,
) -> Result<files::Report, Error> {
    let input = w.work.join("in.pqkf");
    std::fs::write(&input, bytes).unwrap();
    let out = w.work.join("out");
    let result = files::decrypt_with(&input, &out, unlock, expect);
    std::fs::remove_file(&input).unwrap();
    if result.is_ok() {
        assert_eq!(std::fs::read(&out).unwrap(), CONTENT);
        std::fs::remove_file(&out).unwrap();
    }
    assert!(common::dir_names(&w.work).is_empty(), "Reste / leftovers");
    result
}

#[test]
fn signed_passphrase_file_is_v3_and_names_the_sender() {
    let w = v2::workspace();
    let (key, public) = signer();
    let pass = common::random_passphrase();
    let protection = Protection::Passphrase {
        passphrase: &pass,
        params: common::min_params(),
    };
    let bytes = signed(&w, &protection, &key);
    assert_eq!(v2::version(&bytes), 3);
    let unlock = Unlock::Passphrase(pass.as_ref());
    let report = open(&w, &bytes, &unlock, None).unwrap();
    assert_eq!(report.signer.unwrap().key_id(), public.key_id());
    // DE: Verlangter, richtiger Absender. EN: Required, correct sender.
    assert!(open(&w, &bytes, &unlock, Some(&public)).is_ok());
    // DE: Header zeigt den Absender ungeprüft. EN: Header shows the sender unverified.
    let input = w.work.join("in.pqkf");
    std::fs::write(&input, &bytes).unwrap();
    let header = files::inspect_v2(&input).unwrap();
    std::fs::remove_file(&input).unwrap();
    assert_eq!(header.signer.unwrap().key_id(), public.key_id());
}

#[test]
fn signed_works_with_recipients_factor_and_check() {
    let w = v2::workspace();
    let (key, public) = signer();
    let pass = common::random_passphrase();
    let factor = v2::factor();
    let (anna_pub, anna) = v2::kem_key(KEMS[0]);
    let (ben_pub, ben) = v2::kem_key(KEMS[2]);
    let recipients = [&anna_pub, &ben_pub];
    let protection = Protection::Slots {
        passphrase: Some(PassphraseAccess {
            passphrase: &pass,
            params: common::min_params(),
            factor: Some(&factor),
        }),
        recipients: &recipients,
    };
    let bytes = signed(&w, &protection, &key);
    assert_eq!(v2::version(&bytes), 3);
    for unlock in [
        Unlock::Key(&anna),
        Unlock::Key(&ben),
        Unlock::PassphraseWithFactor {
            passphrase: pass.as_ref(),
            factor: &factor,
        },
    ] {
        let report = open(&w, &bytes, &unlock, Some(&public)).unwrap();
        assert_eq!(report.signer.unwrap().key_id(), public.key_id());
    }
    let input = w.work.join("check.pqkf");
    std::fs::write(&input, &bytes).unwrap();
    let report = files::check_with(&input, &Unlock::Key(&anna), Some(&public)).unwrap();
    assert_eq!(report.signer.unwrap().key_id(), public.key_id());
    assert!(files::list(&input, &Unlock::Key(&ben)).is_ok());
    std::fs::remove_file(&input).unwrap();
}

#[test]
fn unsigned_files_keep_v1_and_v2_and_carry_no_sender() {
    let w = v2::workspace();
    let (anna_pub, anna) = v2::kem_key(KEMS[1]);
    let (ben_pub, _) = v2::kem_key(KEMS[1]);
    for (recipients, version) in [(vec![&anna_pub], 1), (vec![&anna_pub, &ben_pub], 2)] {
        let target = w.dir.path().join("plain.pqkf");
        let protection = Protection::Slots {
            passphrase: None,
            recipients: &recipients,
        };
        files::encrypt(&w.source, &target, &protection).unwrap();
        let bytes = std::fs::read(&target).unwrap();
        std::fs::remove_file(&target).unwrap();
        assert_eq!(v2::version(&bytes), version);
        let report = open(&w, &bytes, &Unlock::Key(&anna), None).unwrap();
        assert_eq!(report.signer, None);
        // DE: Verlangter Absender, Datei unsigniert. EN: Required sender, file unsigned.
        let (_, public) = signer();
        let err = open(&w, &bytes, &Unlock::Key(&anna), Some(&public));
        assert_eq!(err.unwrap_err(), Error::InvalidSignature);
    }
}

fn recipient_case() -> (Workspace, Vec<u8>, UnlockedKey, PublicKeyFile) {
    let w = v2::workspace();
    let (key, public) = signer();
    let (anna_pub, anna) = v2::kem_key(KEMS[1]);
    let bytes = signed(&w, &Protection::Recipient(&anna_pub), &key);
    (w, bytes, anna, public)
}

#[test]
fn stripped_truncated_and_appended_signatures_fail_without_output() {
    let (w, bytes, anna, _) = recipient_case();
    let unlock = Unlock::Key(&anna);
    let n = bytes.len();
    for broken in [
        bytes[..n - SIG_LEN].to_vec(),
        bytes[..n - 1].to_vec(),
        bytes[..n - SIG_LEN - 1].to_vec(),
        [bytes.as_slice(), b"x"].concat(),
        [bytes.as_slice(), &bytes[n - SIG_LEN..]].concat(),
    ] {
        let err = open(&w, &broken, &unlock, None).unwrap_err();
        assert!(
            matches!(err, Error::Decrypt | Error::InvalidSignature),
            "{err:?}"
        );
    }
}

#[test]
fn altered_signature_content_and_header_fail() {
    let (w, bytes, anna, _) = recipient_case();
    let unlock = Unlock::Key(&anna);
    let n = bytes.len();
    let header = v2::header_len(&bytes);
    for i in [n - 1, n - SIG_LEN, n - SIG_LEN / 2] {
        let err = open(&w, &common::flip(&bytes, i), &unlock, None).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidSignature,
            "Signatur-Byte / signature byte {i}"
        );
    }
    // DE: Chiffrat und Absenderblock/Schlüsselbindung im Header.
    // EN: Ciphertext and sender block/commitment in the header.
    for i in [
        header + 3,
        n - SIG_LEN - 1,
        header - 1 - 48,
        header - 48 - 40,
    ] {
        assert!(
            open(&w, &common::flip(&bytes, i), &unlock, None).is_err(),
            "Byte {i}"
        );
    }
}

#[test]
fn swapped_sender_and_rewrite_to_v2_fail() {
    let (w, bytes, anna, _) = recipient_case();
    let unlock = Unlock::Key(&anna);
    let header = v2::header_len(&bytes);
    // DE: Absenderblock = 1 + 2592 + 32 Byte direkt vor der einen Hülle (48 Byte).
    // EN: Sender block = 1 + 2592 + 32 bytes right before the single wrap (48 bytes).
    let block_end = header - 48;
    let block_start = block_end - (1 + 2592 + 32);
    let (_, other) = signer();
    let mut swapped = bytes.clone();
    swapped[block_start + 1..block_start + 1 + 2592].copy_from_slice(other.public_key());
    assert!(open(&w, &swapped, &unlock, None).is_err());
    assert_eq!(
        open(&w, &swapped, &unlock, Some(&other)).unwrap_err(),
        Error::Decrypt
    );
    // DE: Absenderblock und Signatur entfernt, Version 2 eingetragen.
    // EN: Sender block and signature removed, version 2 written.
    let mut v2_bytes = [
        &bytes[..block_start],
        &bytes[block_end..bytes.len() - SIG_LEN],
    ]
    .concat();
    v2_bytes[8] = 2;
    assert_eq!(
        open(&w, &v2_bytes, &unlock, None).unwrap_err(),
        Error::Decrypt
    );
}

#[test]
fn required_sender_is_checked_before_unlocking() {
    let (w, bytes, anna, public) = recipient_case();
    let (_, other) = signer();
    // DE: Anderer Absender: Fehler schon vor der Entkapselung (auch mit fremdem Schlüssel).
    // EN: Other sender: error already before decapsulation (even with a foreign key).
    let (_, stranger) = v2::kem_key(KEMS[0]);
    for unlock in [Unlock::Key(&anna), Unlock::Key(&stranger)] {
        let err = open(&w, &bytes, &unlock, Some(&other)).unwrap_err();
        assert_eq!(err, Error::InvalidSignature);
    }
    assert!(open(&w, &bytes, &Unlock::Key(&anna), Some(&public)).is_ok());
    // DE: Verlangter Absender muss ML-DSA-87 sein. EN: Required sender must be ML-DSA-87.
    let (kem_pub, _) = v2::kem_key(KEMS[1]);
    let err = open(&w, &bytes, &Unlock::Key(&anna), Some(&kem_pub)).unwrap_err();
    assert_eq!(err, Error::Unsupported);
}

#[test]
fn only_ml_dsa_87_can_sign() {
    let w = v2::workspace();
    let (anna_pub, _) = v2::kem_key(KEMS[1]);
    let target = w.dir.path().join("nein.pqkf");
    for algorithm in [
        KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa65),
        KeyAlgorithm::Kem(KEMS[1]),
    ] {
        let (file, pass) = common::key_file(algorithm);
        let key = file.unlock(pass.as_ref()).unwrap();
        let err =
            files::encrypt_signed(&w.source, &target, &Protection::Recipient(&anna_pub), &key);
        assert_eq!(err.unwrap_err(), Error::Unsupported);
        assert!(!target.exists());
    }
}
