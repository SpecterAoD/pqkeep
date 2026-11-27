//! DE: Verborgener Absender (Format v4, Bit `HIDDEN_SENDER`, #316 Schritt 5; Katalog P08): Rundläufe
//! für Datei, Ordner und Strom, auch mit Füllung und anonymen Empfängern; kein Absenderschlüssel im
//! Header oder Klartext der Datei; verlangter Absender passend/unpassend (ohne Ausgabe); ohne
//! Schlüssel abgewiesen; Umschalten der Bits (auch SIGNED+HIDDEN) abgewiesen.
//! EN: Hidden sender (format v4, bit `HIDDEN_SENDER`, #316 step 5; catalogue P08): round trips for
//! file, directory and stream, also with padding and anonymous recipients; no sender key in the
//! header or anywhere in the file; required sender matching/non-matching (no output); rejected
//! without a key; toggling the bits (also SIGNED+HIDDEN) rejected.

// DE: Tests dürfen unwrap/expect nutzen. EN: Tests may use unwrap/expect.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

use pqkeep::Error;
use pqkeep::crypto::{DsaAlgorithm, KemAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{PublicKeyFile, UnlockedKey};
use pqkeep::files::format_v4::{OPT_ANON, OPT_HIDDEN_SENDER, OPT_PAD, OPT_SIGNED, padme};
use pqkeep::files::{self, Content, EncryptOptions, Protection, Unlock};

const HIDE: EncryptOptions = EncryptOptions {
    pad: false,
    anonymous: false,
    hide_sender: true,
};

fn signer() -> (UnlockedKey, PublicKeyFile) {
    let (file, pass) = common::key_file(KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87));
    (
        file.unlock(pass.as_ref()).unwrap(),
        file.public_part().unwrap(),
    )
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// DE: Header ohne sichtbaren Absender, Bit gesetzt, Schlüssel nirgends im Klartext.
/// EN: Header without visible sender, bit set, key nowhere in clear.
fn assert_hidden(enc: &Path, key: &UnlockedKey, content: Content) {
    let header = files::inspect_v2(enc).unwrap();
    assert_eq!((header.version(), header.content), (4, content));
    let options = header.v4.as_ref().unwrap().options;
    assert_eq!(
        options & (OPT_HIDDEN_SENDER | OPT_SIGNED),
        OPT_HIDDEN_SENDER
    );
    assert!(header.signer.is_none());
    let bytes = std::fs::read(enc).unwrap();
    assert!(!contains(&bytes, &key.public_key[..64]));
}

fn opened(
    enc: &Path,
    unlock: &Unlock<'_>,
    expect: Option<&PublicKeyFile>,
) -> pqkeep::Result<files::Report> {
    let out = enc.with_file_name("klar");
    let _ = std::fs::remove_dir_all(&out);
    let _ = std::fs::remove_file(&out);
    let result = files::decrypt_with(enc, &out, unlock, expect);
    assert_eq!(
        result.is_ok(),
        out.exists(),
        "Ausgabe nur bei Erfolg / output only on success"
    );
    result
}

#[test]
fn file_directory_and_stream_roundtrip_with_hidden_sender() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("brief.txt");
    std::fs::write(&file, vec![5u8; 3000]).unwrap();
    let tree = dir.path().join("baum");
    std::fs::create_dir(&tree).unwrap();
    common::write_sample_tree(&tree);
    let (key, public) = signer();
    let pass = common::random_passphrase();
    let p = Protection::Passphrase {
        passphrase: &pass,
        params: common::min_params(),
    };
    let unlock = Unlock::Passphrase(pass.as_ref());
    for options in [HIDE, EncryptOptions { pad: true, ..HIDE }] {
        for (src, content) in [(&file, Content::File), (&tree, Content::Directory)] {
            let enc = dir.path().join("x.pqkf");
            let _ = std::fs::remove_file(&enc);
            files::encrypt_with_options(src, &enc, &p, Some(&key), options).unwrap();
            assert_hidden(&enc, &key, content);
            let report = opened(&enc, &unlock, None).unwrap();
            assert_eq!(report.signer.unwrap().key_id, public.key_id());
            assert_eq!(
                files::check(&enc, &unlock).unwrap().signer.unwrap().key_id,
                public.key_id()
            );
            assert!(files::list(&enc, &unlock).is_ok());
        }
        let enc = dir.path().join("s.pqkf");
        let _ = std::fs::remove_file(&enc);
        let plain = vec![9u8; 70_000];
        files::encrypt_stream_to(&mut &plain[..], &enc, &p, Some(&key), options).unwrap();
        assert_hidden(&enc, &key, Content::Stream);
        assert_eq!(
            opened(&enc, &unlock, None).unwrap().signer.unwrap().key_id,
            public.key_id()
        );
        assert_eq!(std::fs::read(enc.with_file_name("klar")).unwrap(), plain);
        let header = files::inspect_v2(&enc).unwrap();
        assert_eq!(
            header.v4.as_ref().unwrap().options & OPT_PAD != 0,
            options.pad
        );
        if options.pad {
            // DE: PADMÉ über Nutzdaten und ganzen Trailer (7244 B). EN: PADMÉ over payload + whole trailer.
            let total = padme(70_000 + 7244).unwrap();
            let cipher = total + 16 * total.div_ceil(64 * 1024);
            let head = header.encode().unwrap().len() as u64;
            assert_eq!(std::fs::metadata(&enc).unwrap().len(), head + cipher);
        }
    }
}

#[test]
fn anonymous_recipient_with_hidden_sender() {
    let dir = tempfile::tempdir().unwrap();
    let (kem, pass) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem1024));
    let recipient = kem.public_part().unwrap();
    let unlocked = kem.unlock(pass.as_ref()).unwrap();
    let (key, public) = signer();
    let options = EncryptOptions {
        anonymous: true,
        ..HIDE
    };
    let p = Protection::Slots {
        passphrase: None,
        recipients: &[&recipient],
    };
    let enc = dir.path().join("a.pqkf");
    files::encrypt_stream_to(&mut &b"anonym"[..], &enc, &p, Some(&key), options).unwrap();
    assert_hidden(&enc, &key, Content::Stream);
    let header = files::inspect_v2(&enc).unwrap();
    assert_eq!(header.v4.unwrap().options & OPT_ANON, OPT_ANON);
    let report = opened(&enc, &Unlock::Key(&unlocked), Some(&public)).unwrap();
    assert_eq!(report.signer.unwrap().key_id, public.key_id());
}

#[test]
fn required_sender_is_checked_after_decrypting() {
    let dir = tempfile::tempdir().unwrap();
    let (key, public) = signer();
    let (_, other) = signer();
    let pass = common::random_passphrase();
    let p = Protection::Passphrase {
        passphrase: &pass,
        params: common::min_params(),
    };
    let unlock = Unlock::Passphrase(pass.as_ref());
    let src = dir.path().join("brief.txt");
    std::fs::write(&src, b"geheim").unwrap();
    for stream in [false, true] {
        let enc = dir.path().join("h.pqkf");
        let _ = std::fs::remove_file(&enc);
        if stream {
            files::encrypt_stream_to(&mut &b"geheim"[..], &enc, &p, Some(&key), HIDE).unwrap();
        } else {
            files::encrypt_with_options(&src, &enc, &p, Some(&key), HIDE).unwrap();
        }
        assert!(opened(&enc, &unlock, Some(&public)).is_ok());
        let err = opened(&enc, &unlock, Some(&other)).unwrap_err();
        assert_eq!(err, Error::InvalidSignature);
        assert!(files::check_with(&enc, &unlock, Some(&other)).is_err());
    }
    // DE: Unsigniert, aber Absender verlangt. EN: Unsigned, but sender required.
    let plain = dir.path().join("u.pqkf");
    files::encrypt_stream_to(&mut &b"x"[..], &plain, &p, None, EncryptOptions::default()).unwrap();
    assert_eq!(
        opened(&plain, &unlock, Some(&public)).unwrap_err(),
        Error::InvalidSignature
    );
}

#[test]
fn hide_sender_needs_a_signing_key() {
    let dir = tempfile::tempdir().unwrap();
    let pass = common::random_passphrase();
    let p = Protection::Passphrase {
        passphrase: &pass,
        params: common::min_params(),
    };
    let enc = dir.path().join("n.pqkf");
    let err = files::encrypt_stream_to(&mut &b"x"[..], &enc, &p, None, HIDE).unwrap_err();
    assert_eq!(
        err,
        Error::InvalidInput {
            field: "hide_sender"
        }
    );
    assert!(!enc.exists());
    let src = dir.path().join("brief.txt");
    std::fs::write(&src, b"x").unwrap();
    assert!(files::encrypt_with_options(&src, &enc, &p, None, HIDE).is_err());
    assert!(!enc.exists());
}

#[test]
fn toggling_hidden_or_signed_bits_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (key, _) = signer();
    let pass = common::random_passphrase();
    let p = Protection::Passphrase {
        passphrase: &pass,
        params: common::min_params(),
    };
    let unlock = Unlock::Passphrase(pass.as_ref());
    let enc = dir.path().join("h.pqkf");
    files::encrypt_stream_to(&mut &[4u8; 5000][..], &enc, &p, Some(&key), HIDE).unwrap();
    let good = std::fs::read(&enc).unwrap();
    // DE/EN: Optionsbits ab Byte 22 / option bits from byte 22
    for value in [0x00u8, 0x04, 0x0C, 0x09] {
        let mut bytes = good.clone();
        bytes[22] = value;
        let bad = dir.path().join("bad.pqkf");
        std::fs::write(&bad, &bytes).unwrap();
        assert!(opened(&bad, &unlock, None).is_err(), "{value:#x}");
        assert!(files::check(&bad, &unlock).is_err(), "{value:#x}");
    }
    // DE: Letztes Byte (Tag des letzten Blocks) kippen. EN: Flip the last byte (tag of last chunk).
    let bad = dir.path().join("bad.pqkf");
    std::fs::write(&bad, common::flip(&good, good.len() - 1)).unwrap();
    assert!(opened(&bad, &unlock, None).is_err());
}
