//! DE: Ver- und Entschlüsseln mit mehreren Zugängen (C06, C08 aus `docs/V2_TESTS.md`). C06: v1
//! wird geschrieben, solange ein einzelner Zugang ohne Faktordatei genügt (D3), sonst v2; v1 und
//! v2 werden gelesen; die Faktordatei wird nie still ignoriert und fehlt sie, scheitert es vor der
//! Ableitung; falsche Geheimnisse scheitern einheitlich; Downgrade-Versuche und unbekannte
//! Versionen/Zugangstypen werden abgelehnt. C08: 1, 2 und 64 Empfänger gemischter KEM-Stufen –
//! jeder öffnet mit dem eigenen Schlüssel, ein fremder Schlüssel bekommt eine klare Meldung.
//! EN: Encrypting and decrypting with several slots (C06, C08 in `docs/V2_TESTS.md`). C06: v1 is
//! written while a single slot without factor file suffices (D3), else v2; v1 and v2 are read;
//! the factor file is never silently ignored and if it is missing this fails before deriving;
//! wrong secrets fail uniformly; downgrade attempts and unknown versions/slot types are
//! rejected. C08: 1, 2 and 64 recipients of mixed KEM levels – each opens with their own key, a
//! foreign key gets a clear message.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::v2_files::{self as v2, KEMS, Workspace};
use pqkeep::Error;
use pqkeep::crypto::factor::Factor;
use pqkeep::crypto::{DsaAlgorithm, KeyAlgorithm};
use pqkeep::envelope::PublicKeyFile;
use pqkeep::files::{self, PassphraseAccess, Protection, Slot, Unlock};
use pqkeep::security::StrongPassphrase;

fn bad(field: &'static str) -> Error {
    Error::InvalidInput { field }
}

fn access<'a>(
    passphrase: &'a StrongPassphrase,
    factor: Option<&'a Factor>,
) -> PassphraseAccess<'a> {
    PassphraseAccess {
        passphrase,
        params: common::min_params(),
        factor,
    }
}

/// DE: Verschlüsselt die Quelldatei und liefert die Bytes. EN: Encrypts the source, returns bytes.
fn encrypt(
    w: &Workspace,
    passphrase: Option<PassphraseAccess<'_>>,
    recipients: &[&PublicKeyFile],
) -> Result<Vec<u8>, Error> {
    let target = w.dir.path().join("ziel.pqkf");
    let protection = Protection::Slots {
        passphrase,
        recipients,
    };
    files::encrypt(&w.source, &target, &protection)?;
    let bytes = std::fs::read(&target).unwrap();
    std::fs::remove_file(&target).unwrap();
    Ok(bytes)
}

#[test]
fn c06_single_slot_without_factor_stays_v1() {
    let w = v2::workspace();
    let pass = common::random_passphrase();
    let by_passphrase = encrypt(&w, Some(access(&pass, None)), &[]).unwrap();
    assert_eq!(v2::version(&by_passphrase), 1);
    let unlock = Unlock::Passphrase(pass.as_ref());
    assert_eq!(v2::try_decrypt(&w.work, &by_passphrase, &unlock), Ok(()));

    let (public, unlocked) = v2::kem_key(KEMS[1]);
    let by_key = encrypt(&w, None, &[&public]).unwrap();
    assert_eq!(v2::version(&by_key), 1);
    let unlock = Unlock::Key(&unlocked);
    assert_eq!(v2::try_decrypt(&w.work, &by_key, &unlock), Ok(()));
}

#[test]
fn c06_factor_or_several_slots_write_v2() {
    let w = v2::workspace();
    let pass = common::random_passphrase();
    let factor = v2::factor();
    let with_factor = encrypt(&w, Some(access(&pass, Some(&factor))), &[]).unwrap();
    assert_eq!(v2::version(&with_factor), 2);
    let unlock = Unlock::PassphraseWithFactor {
        passphrase: pass.as_ref(),
        factor: &factor,
    };
    assert_eq!(v2::try_decrypt(&w.work, &with_factor, &unlock), Ok(()));

    // DE: C08 mit einem Empfänger: Passphrase und Schlüssel öffnen dieselbe Datei (D2).
    // EN: C08 with one recipient: passphrase and key open the same file (D2).
    let (public, unlocked) = v2::kem_key(KEMS[0]);
    let both = encrypt(&w, Some(access(&pass, None)), &[&public]).unwrap();
    assert_eq!(v2::version(&both), 2);
    let by_passphrase = Unlock::Passphrase(pass.as_ref());
    assert_eq!(v2::try_decrypt(&w.work, &both, &by_passphrase), Ok(()));
    let by_key = Unlock::Key(&unlocked);
    assert_eq!(v2::try_decrypt(&w.work, &both, &by_key), Ok(()));

    // DE: Zwei Dateien mit denselben Zugängen unterscheiden sich vollständig im Zufall.
    // EN: Two files with the same slots differ completely in their randomness.
    let again = encrypt(&w, Some(access(&pass, None)), &[&public]).unwrap();
    assert_ne!(both[15..22], again[15..22]);
    assert_ne!(both[both.len() - 32..], again[again.len() - 32..]);
}

#[test]
fn c06_factor_is_never_ignored_and_checked_before_deriving() {
    let w = v2::workspace();
    let pass = common::random_passphrase();
    let factor = v2::factor();
    let (public, unlocked) = v2::kem_key(KEMS[0]);
    let with_factor = Unlock::PassphraseWithFactor {
        passphrase: pass.as_ref(),
        factor: &factor,
    };

    let v1 = encrypt(&w, Some(access(&pass, None)), &[]).unwrap();
    let unused = Some(bad("factor_unused"));
    assert_eq!(v2::try_decrypt(&w.work, &v1, &with_factor).err(), unused);
    let v1_key = encrypt(&w, None, &[&public]).unwrap();
    assert_eq!(
        v2::try_decrypt(&w.work, &v1_key, &with_factor).err(),
        unused
    );
    let no_factor = encrypt(&w, Some(access(&pass, None)), &[&public]).unwrap();
    assert_eq!(v2::version(&no_factor), 2);
    assert_eq!(
        v2::try_decrypt(&w.work, &no_factor, &with_factor).err(),
        unused
    );

    // DE: Fehlt die Faktordatei, kommt die Meldung auch bei falscher Passphrase – also vor der
    //     Ableitung. EN: Without factor file the message appears even with a wrong passphrase.
    let needs_factor = encrypt(&w, Some(access(&pass, Some(&factor))), &[&public]).unwrap();
    let required = Some(bad("factor_required"));
    let wrong = common::passphrase("falsch / wrong");
    for candidate in [pass.as_ref(), &wrong] {
        let unlock = Unlock::Passphrase(candidate);
        assert_eq!(
            v2::try_decrypt(&w.work, &needs_factor, &unlock).err(),
            required
        );
    }
    // DE: Der Empfänger braucht die Faktordatei nicht. EN: The recipient needs no factor file.
    let by_key = Unlock::Key(&unlocked);
    assert_eq!(v2::try_decrypt(&w.work, &needs_factor, &by_key), Ok(()));
}

#[test]
fn c06_wrong_secrets_fail_uniformly() {
    let w = v2::workspace();
    let pass = common::random_passphrase();
    let factor = v2::factor();
    let other_factor = v2::factor();
    let wrong = common::passphrase("falsch / wrong");
    let (public, unlocked) = v2::kem_key(KEMS[2]);
    let file = encrypt(&w, Some(access(&pass, Some(&factor))), &[]).unwrap();
    for (passphrase, factor) in [(&wrong, &factor), (pass.as_ref(), &other_factor)] {
        let unlock = Unlock::PassphraseWithFactor { passphrase, factor };
        assert_eq!(
            v2::try_decrypt(&w.work, &file, &unlock).err(),
            Some(Error::Decrypt)
        );
    }
    // DE: Datei ohne den passenden Zugang: falsche Schlüsselart, vor jeder Ableitung.
    // EN: File without the matching slot: wrong key kind, before any derivation.
    let by_key = Unlock::Key(&unlocked);
    assert_eq!(
        v2::try_decrypt(&w.work, &file, &by_key).err(),
        Some(bad("key_kind"))
    );
    let (second, _) = v2::kem_key(KEMS[0]);
    let keys_only = encrypt(&w, None, &[&public, &second]).unwrap();
    let by_passphrase = Unlock::Passphrase(pass.as_ref());
    assert_eq!(
        v2::try_decrypt(&w.work, &keys_only, &by_passphrase).err(),
        Some(bad("key_kind"))
    );
}

#[test]
fn c06_downgrade_and_unknown_versions_are_rejected() {
    let w = v2::workspace();
    let pass = common::random_passphrase();
    let factor = v2::factor();
    let (public, unlocked) = v2::kem_key(KEMS[1]);
    let by_key = Unlock::Key(&unlocked);
    let v2_file = encrypt(&w, Some(access(&pass, Some(&factor))), &[&public]).unwrap();
    let v1_file = encrypt(&w, None, &[&public]).unwrap();
    assert_eq!((v2::version(&v2_file), v2::version(&v1_file)), (2, 1));

    // DE: Version umetikettieren öffnet nie. EN: Relabelling the version never opens.
    for (file, version) in [(&v2_file, 1u8), (&v1_file, 2)] {
        let mut relabelled = file.clone();
        relabelled[8] = version;
        assert!(v2::try_decrypt(&w.work, &relabelled, &by_key).is_err());
    }
    for version in [0u8, 3, 255] {
        let mut unknown = v2_file.clone();
        unknown[8] = version;
        let result = v2::try_decrypt(&w.work, &unknown, &by_key);
        assert_eq!(result.err(), Some(Error::Unsupported), "{version}");
    }
    // DE: Reservierte (TPM/FIDO2) und unbekannte Zugangstypen. EN: Reserved and unknown types.
    for slot_type in [3u8, 4, 9] {
        let mut reserved = v2_file.clone();
        reserved[23] = slot_type;
        let result = v2::try_decrypt(&w.work, &reserved, &by_key);
        assert_eq!(result.err(), Some(Error::Unsupported), "{slot_type}");
    }
}

#[test]
fn c08_two_and_64_recipients_of_mixed_levels() {
    let w = v2::workspace();
    // DE: 64 Schlüssel in 8 Threads erzeugen (je Schlüssel zweimal Argon2id).
    // EN: Create 64 keys in 8 threads (Argon2id twice per key).
    let keys: Vec<_> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|t| {
                scope.spawn(move || {
                    (0..8)
                        .map(|i| v2::kem_key(KEMS[(t * 8 + i) % 3]))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|w| w.join().unwrap())
            .collect()
    });
    let (_, outsider) = v2::kem_key(KEMS[1]);
    for count in [2, 64] {
        let recipients: Vec<&PublicKeyFile> = keys[..count].iter().map(|k| &k.0).collect();
        let file = encrypt(&w, None, &recipients).unwrap();
        assert_eq!(v2::version(&file), 2);

        // DE: Kanonisch: nach ID aufsteigend, jeder Empfänger genau einmal.
        // EN: Canonical: ascending by ID, every recipient exactly once.
        let header = pqkeep::files::HeaderV2::read(&mut &file[..]).unwrap();
        let ids: Vec<&[u8]> = header
            .slots
            .iter()
            .map(|slot| match slot {
                Slot::Recipient { recipient_id, .. } => &recipient_id[..],
                Slot::Passphrase { .. } => unreachable!("nur Empfänger / recipients only"),
            })
            .collect();
        assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
        let mut expected: Vec<&[u8]> = recipients.iter().map(|k| k.key_id()).collect();
        expected.sort_unstable();
        assert_eq!(ids, expected);

        for (_, unlocked) in &keys[..count] {
            let unlock = Unlock::Key(unlocked);
            assert_eq!(v2::try_decrypt(&w.work, &file, &unlock), Ok(()));
        }
        // DE: Eigener Schlüssel nicht dabei: klare Meldung. EN: Own key missing: clear message.
        let unlock = Unlock::Key(&outsider);
        assert_eq!(
            v2::try_decrypt(&w.work, &file, &unlock).err(),
            Some(bad("recipient"))
        );
    }
}

#[test]
fn c08_invalid_recipient_lists_are_rejected_without_output() {
    let w = v2::workspace();
    let (first, _) = v2::kem_key(KEMS[0]);
    let (second, _) = v2::kem_key(KEMS[2]);
    assert_eq!(encrypt(&w, None, &[]).err(), Some(bad("recipient")));
    assert_eq!(
        encrypt(&w, None, &[&first, &second, &first]).err(),
        Some(bad("duplicate"))
    );
    let too_many: Vec<&PublicKeyFile> = (0..65).map(|i| [&first, &second][i % 2]).collect();
    assert_eq!(encrypt(&w, None, &too_many).err(), Some(bad("recipient")));
    let (signer, _) = common::key_file(KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa65));
    let signer = signer.public_part().unwrap();
    assert_eq!(
        encrypt(&w, None, &[&first, &signer]).err(),
        Some(bad("recipient"))
    );
    assert_eq!(common::dir_names(w.dir.path()), ["arbeit", "quelle.txt"]);
}

#[test]
fn directory_and_several_sources_with_slots() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("baum");
    std::fs::create_dir(&tree).unwrap();
    common::write_sample_tree(&tree);
    let extra = dir.path().join("einzeln.txt");
    std::fs::write(&extra, b"einzeln / single").unwrap();
    let (first, unlocked) = v2::kem_key(KEMS[2]);
    let (second, _) = v2::kem_key(KEMS[0]);
    let protection = Protection::Slots {
        passphrase: None,
        recipients: &[&first, &second],
    };

    let target = dir.path().join("baum.pqkf");
    files::encrypt(&tree, &target, &protection).unwrap();
    assert_eq!(v2::version(&std::fs::read(&target).unwrap()), 2);
    let out = dir.path().join("zurück");
    files::decrypt(&target, &out, &Unlock::Key(&unlocked)).unwrap();
    assert_eq!(common::read_tree(&out), common::read_tree(&tree));

    let many = dir.path().join("mehrere.pqkf");
    files::encrypt_many(&[&tree, &extra], &many, &protection).unwrap();
    let out = dir.path().join("mehrere");
    let report = files::decrypt(&many, &out, &Unlock::Key(&unlocked)).unwrap();
    assert_eq!(report.files, 6);
    assert_eq!(
        std::fs::read(out.join("einzeln.txt")).unwrap(),
        b"einzeln / single"
    );
    assert_eq!(
        common::read_tree(&out.join("baum")),
        common::read_tree(&tree)
    );
}
