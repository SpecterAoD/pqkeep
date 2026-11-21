//! DE: RKEY-012: vorhandene v1/v2-Archive und Signaturen nach Rekey/Restore nutzbar.
//! EN: RKEY-012: existing v1/v2 archives and signatures usable after rekey/restore.
#![allow(clippy::unwrap_used)]
mod common;
use common::rekey::Fixture;
use pqkeep::crypto::{DsaAlgorithm, KemAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{self, KeyFile, RekeyFile};
use pqkeep::{files, sign};

fn replace(f: &Fixture) -> (KeyFile, KeyFile) {
    RekeyFile::open(&f.source)
        .unwrap()
        .write(&f.options(true), f.old.as_ref(), &f.new, f.factor.as_ref())
        .unwrap();
    let changed = envelope::load(&f.source).unwrap().0;
    let backup = envelope::load(&f.backup).unwrap().0;
    f.assert_identity(&changed);
    (changed, backup)
}

#[test]
fn rkey012_old_recipient_archives_both_versions_open_after_rekey_and_restore() {
    for v2 in [false, true] {
        let f = Fixture::new(v2, KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
        let public = f.key.public_part().unwrap();
        let source = f.root.path().join("plain");
        std::fs::write(&source, common::random_secret()).unwrap();
        let archives = [f.root.path().join("v1.pqkf"), f.root.path().join("v2.pqkf")];
        files::encrypt(
            &source,
            &archives[0],
            &files::Protection::Recipient(&public),
        )
        .unwrap();
        files::encrypt(
            &source,
            &archives[1],
            &files::Protection::Slots {
                passphrase: Some(files::PassphraseAccess {
                    passphrase: &f.old,
                    params: common::min_params(),
                    factor: f.factor.as_ref(),
                }),
                recipients: &[&public],
            },
        )
        .unwrap();
        let snapshots: Vec<_> = archives.iter().map(|p| std::fs::read(p).unwrap()).collect();
        let (changed, backup) = replace(&f);
        for (i, (key, pass)) in [(&changed, f.new.as_ref()), (&backup, f.old.as_ref())]
            .into_iter()
            .enumerate()
        {
            let opened = f.unlock(key, pass).unwrap();
            for (j, archive) in archives.iter().enumerate() {
                files::check(archive, &files::Unlock::Key(&opened)).unwrap();
                let out = f.root.path().join(format!("out-{i}-{j}"));
                files::decrypt(archive, &out, &files::Unlock::Key(&opened)).unwrap();
                assert!(
                    std::fs::read(&out).unwrap() == std::fs::read(&source).unwrap(),
                    "Plaintext changed / Klartext verändert"
                );
                assert!(
                    std::fs::read(archive).unwrap() == snapshots[j],
                    "Archive changed / Archiv verändert"
                );
            }
        }
    }
}

#[test]
fn rkey012_existing_and_new_signatures_verify_with_unchanged_public_key() {
    for v2 in [false, true] {
        let f = Fixture::new(v2, KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87));
        let public = f.key.public_part().unwrap();
        let data = zeroize::Zeroizing::new(common::random_secret());
        let old = f.unlock(&f.key, f.old.as_ref()).unwrap();
        let signature = sign::sign_reader(&old, &data[..]).unwrap();
        let (changed, backup) = replace(&f);
        sign::verify_reader(&public, &signature, &data[..]).unwrap();
        for (key, pass) in [(&changed, f.new.as_ref()), (&backup, f.old.as_ref())] {
            let opened = f.unlock(key, pass).unwrap();
            let sig = sign::sign_reader(&opened, &data[..]).unwrap();
            sign::verify_reader(&public, &sig, &data[..]).unwrap();
            assert!(
                key.public_part().unwrap() == public,
                "Public key changed / Öffentlicher Schlüssel verändert"
            );
        }
    }
}
