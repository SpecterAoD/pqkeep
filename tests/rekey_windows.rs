//! DE: RKEY-013: native Windows-Handles, keine Antivirus-/ACL-Garantie.
//! EN: RKEY-013: native Windows handles, no antivirus/ACL guarantee.
#![cfg(windows)]
#![allow(clippy::unwrap_used)]
mod common;
use common::rekey::Fixture;
use pqkeep::crypto::KeyAlgorithm;
use pqkeep::envelope::{self, RekeyFile};
use std::fs::{self, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;

#[test]
fn rkey013_exclusive_source_lock_fails_without_output_and_retry_works() {
    let f = Fixture::new(false, KeyAlgorithm::Aes256);
    let before = fs::read(&f.source).unwrap();
    let lock = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&f.source)
        .unwrap();
    assert!(RekeyFile::open(&f.source).is_err());
    assert!(!f.output.exists() && !f.backup.exists());
    drop(lock);
    assert!(
        fs::read(&f.source).unwrap() == before,
        "Source changed / Quelle verändert"
    );
    RekeyFile::open(&f.source)
        .unwrap()
        .write(&f.options(false), f.old.as_ref(), &f.new, None)
        .unwrap();
    f.assert_identity(&envelope::load(&f.output).unwrap().0);
}

#[test]
fn rkey013_delete_sharing_lock_keeps_old_source_and_committed_backup() {
    let f = Fixture::new(true, KeyAlgorithm::Aes256);
    let before = fs::read(&f.source).unwrap();
    let loaded = RekeyFile::open(&f.source).unwrap();
    // DE: Lesen/Schreiben teilen, Löschen/Ersetzen verbieten. EN: Share reads/writes, deny deletion.
    let lock = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(&f.source)
        .unwrap();
    let result = loaded.write(&f.options(true), f.old.as_ref(), &f.new, f.factor.as_ref());
    assert!(result.is_err());
    drop(lock);
    assert!(
        fs::read(&f.source).unwrap() == before,
        "Old source changed / Alte Quelle verändert"
    );
    assert!(
        fs::read(&f.backup).unwrap() == before,
        "Backup changed / Sicherung verändert"
    );
    assert!(
        f.unlock(&envelope::load(&f.source).unwrap().0, f.old.as_ref())
            .is_ok()
    );
    let fresh_backup = f.root.path().join("second-backup.json");
    let mut options = f.options(true);
    options.backup = Some(&fresh_backup);
    loaded
        .write(&options, f.old.as_ref(), &f.new, f.factor.as_ref())
        .unwrap();
    f.assert_identity(&envelope::load(&f.source).unwrap().0);
    assert!(
        fs::read(&f.backup).unwrap() == before,
        "First backup changed / Erste Sicherung verändert"
    );
}
