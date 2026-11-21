//! DE: RKEY-004–007/012: atomare Ausgabe, Sicherung, Pfade, Wiederherstellung.
//! EN: RKEY-004–007/012: atomic output, backup, paths and recovery.
// DE: Boolean-Vergleiche verhindern Secret-/Container-Dumps bei Fehlern.
// EN: Boolean comparisons avoid secret/container dumps on assertion failures.
#![allow(clippy::unwrap_used, clippy::manual_assert_eq)]

mod common;

use common::rekey::Fixture;
use pqkeep::Error;
use pqkeep::crypto::KeyAlgorithm;
use pqkeep::envelope::{self, Overwrite, RekeyFile, RekeyOptions};
use std::fs;

#[test]
fn rkey004_005_new_output_and_in_place_keep_exact_old_backup() {
    for v2 in [false, true] {
        for in_place in [false, true] {
            let f = Fixture::new(v2, KeyAlgorithm::Aes256);
            let before = fs::read(&f.source).unwrap();
            let loaded = RekeyFile::open(&f.source).unwrap();
            let options = f.options(in_place);
            loaded
                .write(&options, f.old.as_ref(), &f.new, f.factor.as_ref())
                .unwrap();
            assert!(fs::read(&f.backup).unwrap() == before);
            if !in_place {
                assert!(fs::read(&f.source).unwrap() == before);
            }
            f.assert_identity(&envelope::load(options.output).unwrap().0);
            let backup = envelope::load(&f.backup).unwrap().0;
            assert!(f.unlock(&backup, f.old.as_ref()).is_ok());
            assert!(matches!(
                f.unlock(&backup, f.new.as_ref()),
                Err(Error::Decrypt)
            ));
            // DE: Exakte Wiederherstellung in eigenem Temp-Verzeichnis. EN: Exact private restore.
            let restore = f.root.path().join("restored.json");
            fs::copy(&f.backup, &restore).unwrap();
            assert!(fs::read(&restore).unwrap() == before);
            assert!(
                f.unlock(&envelope::load(&restore).unwrap().0, f.old.as_ref())
                    .is_ok()
            );
        }
    }
}

#[test]
fn rkey004_005_existing_outputs_backups_and_unconfirmed_replace_fail() {
    let f = Fixture::new(false, KeyAlgorithm::Aes256);
    let loaded = RekeyFile::open(&f.source).unwrap();
    let before = fs::read(&f.source).unwrap();
    let mut options = RekeyOptions::new(&f.source);
    assert!(loaded.check(&options).is_err());
    options.overwrite = Overwrite::Yes;
    assert!(matches!(
        loaded.check(&options),
        Err(Error::InvalidInput {
            field: "rekey_backup"
        })
    ));
    options.backup = Some(&f.source);
    assert!(loaded.check(&options).is_err());
    fs::write(&f.output, b"foreign output").unwrap();
    options.output = &f.output;
    options.backup = Some(&f.backup);
    assert!(loaded.check(&options).is_err());
    assert!(fs::read(&f.output).unwrap() == b"foreign output");
    fs::write(&f.backup, b"foreign backup").unwrap();
    options.output = &f.source;
    assert!(loaded.check(&options).is_err());
    assert!(fs::read(&f.backup).unwrap() == b"foreign backup");
    assert!(fs::read(&f.source).unwrap() == before);
}

#[test]
fn rkey006_bad_credentials_write_nothing_and_stale_snapshot_is_rejected() {
    for v2 in [false, true] {
        let f = Fixture::new(v2, KeyAlgorithm::Aes256);
        let loaded = RekeyFile::open(&f.source).unwrap();
        let before = fs::read(&f.source).unwrap();
        let options = f.options(true);
        assert!(matches!(
            loaded.write(&options, f.new.as_ref(), &f.new, f.factor.as_ref()),
            Err(Error::Decrypt)
        ));
        assert!(!f.backup.exists());
        assert!(fs::read(&f.source).unwrap() == before);
        let changed = format!("{}\n", f.key.to_json().unwrap());
        fs::write(&f.source, changed.as_bytes()).unwrap();
        assert!(matches!(
            loaded.write(&options, f.old.as_ref(), &f.new, f.factor.as_ref()),
            Err(Error::InvalidInput {
                field: "rekey_changed"
            })
        ));
        assert!(!f.backup.exists());
        assert!(fs::read(&f.source).unwrap() == changed.as_bytes());
    }
}

#[test]
fn rkey007_size_type_and_truncation_limits() {
    let root = tempfile::tempdir().unwrap();
    assert!(RekeyFile::open(root.path()).is_err());
    let path = root.path().join("key.json");
    for data in [
        Vec::new(),
        b"{\"magic\":".to_vec(),
        vec![b' '; envelope::MAX_FILE_BYTES + 1],
        vec![0xff],
    ] {
        fs::write(&path, data).unwrap();
        assert!(RekeyFile::open(&path).is_err());
    }
}

#[cfg(unix)]
#[test]
fn rkey007_unix_links_rejected_and_published_files_are_private() {
    use std::os::unix::{fs::PermissionsExt, fs::symlink};
    let f = Fixture::new(false, KeyAlgorithm::Aes256);
    let alias = f.root.path().join("alias");
    symlink(&f.source, &alias).unwrap();
    assert!(RekeyFile::open(&alias).is_err());
    let loaded = RekeyFile::open(&f.source).unwrap();
    let mut options = RekeyOptions::new(&alias);
    assert!(loaded.check(&options).is_err());
    options = f.options(true);
    let hard = f.root.path().join("hard");
    fs::hard_link(&f.source, &hard).unwrap();
    assert!(loaded.check(&options).is_err());
    // DE: Neuausgabe erhält vorhandene Links; kein In-place-Austausch. EN: New output retains links.
    options = f.options(false);
    loaded
        .write(&options, f.old.as_ref(), &f.new, None)
        .unwrap();
    for path in [&f.output, &f.backup] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(fs::read(&hard).unwrap() == fs::read(&f.source).unwrap());
}
