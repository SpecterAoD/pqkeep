//! DE: FS-009: native Windows-Sharing-Locks, keine Antivirus-Simulation.
//! EN: FS-009: native Windows sharing locks, not antivirus simulation.
#![cfg(windows)]
#![allow(clippy::unwrap_used)]

mod common;

use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;

use pqkeep::Error;
use pqkeep::crypto::{KeyAlgorithm, factor::Factor};
use pqkeep::envelope::{self, Overwrite};
use pqkeep::files::{self, Protection, Unlock};

fn lock(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(path)
        .unwrap()
}

// DE: ERROR_SHARING_VIOLATION (32); ErrorKind-Zuordnung hängt von Rust ab.
// EN: ERROR_SHARING_VIOLATION (32); ErrorKind mapping depends on Rust.
fn sharing_error(path: &Path) -> ErrorKind {
    let error = File::open(path).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(32));
    error.kind()
}

#[test]
fn fs009_locked_key_replace_preserves_original_and_retry_succeeds() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("key.json");
    let (old, _) = common::key_file(KeyAlgorithm::Aes256);
    let (new, pass) = common::key_file(KeyAlgorithm::Aes256);
    envelope::save(&old, &target, Overwrite::No).unwrap();
    let before = std::fs::read(&target).unwrap();
    let locked = lock(&target);
    assert_eq!(
        envelope::save(&new, &target, Overwrite::Yes),
        Err(Error::Io(ErrorKind::PermissionDenied))
    );
    drop(locked);
    assert!(
        std::fs::read(&target).unwrap() == before,
        "Key changed / Schlüssel verändert"
    );
    assert!(
        envelope::load(&target).unwrap().0 == old,
        "Key changed / Schlüssel verändert"
    );
    envelope::save(&new, &target, Overwrite::Yes).unwrap();
    assert!(
        envelope::load(&target)
            .unwrap()
            .0
            .unlock(pass.as_ref())
            .is_ok()
    );
    assert_no_temps(root.path());
}

#[test]
fn fs009_locked_archive_does_not_publish_plaintext_and_retry_succeeds() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    let archive = root.path().join("archive.pqkf");
    let target = root.path().join("out");
    let pass = common::random_passphrase();
    std::fs::write(&source, b"synthetic / synthetisch").unwrap();
    files::encrypt(
        &source,
        &archive,
        &Protection::Passphrase {
            passphrase: &pass,
            params: common::min_params(),
        },
    )
    .unwrap();
    let before = std::fs::read(&archive).unwrap();
    let locked = lock(&archive);
    let expected = sharing_error(&archive);
    assert_eq!(
        files::decrypt(&archive, &target, &Unlock::Passphrase(pass.as_ref())),
        Err(Error::Io(expected))
    );
    assert!(!target.exists());
    drop(locked);
    assert!(
        std::fs::read(&archive).unwrap() == before,
        "Archive changed / Archiv verändert"
    );
    files::decrypt(&archive, &target, &Unlock::Passphrase(pass.as_ref())).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"synthetic / synthetisch");
    assert_no_temps(root.path());
}

#[test]
fn fs009_locked_factor_read_fails_then_reopens_without_replacement() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("factor");
    Factor::create(&target).unwrap();
    let before = zeroize::Zeroizing::new(std::fs::read(&target).unwrap());
    let locked = lock(&target);
    let expected = sharing_error(&target);
    assert!(matches!(Factor::read(&target), Err(Error::Io(kind)) if kind == expected));
    assert_eq!(
        Factor::create(&target),
        Err(Error::Io(ErrorKind::AlreadyExists))
    );
    drop(locked);
    assert!(Factor::read(&target).is_ok());
    assert!(
        zeroize::Zeroizing::new(std::fs::read(&target).unwrap()) == before,
        "Factor changed / Faktor verändert"
    );
    assert_no_temps(root.path());
}

fn assert_no_temps(root: &Path) {
    assert!(
        std::fs::read_dir(root).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp-"))
    );
}
