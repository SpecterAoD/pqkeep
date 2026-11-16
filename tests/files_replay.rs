//! DE: Replay-Grenze: gültige alte Container bleiben lesbar; kein Frischezustand im Format.
//! EN: Replay boundary: old valid containers remain readable; the format has no freshness state.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::v2_files::{self as v2, CONTENT};
use pqkeep::crypto::{KemAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{self, KeyFile, Overwrite};
use pqkeep::files::{self, Protection, Unlock};

// DE: Nur erzeugte Testdateien; Inhalte nie in Assertions ausgeben.
// EN: Generated test files only; never print their contents in assertions.
fn snapshot(paths: &[PathBuf]) -> Vec<Vec<u8>> {
    paths.iter().map(|p| std::fs::read(p).unwrap()).collect()
}

fn unchanged(paths: &[PathBuf], before: &[Vec<u8>]) {
    let same = snapshot(paths) == before;
    assert!(same, "Testdateien verändert / test files changed");
}

fn save_key(file: &KeyFile, dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    envelope::save(file, &path, Overwrite::No).unwrap();
    path
}

#[test]
fn v1_valid_container_can_be_replayed_to_distinct_targets() {
    let w = v2::workspace();
    let (file, pass) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    let key_path = save_key(&file, w.dir.path(), "recipient.key.json");
    let key = file.unlock(pass.as_ref()).unwrap();
    let public = file.public_part().unwrap();
    let container = w.work.join("old.pqkf");
    files::encrypt(&w.source, &container, &Protection::Recipient(&public)).unwrap();
    let paths = [key_path, container.clone(), w.source.clone()];
    let before = snapshot(&paths);
    assert_eq!(v2::version(&before[1]), 1);
    for name in ["first.txt", "replayed.txt"] {
        let target = w.work.join(name);
        files::decrypt(&container, &target, &Unlock::Key(&key)).unwrap();
        assert_eq!(std::fs::read(target).unwrap(), CONTENT);
    }
    unchanged(&paths, &before);
}

#[test]
fn v2_old_copy_remains_readable_after_newer_container() {
    let w = v2::workspace();
    let (first, pass) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    let (second, _) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem512));
    let first_path = save_key(&first, w.dir.path(), "first.key.json");
    let second_path = save_key(&second, w.dir.path(), "second.key.json");
    let key = first.unlock(pass.as_ref()).unwrap();
    let public = [first.public_part().unwrap(), second.public_part().unwrap()];
    let recipients = [&public[0], &public[1]];
    let protection = Protection::Slots {
        passphrase: None,
        recipients: &recipients,
    };
    let old = w.work.join("old.pqkf");
    files::encrypt(&w.source, &old, &protection).unwrap();
    let protected = [first_path, second_path, old.clone()];
    let original = snapshot(&protected);
    let newer = w.work.join("newer.pqkf");
    let new_source = w.dir.path().join("newer.txt");
    std::fs::write(&new_source, b"new revision / neue Fassung").unwrap();
    files::encrypt(&new_source, &newer, &protection).unwrap();
    unchanged(&protected, &original);
    let paths = [
        protected.to_vec(),
        vec![newer.clone(), w.source.clone(), new_source],
    ]
    .concat();
    let before = snapshot(&paths);
    assert_eq!(v2::version(&before[2]), 2);
    assert_eq!(v2::version(&before[3]), 2);
    let target = w.work.join("replayed.txt");
    files::decrypt(&old, &target, &Unlock::Key(&key)).unwrap();
    assert_eq!(std::fs::read(target).unwrap(), CONTENT);
    unchanged(&paths, &before);
}
