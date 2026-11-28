//! DE: Datei-Races (#338, PR 1): deterministische Tests über Test-Haltepunkte (nur `cfg(test)`):
//! ein konkurrierender Prozess legt das Ziel zwischen Prüfung und Veröffentlichung an oder tauscht
//! die Quelle zwischen Durchlauf und Öffnen gegen einen Symlink. Was heute schon hält, ist scharf;
//! bekannte Lücken sind mit `#[ignore]` markiert und werden mit PR 2 (Veröffentlichung) bzw. PR 4
//! (Quellen) scharf geschaltet – `cargo test -- --ignored` zeigt den heutigen Stand.
//! EN: File races (#338, PR 1): deterministic tests via test checkpoints (`cfg(test)` only): a
//! concurrent process creates the target between check and publication or swaps the source for a
//! symlink between walk and open. What already holds is enforced; known gaps are marked
//! `#[ignore]` and get enforced with PR 2 (publication) or PR 4 (sources) – `cargo test --
//! --ignored` shows today's state.
#![allow(clippy::unwrap_used)]

use std::io::ErrorKind;
use std::path::Path;

use crate::crypto::kdf;
use crate::fault_fixture_tests::{assert_no_temps, plan};
use crate::fault_io_tests::{Action, Failure, Point, Scope};
use crate::files::{self, Protection, Unlock};
use crate::security::{StrongPassphrase, generator};
use crate::{Error, Result};

const FOREIGN: &[u8] = b"fremd / foreign";
#[cfg(unix)]
const SECRET: &[u8] = b"geheim, nie verschluesseln / secret, never encrypt";

fn pass() -> StrongPassphrase {
    generator::generate(&generator::Options::default()).unwrap()
}

fn encrypt(source: &Path, target: &Path, pass: &StrongPassphrase) -> Result<files::Report> {
    let params = kdf::KdfParams {
        memory_kib: kdf::MIN_MEMORY_KIB,
        iterations: kdf::MIN_ITERATIONS,
        parallelism: 1,
    };
    let p = Protection::Passphrase {
        passphrase: pass,
        params,
    };
    files::encrypt(source, target, &p)
}

/// DE: Konkurrierender Prozess: legt `out` (Datei) neben der Temporärausgabe an.
/// EN: Concurrent process: creates `out` (file) next to the temporary output.
fn create_foreign_file(temp: &Path) {
    std::fs::write(temp.parent().unwrap().join("out"), FOREIGN).unwrap();
}

/// DE: Konkurrierender Prozess: legt `out` als leeren Ordner an. EN: Creates `out` as empty dir.
#[cfg(unix)]
fn create_foreign_dir(temp: &Path) {
    std::fs::create_dir(temp.parent().unwrap().join("out")).unwrap();
}

/// DE: Konkurrierender Prozess: tauscht `src/a` gegen einen Symlink auf `geheim`.
/// EN: Concurrent process: swaps `src/a` for a symlink to `geheim`.
#[cfg(unix)]
fn swap_source_for_symlink(temp: &Path) {
    let root = temp.parent().unwrap();
    std::fs::remove_file(root.join("src/a")).unwrap();
    std::os::unix::fs::symlink(root.join("geheim"), root.join("src/a")).unwrap();
}

/// DE: Verschlüsselte Datei `archive.pqkf` aus einer Datei bzw. einem Ordner in `root`.
/// EN: Encrypted `archive.pqkf` from a file or a directory in `root`.
fn sealed(root: &Path, tree: bool, pass: &StrongPassphrase) -> std::path::PathBuf {
    let src = root.join("src");
    if tree {
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("a"), b"inhalt / content").unwrap();
    } else {
        std::fs::write(&src, b"inhalt / content").unwrap();
    }
    let archive = root.join("archive.pqkf");
    encrypt(&src, &archive, pass).unwrap();
    archive
}

#[test]
fn file_target_created_before_publish_is_never_overwritten() {
    let root = tempfile::tempdir().unwrap();
    let pass = pass();
    let archive = sealed(root.path(), false, &pass);
    let out = root.path().join("out");
    let scope = Scope::new(
        root.path(),
        plan(Point::BeforePublish, Action::Run(create_foreign_file)),
    );
    let result = files::decrypt(&archive, &out, &Unlock::Passphrase(pass.as_ref()));
    scope.finish();
    assert_eq!(result, Err(Error::Io(ErrorKind::AlreadyExists)));
    assert_eq!(std::fs::read(&out).unwrap(), FOREIGN);
    assert_no_temps(root.path());
}

#[test]
#[ignore = "bekannte Lücke / known gap #338 PR 2: Rückfall ohne Hardlinks ersetzt / fallback replaces"]
fn fallback_without_hard_links_never_overwrites() {
    let root = tempfile::tempdir().unwrap();
    let pass = pass();
    let archive = sealed(root.path(), false, &pass);
    let out = root.path().join("out");
    let plans = vec![
        plan(
            Point::BeforeHardLink,
            Action::Fail(Failure::Kind(ErrorKind::Unsupported)),
        ),
        plan(Point::BeforeRename, Action::Run(create_foreign_file)),
    ];
    let scope = Scope::sequence(root.path(), plans);
    let result = files::decrypt(&archive, &out, &Unlock::Passphrase(pass.as_ref()));
    scope.finish();
    assert_eq!(result, Err(Error::Io(ErrorKind::AlreadyExists)));
    assert_eq!(std::fs::read(&out).unwrap(), FOREIGN);
}

#[test]
#[cfg(unix)]
#[ignore = "bekannte Lücke / known gap #338 PR 2: Ordner per Prüfen + Umbenennen / check + rename"]
fn directory_target_created_before_rename_is_not_replaced() {
    let root = tempfile::tempdir().unwrap();
    let pass = pass();
    let archive = sealed(root.path(), true, &pass);
    let out = root.path().join("out");
    let scope = Scope::new(
        root.path(),
        plan(Point::BeforeRename, Action::Run(create_foreign_dir)),
    );
    let result = files::decrypt(&archive, &out, &Unlock::Passphrase(pass.as_ref()));
    scope.finish();
    assert_eq!(result, Err(Error::Io(ErrorKind::AlreadyExists)));
    assert!(
        std::fs::read_dir(&out).unwrap().next().is_none(),
        "fremder Ordner ersetzt / replaced"
    );
}

#[test]
#[cfg(unix)]
#[ignore = "bekannte Lücke / known gap #338 PR 4: Quelle folgt Symlink nach dem Durchlauf / follows"]
fn source_swapped_for_symlink_is_never_read() {
    let root = tempfile::tempdir().unwrap();
    let pass = pass();
    std::fs::write(root.path().join("geheim"), SECRET).unwrap();
    let src = root.path().join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("a"), vec![b'x'; SECRET.len()]).unwrap();
    let archive = root.path().join("archive.pqkf");
    let run = Action::Run(swap_source_for_symlink);
    let scope = Scope::new(root.path(), plan(Point::AfterTempCreate, run));
    let result = encrypt(&src, &archive, &pass);
    scope.finish();
    let leaked = result.is_ok() && {
        let out = root.path().join("check");
        files::decrypt(&archive, &out, &Unlock::Passphrase(pass.as_ref())).unwrap();
        std::fs::read(out.join("a")).unwrap() == SECRET
    };
    assert!(
        !leaked,
        "Ziel des Symlinks verschlüsselt / symlink target encrypted"
    );
    assert!(result.is_err() && !archive.exists());
}
