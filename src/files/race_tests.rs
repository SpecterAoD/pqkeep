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

/// DE: Angreifer im Zielordner: benennt den Temporärordner um und setzt einen Symlink auf
/// `woanders` (GHSA-9vh5-2vch-2r68, Fall 1). EN: Attacker in the target directory: renames the
/// temporary directory and puts a symlink to `woanders` (case 1).
#[cfg(unix)]
fn swap_temp_dir_for_symlink(temp: &Path) {
    let root = temp.parent().unwrap();
    std::fs::rename(temp, root.join("weg")).unwrap();
    std::os::unix::fs::symlink(root.join("woanders"), temp).unwrap();
}

/// DE: Angreifer ersetzt die Temporärdatei vor dem Veröffentlichen durch einen Symlink auf eigene
/// Daten (Fall 2). EN: Attacker replaces the temporary file with a symlink to own data (case 2).
#[cfg(unix)]
fn swap_temp_file_for_symlink(temp: &Path) {
    let root = temp.parent().unwrap();
    std::fs::rename(temp, root.join("weg")).unwrap();
    std::fs::write(root.join("fake"), FOREIGN).unwrap();
    std::os::unix::fs::symlink(root.join("fake"), temp).unwrap();
}

/// DE: Wie Fall 2, aber mit einer gewöhnlichen fremden Datei. EN: Like case 2 with a plain file.
fn swap_temp_file_for_file(temp: &Path) {
    let root = temp.parent().unwrap();
    std::fs::rename(temp, root.join("weg")).unwrap();
    std::fs::write(temp, FOREIGN).unwrap();
}

#[test]
#[cfg(target_os = "linux")]
fn swapped_temp_dir_cannot_redirect_writes() {
    let root = tempfile::tempdir().unwrap();
    let pass = pass();
    let archive = sealed(root.path(), true, &pass);
    std::fs::create_dir(root.path().join("woanders")).unwrap();
    let out = root.path().join("out");
    let run = Action::Run(swap_temp_dir_for_symlink);
    let scope = Scope::new(root.path(), plan(Point::AfterTempCreate, run));
    let result = files::decrypt(&archive, &out, &Unlock::Passphrase(pass.as_ref()));
    scope.finish();
    assert!(result.is_err(), "{result:?}");
    let leaked = std::fs::read_dir(root.path().join("woanders"))
        .unwrap()
        .count();
    assert_eq!(
        leaked, 0,
        "Klartext außerhalb des Ziels / plaintext outside the target"
    );
    assert!(std::fs::symlink_metadata(&out).is_err(), "Ziel / target");
    // DE: Der umbenannte eigene Ordner wurde über das Handle geleert. EN: Emptied via the handle.
    assert_eq!(
        std::fs::read_dir(root.path().join("weg")).unwrap().count(),
        0
    );
}

#[test]
#[cfg(unix)]
fn swapped_temp_file_is_never_published() {
    for swap in [
        swap_temp_file_for_symlink as fn(&Path),
        swap_temp_file_for_file,
    ] {
        let root = tempfile::tempdir().unwrap();
        let pass = pass();
        let archive = sealed(root.path(), false, &pass);
        let out = root.path().join("out");
        let scope = Scope::new(root.path(), plan(Point::BeforePublish, Action::Run(swap)));
        let result = files::decrypt(&archive, &out, &Unlock::Passphrase(pass.as_ref()));
        scope.finish();
        // DE: Linux veröffentlicht über den Deskriptor (eigener Inhalt), sonst Fehler – nie fremd.
        // EN: Linux publishes via the descriptor (own content), else an error – never foreign.
        match result {
            Ok(_) => assert_eq!(std::fs::read(&out).unwrap(), b"inhalt / content"),
            Err(_) => assert!(std::fs::symlink_metadata(&out).is_err()),
        }
        let link = std::fs::symlink_metadata(&out).is_ok_and(|m| m.file_type().is_symlink());
        assert!(!link, "Ziel ist ein Symlink / target is a symlink");
    }
}
