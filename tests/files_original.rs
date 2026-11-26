//! DE: Zufällige äußere Namen und Wiederherstellung des Originalnamens (#315): Datei, Ordner,
//! Container, Signatur, Konflikte und bösartige Archivnamen (korrekt verschlüsselt).
//! EN: Random outer names and restoring the original name (#315): file, directory, container,
//! signature, conflicts and malicious archive names (correctly encrypted).

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use common::archive::{build, dir_entry, end, file_entry, key};
use pqkeep::Error;
use pqkeep::files::{self, Content, Protection, Unlock};
use pqkeep::security::StrongPassphrase;

/// DE: Ziel unverändert übernehmen. EN: Take the target unchanged.
#[allow(clippy::unnecessary_wraps)]
fn same(p: &Path) -> Option<PathBuf> {
    Some(p.to_path_buf())
}

fn protection(pass: &StrongPassphrase) -> Protection<'_> {
    Protection::Passphrase {
        passphrase: pass,
        params: common::min_params(),
    }
}

#[test]
fn file_name_restored_from_archive() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("steuer-2026.pdf");
    std::fs::write(&src, b"geheim").unwrap();
    let pass = common::random_passphrase();
    let enc = files::random_target(dir.path()).unwrap();
    files::encrypt(&src, &enc, &protection(&pass)).unwrap();
    assert!(files::is_random_name(
        enc.file_name().unwrap().to_str().unwrap()
    ));
    let out = dir.path().join("zurück");
    std::fs::create_dir(&out).unwrap();
    let unlock = Unlock::Passphrase(pass.as_ref());
    let (target, report) = files::decrypt_original(&enc, &out, &unlock, None, &same).unwrap();
    assert_eq!(target, out.join("steuer-2026.pdf"));
    assert_eq!(std::fs::read(&target).unwrap(), b"geheim");
    assert_eq!(report.files, 1);
    // DE: Zweites Mal: Ziel existiert, nichts überschrieben, keine Reste.
    // EN: Second time: target exists, nothing overwritten, no leftovers.
    let again = files::decrypt_original(&enc, &out, &unlock, None, &same);
    assert!(matches!(again, Err(Error::Io(ErrorKind::AlreadyExists))));
    assert_eq!(common::dir_names(&out), vec!["steuer-2026.pdf"]);
    // DE: Mit Namenswahl (wie `--rename`). EN: With name choice (like `--rename`).
    let renamed = |p: &Path| Some(p.with_file_name("steuer-2026 (2).pdf"));
    let (second, _) = files::decrypt_original(&enc, &out, &unlock, None, &renamed).unwrap();
    assert_eq!(std::fs::read(second).unwrap(), b"geheim");
    let none = |_: &Path| None;
    let refused = files::decrypt_original(&enc, &out, &unlock, None, &none);
    assert!(matches!(refused, Err(Error::Io(ErrorKind::AlreadyExists))));
}

#[test]
fn directory_and_container_restored() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("Urlaub 2026");
    std::fs::create_dir(&tree).unwrap();
    common::write_sample_tree(&tree);
    let pass = common::random_passphrase();
    let unlock = Unlock::Passphrase(pass.as_ref());
    let out = dir.path().join("zurück");
    std::fs::create_dir(&out).unwrap();
    // DE: Ein Ordner: oberster Eintrag = Ordnername. EN: One directory: top entry = its name.
    let enc = files::random_target(dir.path()).unwrap();
    files::encrypt_many(&[tree.as_path()], &enc, &protection(&pass)).unwrap();
    let (target, _) = files::decrypt_original(&enc, &out, &unlock, None, &same).unwrap();
    assert_eq!(target, out.join("Urlaub 2026"));
    assert_eq!(common::read_tree(&target), common::read_tree(&tree));
    // DE: Container: Name bleibt im Archiv. EN: Container: name kept in the archive.
    let note = dir.path().join("notiz.txt");
    std::fs::write(&note, b"n").unwrap();
    let enc2 = files::random_target(dir.path()).unwrap();
    let list = [tree.as_path(), note.as_path()];
    files::encrypt_many_under(&list, "Auswahl", &enc2, &protection(&pass), None).unwrap();
    let (target, report) = files::decrypt_original(&enc2, &out, &unlock, None, &same).unwrap();
    assert_eq!(target, out.join("Auswahl"));
    assert_eq!(std::fs::read(target.join("notiz.txt")).unwrap(), b"n");
    assert_eq!(report.files, 6);
    assert_eq!(common::dir_names(&out), vec!["Auswahl", "Urlaub 2026"]);
    // DE: Ungültiger Containername. EN: Invalid container name.
    for bad in ["a/b", "..", "CON", ""] {
        let r = files::encrypt_many_under(&list, bad, &enc2, &protection(&pass), None);
        assert!(r.is_err(), "{bad}");
    }
}

#[test]
fn plain_directory_archive_has_no_single_name() {
    // DE: Normal verschlüsselter Ordner (ohne obersten Eintrag) → klare Meldung, keine Reste.
    // EN: Normally encrypted directory (no top entry) → clear error, no leftovers.
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("baum");
    std::fs::create_dir(&tree).unwrap();
    common::write_sample_tree(&tree);
    let pass = common::random_passphrase();
    let enc = dir.path().join("baum.pqkf");
    files::encrypt(&tree, &enc, &protection(&pass)).unwrap();
    let out = dir.path().join("zurück");
    std::fs::create_dir(&out).unwrap();
    let r = files::decrypt_original(&enc, &out, &Unlock::Passphrase(pass.as_ref()), None, &same);
    assert!(matches!(
        r,
        Err(Error::InvalidInput {
            field: "original_name"
        })
    ));
    assert_eq!(common::dir_names(&out), Vec::<String>::new());
}

/// DE: Korrekt verschlüsselte, aber für Originalnamen unbrauchbare Archive.
/// EN: Correctly encrypted archives that are unusable for original names.
fn malicious_cases() -> Vec<(Content, Vec<u8>)> {
    vec![
        (
            Content::File,
            [file_entry("a/b.txt", b"x", true), end(1)].concat(),
        ),
        (
            Content::File,
            [file_entry("../x", b"x", true), end(1)].concat(),
        ),
        (
            Content::File,
            [file_entry("CON", b"x", true), end(1)].concat(),
        ),
        (
            Content::File,
            [file_entry("a\nb", b"x", true), end(1)].concat(),
        ),
        (
            Content::Directory,
            [file_entry("x.txt", b"x", true), end(1)].concat(),
        ),
        (
            Content::Directory,
            [dir_entry("a"), dir_entry("b"), end(2)].concat(),
        ),
        (
            Content::Directory,
            [dir_entry("a"), file_entry("ab/x", b"x", true), end(2)].concat(),
        ),
        (
            Content::Directory,
            [dir_entry("a"), file_entry("a/../x", b"x", true), end(2)].concat(),
        ),
        (Content::Directory, end(0)),
    ]
}

#[test]
fn malicious_archive_names_rejected() {
    let key = key();
    let unlock = Unlock::Key(&key.unlocked);
    let cases = malicious_cases();
    for (i, (content, plain)) in cases.iter().enumerate() {
        let dir = tempfile::tempdir().unwrap();
        let enc = dir.path().join("abcdefghijklmnopqrstuvwxyz.pqkf");
        build(&key, *content, plain, &enc);
        let out = dir.path().join("ziel");
        std::fs::create_dir(&out).unwrap();
        let r = files::decrypt_original(&enc, &out, &unlock, None, &same);
        assert!(r.is_err(), "Fall / case {i}");
        assert_eq!(common::dir_names(&out), Vec::<String>::new(), "{i}");
        assert_eq!(
            common::dir_names(dir.path()),
            vec!["abcdefghijklmnopqrstuvwxyz.pqkf", "ziel"],
            "außerhalb / outside {i}"
        );
    }
}
