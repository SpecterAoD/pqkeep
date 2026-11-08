//! DE: Mehrere Quellen als ein Container (`files::encrypt_many`, Mehrfachauswahl): Rundlauf in
//! beiden Modi, Inhalt „Ordner“, gleiche Namen, ausgewählte Verknüpfungen, fehlende Quellen.
//! EN: Several sources as one container (`files::encrypt_many`, multi-selection): round trip in
//! both modes, content "directory", equal names, selected symlinks, missing sources.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use pqkeep::Error;
use pqkeep::crypto::{KemAlgorithm, KeyAlgorithm};
use pqkeep::files::{self, Content, Protection, Unlock};

/// DE: Zwei Dateien und ein Ordner im Ordner `auswahl`. EN: Two files and a folder in `auswahl`.
fn selection(root: &Path) -> Vec<PathBuf> {
    let base = root.join("auswahl");
    std::fs::create_dir(&base).unwrap();
    std::fs::write(base.join("brief.txt"), b"Brief").unwrap();
    std::fs::write(base.join("Größe ä.bin"), vec![7u8; 70_000]).unwrap();
    let tree = base.join("projekt");
    std::fs::create_dir(&tree).unwrap();
    common::write_sample_tree(&tree);
    vec![base.join("brief.txt"), base.join("Größe ä.bin"), tree]
}

fn refs(list: &[PathBuf]) -> Vec<&Path> {
    list.iter().map(PathBuf::as_path).collect()
}

#[test]
fn container_roundtrip_with_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let sources = selection(dir.path());
    let pass = common::random_passphrase();
    let protection = Protection::Passphrase {
        passphrase: &pass,
        params: common::min_params(),
    };
    let enc = dir.path().join("auswahl.pqkf");
    let report = files::encrypt_many(&refs(&sources), &enc, &protection).unwrap();
    assert_eq!((report.files, report.directories), (7, 5));
    assert_eq!(files::inspect(&enc).unwrap().content, Content::Directory);
    let out = dir.path().join("zurück");
    files::decrypt(&enc, &out, &Unlock::Passphrase(pass.as_ref())).unwrap();
    assert_eq!(
        common::read_tree(&out),
        common::read_tree(&dir.path().join("auswahl"))
    );
}

#[test]
fn container_roundtrip_for_recipient() {
    let dir = tempfile::tempdir().unwrap();
    let sources = selection(dir.path());
    let (key, pass) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    let public = key.public_part().unwrap();
    let enc = dir.path().join("c.pqkf");
    files::encrypt_many(&refs(&sources[..2]), &enc, &Protection::Recipient(&public)).unwrap();
    let unlocked = key.unlock(pass.as_ref()).unwrap();
    let out = dir.path().join("c");
    files::decrypt(&enc, &out, &Unlock::Key(&unlocked)).unwrap();
    assert_eq!(std::fs::read(out.join("brief.txt")).unwrap(), b"Brief");
    assert_eq!(common::dir_names(&out).len(), 2);
}

#[test]
fn equal_names_are_rejected_before_writing() {
    let dir = tempfile::tempdir().unwrap();
    for (sub, name) in [("a", "bericht.txt"), ("b", "Bericht.TXT")] {
        std::fs::create_dir(dir.path().join(sub)).unwrap();
        std::fs::write(dir.path().join(sub).join(name), b"x").unwrap();
    }
    let sources = [
        dir.path().join("a/bericht.txt"),
        dir.path().join("b/Bericht.TXT"),
    ];
    let pass = common::random_passphrase();
    let protection = Protection::Passphrase {
        passphrase: &pass,
        params: common::min_params(),
    };
    let enc = dir.path().join("x.pqkf");
    let err = files::encrypt_many(&refs(&sources), &enc, &protection).unwrap_err();
    assert_eq!(err, Error::InvalidInput { field: "duplicate" });
    assert!(!enc.exists());
    assert_eq!(common::dir_names(dir.path()), ["a", "b"]);
}

#[cfg(unix)]
#[test]
fn selected_symlink_is_skipped_and_reported() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("echt.txt"), b"x").unwrap();
    std::os::unix::fs::symlink("/etc/hostname", dir.path().join("link")).unwrap();
    let sources = [dir.path().join("echt.txt"), dir.path().join("link")];
    let pass = common::random_passphrase();
    let protection = Protection::Passphrase {
        passphrase: &pass,
        params: common::min_params(),
    };
    let report =
        files::encrypt_many(&refs(&sources), &dir.path().join("y.pqkf"), &protection).unwrap();
    assert_eq!(report.files, 1);
    assert_eq!(report.skipped.len(), 1);
    assert_eq!(report.skipped[0].path, "link");
}

#[test]
fn empty_or_missing_sources_fail_without_output() {
    let dir = tempfile::tempdir().unwrap();
    let pass = common::random_passphrase();
    let protection = Protection::Passphrase {
        passphrase: &pass,
        params: common::min_params(),
    };
    let enc = dir.path().join("z.pqkf");
    assert!(files::encrypt_many(&[], &enc, &protection).is_err());
    let missing = [dir.path().join("fehlt.txt")];
    let err = files::encrypt_many(&refs(&missing), &enc, &protection).unwrap_err();
    assert_eq!(err, Error::Io(std::io::ErrorKind::NotFound));
    assert!(!enc.exists());
}
