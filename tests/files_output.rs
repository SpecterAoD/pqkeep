//! DE: Ausgabe: kein Überschreiben, keine Reste, Rechte (Linux), übersprungene
//! Einträge (Symlinks, nicht portable Namen, Nicht-UTF-8) im Bericht.
//! EN: Output: no overwriting, no leftovers, permissions (Linux), skipped entries
//! (symlinks, non-portable names, non-UTF-8) in the report.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::ErrorKind;

use pqc_keyforge::Error;
use pqc_keyforge::crypto::{KemAlgorithm, KeyAlgorithm};
use pqc_keyforge::files::{self, Protection, Unlock};

#[test]
fn never_overwrites() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("a.txt");
    std::fs::write(&src, b"neu / new").unwrap();
    let (key_file, pass) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    let unlocked = key_file.unlock(pass.as_ref()).unwrap();
    let enc = dir.path().join("a.pqkf");
    std::fs::write(&enc, b"vorhanden / existing").unwrap();
    let err = files::encrypt(&src, &enc, &Protection::Recipient(&key_file)).err();
    assert_eq!(err, Some(Error::Io(ErrorKind::AlreadyExists)));
    assert_eq!(std::fs::read(&enc).unwrap(), b"vorhanden / existing");

    std::fs::remove_file(&enc).unwrap();
    files::encrypt(&src, &enc, &Protection::Recipient(&key_file)).unwrap();
    let existing_file = dir.path().join("da.txt");
    std::fs::write(&existing_file, b"alt / old").unwrap();
    let err = files::decrypt(&enc, &existing_file, &Unlock::Key(&unlocked)).err();
    assert_eq!(err, Some(Error::Io(ErrorKind::AlreadyExists)));
    assert_eq!(std::fs::read(&existing_file).unwrap(), b"alt / old");

    // DE: Auch ein leerer Zielordner wird nicht ersetzt. EN: Even an empty target dir is kept.
    let src_dir = dir.path().join("q");
    std::fs::create_dir(&src_dir).unwrap();
    let enc_dir = dir.path().join("q.pqkf");
    files::encrypt(&src_dir, &enc_dir, &Protection::Recipient(&key_file)).unwrap();
    let empty_target = dir.path().join("leer");
    std::fs::create_dir(&empty_target).unwrap();
    let err = files::decrypt(&enc_dir, &empty_target, &Unlock::Key(&unlocked)).err();
    assert_eq!(err, Some(Error::Io(ErrorKind::AlreadyExists)));
    assert_eq!(
        common::dir_names(dir.path()),
        vec!["a.pqkf", "a.txt", "da.txt", "leer", "q", "q.pqkf"]
    );
}

#[test]
fn missing_source_and_target_directory() {
    let dir = tempfile::tempdir().unwrap();
    let pass = common::random_passphrase();
    let protection = Protection::Passphrase {
        passphrase: &pass,
        params: common::min_params(),
    };
    let err = files::encrypt(
        &dir.path().join("fehlt"),
        &dir.path().join("x.pqkf"),
        &protection,
    );
    assert_eq!(err.err(), Some(Error::Io(ErrorKind::NotFound)));
    let src = dir.path().join("a.txt");
    std::fs::write(&src, b"x").unwrap();
    let target = dir.path().join("kein-ordner").join("x.pqkf");
    let err = files::encrypt(&src, &target, &protection).err();
    assert_eq!(err, Some(Error::Io(ErrorKind::NotFound)));
}

#[cfg(unix)]
#[test]
fn permissions_and_skipped_entries() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("quelle");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("sub").join("ok.txt"), b"ok").unwrap();
    std::fs::write(src.join("CON"), b"reserviert / reserved").unwrap();
    std::fs::write(src.join(std::ffi::OsStr::from_bytes(b"bad\xff")), b"x").unwrap();
    std::os::unix::fs::symlink("/etc/passwd", src.join("link")).unwrap();

    let (key_file, pass) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem512));
    let enc = dir.path().join("q.pqkf");
    let report = files::encrypt(&src, &enc, &Protection::Recipient(&key_file)).unwrap();
    assert_eq!((report.files, report.directories), (1, 1));
    let mut reasons: Vec<_> = report
        .skipped
        .iter()
        .map(|s| (s.path.clone(), s.reason))
        .collect();
    reasons.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        reasons,
        vec![
            ("CON".to_owned(), files::SkipReason::InvalidName),
            ("bad\u{fffd}".to_owned(), files::SkipReason::NonUtf8Name),
            ("link".to_owned(), files::SkipReason::Symlink),
        ]
    );
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&enc), 0o600);

    let out = dir.path().join("out");
    let unlocked = key_file.unlock(pass.as_ref()).unwrap();
    files::decrypt(&enc, &out, &Unlock::Key(&unlocked)).unwrap();
    assert_eq!(mode(&out), 0o700);
    assert_eq!(mode(&out.join("sub")), 0o700);
    assert_eq!(mode(&out.join("sub").join("ok.txt")), 0o600);
    assert!(!out.join("link").exists());
}

#[cfg(unix)]
#[test]
fn symlink_as_source_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.txt");
    std::fs::write(&real, b"x").unwrap();
    let link = dir.path().join("link.txt");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let (key_file, _) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem512));
    let err = files::encrypt(
        &link,
        &dir.path().join("x.pqkf"),
        &Protection::Recipient(&key_file),
    );
    assert_eq!(err.err(), Some(Error::InvalidInput { field: "source" }));
}
