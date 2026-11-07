//! DE: Dateizugriff: atomares Schreiben, kein Überschreiben ohne Zustimmung,
//! Rechte 0600 und Rechte-Warnung (Linux), Größengrenze, Pfade mit Leerzeichen,
//! Unicode und (unter Windows) Backslashes. Läuft in der CI auf Linux und Windows.
//! EN: File access: atomic writing, no overwriting without consent, mode 0600 and
//! permission warning (Linux), size limit, paths with spaces, Unicode and (on
//! Windows) backslashes. Runs in CI on Linux and Windows.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use pqkeep::Error;
use pqkeep::crypto::KeyAlgorithm;
use pqkeep::envelope::{self, MAX_FILE_BYTES, Overwrite};

fn leftover_temp_files(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.to_string_lossy().contains(".tmp-"))
        .collect()
}

#[test]
fn save_and_load_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Schlüssel mit Leerzeichen.json");
    let (file, pass) = common::key_file(KeyAlgorithm::Aes256);
    envelope::save(&file, &path, Overwrite::No).unwrap();
    let (loaded, warnings) = envelope::load(&path).unwrap();
    assert_eq!(loaded, file);
    assert_eq!(warnings, vec![]);
    assert!(loaded.unlock(pass.as_ref()).is_ok());
    assert_eq!(leftover_temp_files(dir.path()), Vec::<PathBuf>::new());
}

#[test]
fn no_overwrite_without_consent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key.json");
    let (first, _) = common::key_file(KeyAlgorithm::Aes256);
    let (second, _) = common::key_file(KeyAlgorithm::Aes256);
    envelope::save(&first, &path, Overwrite::No).unwrap();
    let err = envelope::save(&second, &path, Overwrite::No).err();
    assert_eq!(err, Some(Error::Io(std::io::ErrorKind::AlreadyExists)));
    assert_eq!(
        envelope::load(&path).unwrap().0,
        first,
        "unverändert / unchanged"
    );
    assert_eq!(leftover_temp_files(dir.path()), Vec::<PathBuf>::new());

    envelope::save(&second, &path, Overwrite::Yes).unwrap();
    assert_eq!(envelope::load(&path).unwrap().0, second);
    assert_eq!(leftover_temp_files(dir.path()), Vec::<PathBuf>::new());
}

#[test]
fn nested_and_platform_paths() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("Ordner ä").join("Unterordner");
    std::fs::create_dir_all(&sub).unwrap();
    // DE: Unter Windows ergibt `join` Backslash-Pfade (C:\Users\…\AppData\Local\Temp\…).
    // EN: On Windows `join` yields backslash paths (C:\Users\…\AppData\Local\Temp\…).
    let path = sub.join("schlüssel.json");
    #[cfg(windows)]
    assert!(path.to_string_lossy().contains('\\'));
    envelope::write_atomic(&path, b"{}", Overwrite::No).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"{}");
}

#[test]
fn missing_directory_and_no_filename() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("gibt-es-nicht").join("k.json");
    let err = envelope::write_atomic(&missing, b"x", Overwrite::No).err();
    assert_eq!(err, Some(Error::Io(std::io::ErrorKind::NotFound)));
    let err = envelope::write_atomic(Path::new(".."), b"x", Overwrite::No).err();
    assert_eq!(err, Some(Error::InvalidInput { field: "path" }));
}

#[test]
fn oversized_and_invalid_files_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("big.json");
    std::fs::write(&big, vec![b' '; MAX_FILE_BYTES + 10]).unwrap();
    assert_eq!(
        envelope::load(&big).err(),
        Some(Error::InvalidInput { field: "file" })
    );
    let binary = dir.path().join("bin.json");
    std::fs::write(&binary, [0xFF, 0xFE, 0x00]).unwrap();
    assert!(envelope::load(&binary).is_err());
    let missing = dir.path().join("nope.json");
    assert_eq!(
        envelope::load(&missing).err(),
        Some(Error::Io(std::io::ErrorKind::NotFound))
    );
}

#[cfg(unix)]
#[test]
fn mode_0600_and_permission_warning() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key.json");
    let (file, _) = common::key_file(KeyAlgorithm::Aes256);
    envelope::save(&file, &path, Overwrite::No).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (_, warnings) = envelope::load(&path).unwrap();
    assert_eq!(
        warnings,
        vec![envelope::FileWarning::PermissiveMode { mode: 0o644 }]
    );
    let text = warnings[0].message(pqkeep::security::Lang::De);
    assert!(text.contains("chmod 600"));
}
