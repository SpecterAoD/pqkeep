//! DE: Faktordatei (C03 aus `docs/V2_TESTS.md`): Erzeugen ohne Überschreiben, Lesen nur von
//! regulären Dateien mit genau 32 Bytes; fehlende, falsche, zu große Dateien, Links, Geräte und
//! zu offene Rechte (D4) werden abgelehnt – und nie wird dabei eine Datei neu erzeugt.
//! EN: Factor file (C03 in `docs/V2_TESTS.md`): creation without overwriting, reading only regular
//! files with exactly 32 bytes; missing, wrong, oversized files, links, devices and too open
//! permissions (D4) are rejected – and no file is ever created along the way.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use pqkeep::Error;
use pqkeep::crypto::factor::{FACTOR_LEN, Factor};
use pqkeep::crypto::kdf::KdfParams;
use pqkeep::crypto::v2::{self, Domain};

const WRONG: Error = Error::InvalidInput { field: "factor" };

/// DE: Schreibt eine Datei, die nur der Eigentümer lesen darf. EN: Writes an owner-only file.
fn write_private(path: &Path, data: &[u8]) {
    fs::write(path, data).unwrap();
    set_mode(path, 0o600);
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

/// DE: Schlüssel aus fester Passphrase und Faktor (zum Vergleich zweier Faktoren).
/// EN: Key from a fixed passphrase and factor (to compare two factors).
fn key_with(factor: Option<&Factor>) -> Vec<u8> {
    let pass = common::passphrase("nur ein Testwert / test value only");
    let params = KdfParams {
        parallelism: 1,
        ..common::min_params()
    };
    let key = v2::passphrase_kek(Domain::File, &pass, factor, &[9; 32], &params).unwrap();
    key.expose().to_vec()
}

#[test]
fn create_then_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("faktor.bin");
    Factor::create(&path).unwrap();
    let raw = fs::read(&path).unwrap();
    assert_eq!(raw.len(), FACTOR_LEN);
    assert_ne!(raw, [0u8; FACTOR_LEN]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(common::dir_names(dir.path()), ["faktor.bin"]);

    // DE: Gelesener Faktor entspricht dem Dateiinhalt und verändert den Schlüssel.
    // EN: The factor read equals the file content and changes the key.
    let read = key_with(Some(&Factor::read(&path).unwrap()));
    assert_eq!(read, key_with(Some(&Factor::from_bytes(&raw).unwrap())));
    assert_ne!(read, key_with(None));

    let second = dir.path().join("zweiter.bin");
    Factor::create(&second).unwrap();
    assert_ne!(fs::read(&second).unwrap(), raw);
}

#[test]
fn create_never_overwrites() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("faktor.bin");
    write_private(&path, b"vorhanden / existing");
    let exists = Error::Io(ErrorKind::AlreadyExists);
    assert_eq!(Factor::create(&path).err(), Some(exists.clone()));
    assert_eq!(fs::read(&path).unwrap(), b"vorhanden / existing");
    assert_eq!(Factor::create(dir.path()).err(), Some(exists));
    assert_eq!(common::dir_names(dir.path()), ["faktor.bin"]);
}

#[test]
fn wrong_length_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("faktor.bin");
    for len in [0, 1, FACTOR_LEN - 1, FACTOR_LEN + 1, 64, 4096] {
        write_private(&path, &vec![0x5a; len]);
        assert_eq!(Factor::read(&path).err(), Some(WRONG), "{len}");
        assert_eq!(Factor::from_bytes(&vec![0x5a; len]).err(), Some(WRONG));
    }
    write_private(&path, &[0x5a; FACTOR_LEN]);
    assert!(Factor::read(&path).is_ok());
}

#[test]
fn missing_file_is_an_error_and_nothing_is_created() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fehlt.bin");
    assert_eq!(
        Factor::read(&path).err(),
        Some(Error::Io(ErrorKind::NotFound))
    );
    assert_eq!(common::dir_names(dir.path()), Vec::<String>::new());
}

#[test]
fn directory_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(Factor::read(dir.path()).err(), Some(WRONG));
}

#[cfg(unix)]
#[test]
fn links_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("faktor.bin");
    write_private(&target, &[0x5a; FACTOR_LEN]);
    let link = dir.path().join("link.bin");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert_eq!(Factor::read(&link).err(), Some(WRONG));

    // DE: Auch ein Link ins Leere ist ein vorhandenes Ziel und wird nicht überschrieben.
    // EN: A dangling link also counts as an existing target and is not overwritten.
    let dangling = dir.path().join("leer.bin");
    std::os::unix::fs::symlink(dir.path().join("nirgends"), &dangling).unwrap();
    assert_eq!(
        Factor::create(&dangling).err(),
        Some(Error::Io(ErrorKind::AlreadyExists))
    );
    assert!(!dir.path().join("nirgends").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn devices_are_rejected() {
    for device in ["/dev/zero", "/dev/urandom", "/dev/null"] {
        assert_eq!(Factor::read(Path::new(device)).err(), Some(WRONG));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn open_permissions_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("faktor.bin");
    write_private(&path, &[0x5a; FACTOR_LEN]);
    let open = Error::InvalidInput {
        field: "factor_permissions",
    };
    for mode in [0o640, 0o604, 0o660, 0o644, 0o620, 0o601] {
        set_mode(&path, mode);
        assert_eq!(Factor::read(&path).err(), Some(open.clone()), "{mode:o}");
    }
    for mode in [0o600, 0o400] {
        set_mode(&path, mode);
        assert!(Factor::read(&path).is_ok(), "{mode:o}");
    }
}
