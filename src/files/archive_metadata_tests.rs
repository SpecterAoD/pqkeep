//! DE: Lebende Archivowner, Formatgleichheit und harte Fehlerpfade.
//! EN: Live archive owners, wire compatibility and strict failure paths.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::crypto::{
    SecretBytes, aead,
    stream::{DecryptReader, EncryptWriter},
};
use crate::hardening::memlock;
use std::io::Cursor;

use crate::files::locked_owner_tests::locked;

#[test]
fn record_is_locked_before_population_and_stable_across_owner_moves() {
    let mut entry = Entry::prepare().unwrap();
    let descriptor = entry.0.assert_metadata_locked();
    let base = std::ptr::from_ref(&entry.0.expose()[0]).addr();
    locked(&entry.0.expose()[0]);
    assert!(entry.path().is_err());
    entry.record_mut().path = Some(ConfidentialText::from_text("Ä/name").unwrap());
    entry.record_mut().kind = super::super::TAG_FILE;
    entry.record_mut().size = u64::MAX;
    let mut moved = Box::new(entry);
    assert_eq!(moved.0.assert_metadata_locked(), descriptor);
    assert_eq!(std::ptr::from_ref(&moved.0.expose()[0]).addr(), base);
    locked(&moved.0.expose()[0]);
    locked(&moved.0.expose()[0].size);
    assert!(memlock::is_locked(
        moved.path().unwrap().bytes().as_ptr().addr()
    ));
    assert!(moved.is_file());
    assert_eq!(moved.size(), u64::MAX);
    assert_eq!(format!("{moved:?}"), "Entry([REDACTED])");
    moved.record_mut().zeroize();
    assert!(moved.path().is_err());
    assert_eq!(moved.size(), 0);
    assert!(!moved.is_file());
    locked(&moved.0.expose()[0]);
}

#[test]
fn framing_is_locked_before_io_and_roundtrips_all_size_boundaries() {
    let key = aead::generate_key().unwrap();
    let mut framing = Framing::new().unwrap();
    let descriptor = framing.0.assert_metadata_locked();
    let base = std::ptr::from_ref(&framing.0.expose()[0]).addr();
    locked(&framing.0.expose()[0]);
    let mut enc = EncryptWriter::new(key.expose(), [0; 7], b"sizes", Vec::new()).unwrap();
    for value in [0, 1, 255, 256, u64::MAX] {
        framing.write(&mut enc, value, 8).unwrap();
        assert_eq!(std::ptr::from_ref(&framing.0.expose()[0]).addr(), base);
        assert_eq!(framing.0.assert_metadata_locked(), descriptor);
    }
    let mut dec = DecryptReader::new(
        key.expose(),
        [0; 7],
        b"sizes",
        Cursor::new(enc.finish().unwrap().0),
    )
    .unwrap();
    for expected in [0, 1, 255, 256, u64::MAX] {
        assert_eq!(framing.read(&mut dec, 8).unwrap(), expected);
        locked(&framing.0.expose()[0]);
    }
    dec.finish().unwrap();
    framing.advance(1).unwrap();
    assert!(framing.advance(1).is_err());
    assert_eq!(framing.count(), 1);
    framing.0.expose_mut()[0].count = u64::MAX;
    assert!(framing.advance(u64::MAX).is_err());
    assert_eq!(framing.count(), u64::MAX);
}

#[test]
fn archive_workspace_wiping_preserves_live_locked_descriptors() {
    let mut framing = Framing::new().unwrap();
    let descriptor = framing.0.assert_metadata_locked();
    framing.0.expose_mut()[0].bytes.fill(0x5a);
    framing.0.expose_mut()[0].count = u64::MAX;
    framing.0.expose_mut()[0].zeroize();
    assert!(framing.0.expose()[0].bytes.iter().all(|b| *b == 0));
    assert_eq!(framing.count(), 0);
    let mut moved = Box::new(framing);
    assert_eq!(moved.0.assert_metadata_locked(), descriptor);
    moved.0.zeroize();
    assert!(moved.0.expose().is_empty());
    assert_eq!(moved.0.assert_metadata_locked(), descriptor);
    let mut entry = Entry::prepare().unwrap();
    let record = entry.0.assert_metadata_locked();
    entry.record_mut().path = Some(ConfidentialText::from_text("Ä/wipe").unwrap());
    entry.0.zeroize();
    assert!(entry.0.expose().is_empty());
    assert_eq!(entry.0.assert_metadata_locked(), record);
}

#[test]
fn writer_preserves_exact_directory_wire_layout_and_reader_end_count() {
    let key = aead::generate_key().unwrap();
    let enc = EncryptWriter::new(key.expose(), [0; 7], b"layout", Vec::new()).unwrap();
    let mut writer = super::super::ArchiveWriter::new(enc).unwrap();
    writer.dir("Ä").unwrap();
    let mut dec = DecryptReader::new(
        key.expose(),
        [0; 7],
        b"layout",
        Cursor::new(writer.finish().unwrap()),
    )
    .unwrap();
    let mut wire = SecretBytes::zeroed(14).unwrap();
    dec.read_exact(wire.expose_mut()).unwrap();
    // DE: Öffentliche Formatfixture; keine gespeicherten Geheimwerte.
    // EN: Public format fixture; no stored secret values.
    assert_eq!(
        wire.expose(),
        &[1, 2, 0, 0xc3, 0x84, 0, 1, 0, 0, 0, 0, 0, 0, 0]
    );
    dec.finish().unwrap();
}

#[test]
fn reader_rejects_invalid_tags_lengths_truncation_and_end_count() {
    let fixtures: &[&[u8]] = &[
        &[3],
        &[1, 0, 0],
        &[2, 1, 0, b'x', 0],
        &[0, 1, 0, 0, 0, 0, 0, 0, 0],
        &[1, 1, 0, 0xff],
    ];
    for fixture in fixtures {
        let key = aead::generate_key().unwrap();
        let mut enc = EncryptWriter::new(key.expose(), [0; 7], b"invalid", Vec::new()).unwrap();
        enc.push(fixture).unwrap();
        let dec = DecryptReader::new(
            key.expose(),
            [0; 7],
            b"invalid",
            Cursor::new(enc.finish().unwrap().0),
        )
        .unwrap();
        let mut archive = super::super::ArchiveReader::new(dec).unwrap();
        assert!(archive.next_entry().is_err());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn lock_denial_is_checked_in_a_separate_process() {
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "files::archive::metadata::tests::lock_denial_child",
            "--ignored",
            "--test-threads=1",
        ])
        .env("PQKEEP_ARCHIVE_LOCK_DENIAL_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed"));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "DE: Nur isoliert ausführen. EN: Execute only in an isolated child."]
fn lock_denial_child() {
    use rustix::process::{Resource, Rlimit, setrlimit};
    assert_eq!(
        std::env::var("PQKEEP_ARCHIVE_LOCK_DENIAL_CHILD").unwrap(),
        "1"
    );
    setrlimit(
        Resource::Memlock,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .unwrap();
    assert!(matches!(Framing::new(), Err(crate::Error::MemoryLock)));
    assert!(matches!(Entry::prepare(), Err(crate::Error::MemoryLock)));
}
