//! DE: Echte Archivpfade ohne KDF; Schutz vor und nach der Archivverarbeitung.
//! EN: Actual archive paths without a KDF; protection across archive processing.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock;
use std::io::Cursor;

#[test]
fn actual_archive_reader_retains_locked_names_and_checks_payload_hash() {
    let key = crate::crypto::aead::generate_key().unwrap();
    let prefix = [0; 7];
    let mut writer = ArchiveWriter::new(
        EncryptWriter::new(key.expose(), prefix, b"fixture", Vec::new()).unwrap(),
    );
    writer.dir("Ä/fixture").unwrap();
    writer
        .file("Ä/fixture/name", &mut Cursor::new(b"payload"), 7)
        .unwrap();
    let ciphertext = writer.finish().unwrap();
    let mut reader = ArchiveReader::new(
        DecryptReader::new(key.expose(), prefix, b"fixture", Cursor::new(ciphertext)).unwrap(),
    );
    let dir = reader.next_entry().unwrap().unwrap();
    let name = match dir {
        Entry::Dir(name) => Some(name),
        Entry::File(..) => None,
    }
    .unwrap();
    assert!(memlock::is_locked(name.bytes().as_ptr().addr()));
    assert_eq!(name.expose().unwrap(), "Ä/fixture");
    assert_eq!(format!("{name:?}"), "[REDACTED]");
    let file = reader.next_entry().unwrap().unwrap();
    let (name, size) = match file {
        Entry::File(name, size) => Some((name, size)),
        Entry::Dir(_) => None,
    }
    .unwrap();
    assert!(memlock::is_locked(name.bytes().as_ptr().addr()));
    assert_eq!(name.expose().unwrap(), "Ä/fixture/name");
    let mut sink = SecretBytes::zeroed(usize::try_from(size).unwrap()).unwrap();
    reader
        .copy_file(size, &mut Cursor::new(sink.expose_mut()))
        .unwrap();
    assert_eq!(sink.expose(), b"payload");
    assert!(reader.next_entry().unwrap().is_none());
    reader.finish().unwrap();
}
