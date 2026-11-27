//! DE: Header-Parser von `.pqkf`-Dateien (v1): nie Panik; gültige Header kodieren sich byte-genau
//! wie gelesen (kanonisch – die Strom-AAD entsteht aus dem neu kodierten Header, #335 G1).
//! EN: `.pqkf` header parser (v1): never panic; valid headers re-encode byte-exactly as read
//! (canonical – the stream AAD is derived from the re-encoded header, #335 G1).
#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use pqkeep::files::FileHeader;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    if let Ok(header) = FileHeader::read(&mut cursor) {
        let consumed = usize::try_from(cursor.position()).expect("position");
        let encoded = header.encode();
        assert_eq!(encoded, data[..consumed]);
        let again = FileHeader::read(&mut Cursor::new(&encoded)).expect("reparse");
        assert_eq!(again.encode(), encoded);
    }
});
