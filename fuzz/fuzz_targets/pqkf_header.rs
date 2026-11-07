//! DE: Header-Parser von `.pqkf`-Dateien: nie Panik; gültige Header kodieren sich identisch.
//! EN: `.pqkf` header parser: never panic; valid headers re-encode identically.
#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use pqkeep::files::FileHeader;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    if let Ok(header) = FileHeader::read(&mut cursor) {
        let encoded = header.encode();
        let again = FileHeader::read(&mut Cursor::new(&encoded)).expect("reparse");
        assert_eq!(again.encode(), encoded);
    }
});
