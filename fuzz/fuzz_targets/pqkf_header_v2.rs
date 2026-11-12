//! DE: Header-Parser des Dateiformats v2: nie Panik, liest höchstens den größten zulässigen
//! Header; gültige Header kodieren sich identisch und erfüllen alle Regeln.
//! EN: Header parser of file format v2: never panic, reads at most the largest valid header;
//! valid headers re-encode identically and satisfy all rules.
#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use pqkeep::files::format_v2::{HeaderV2, MAX_ENCODED_LEN, check_slots};

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let result = HeaderV2::read(&mut cursor);
    let consumed = usize::try_from(cursor.position()).expect("position");
    assert!(consumed <= MAX_ENCODED_LEN);
    if let Ok(header) = result {
        check_slots(&header.slots).expect("rules");
        let encoded = header.encode().expect("encode");
        assert_eq!(encoded, data[..consumed]);
        for index in 0..header.slots.len() {
            header.wrap_aad(index).expect("wrap aad");
        }
        header.stream_aad().expect("stream aad");
    }
});
