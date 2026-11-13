//! DE: Schlüsseldatei-Parser (Version 1 und 2) mit beliebigen Eingaben: nie Panik, nur `Ok`
//! oder `Err`.
//! EN: Key file parser (versions 1 and 2) with arbitrary input: never panic, only `Ok` or `Err`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pqkeep::envelope::{FORMAT_VERSION_V2, KeyFile};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Ok(key) = KeyFile::from_json(&text) {
        // DE: Gültige Dateien müssen sich verlustfrei erneut serialisieren lassen.
        // EN: Valid files must re-serialise losslessly.
        let again = key.to_json().expect("serialise");
        let back = KeyFile::from_json(&again).expect("reparse");
        assert_eq!(back.key_id(), key.key_id());
        // DE: Version und Faktorpflicht gehören zusammen und bleiben erhalten.
        // EN: Version and factor requirement belong together and are preserved.
        assert_eq!(key.needs_factor(), key.format_version() == FORMAT_VERSION_V2);
        assert_eq!(back.format_version(), key.format_version());
        assert_eq!(back, key);
        assert_eq!(back.to_json().expect("serialise again"), again);
    }
});
