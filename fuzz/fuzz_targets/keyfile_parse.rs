//! DE: Schlüsseldatei-Parser mit beliebigen Eingaben: nie Panik, nur `Ok` oder `Err`.
//! EN: Key file parser with arbitrary input: never panic, only `Ok` or `Err`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pqkeep::envelope::KeyFile;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Ok(key) = KeyFile::from_json(&text) {
        // DE: Gültige Dateien müssen sich verlustfrei erneut serialisieren lassen.
        // EN: Valid files must re-serialise losslessly.
        let again = key.to_json().expect("serialise");
        let back = KeyFile::from_json(&again).expect("reparse");
        assert_eq!(back.key_id(), key.key_id());
    }
});
