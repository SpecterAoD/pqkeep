//! DE: Parser für öffentliche Schlüsseldateien: nie Panik, Roundtrip bei gültigen Eingaben.
//! EN: Public key file parser: never panic, roundtrip for valid input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pqkeep::envelope::PublicKeyFile;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Ok(key) = PublicKeyFile::from_json(&text) {
        let again = key.to_json().expect("serialise");
        let back = PublicKeyFile::from_json(&again).expect("reparse");
        assert_eq!(back.public_key(), key.public_key());
    }
});
