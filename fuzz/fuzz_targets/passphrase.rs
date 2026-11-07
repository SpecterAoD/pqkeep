//! DE: Passphrase-Normalisierung und Stärkeprüfung: nie Panik, Entropie endlich und nicht negativ.
//! EN: Passphrase normalisation and strength check: never panic, entropy finite and non-negative.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pqkeep::security::{Passphrase, StrongPassphrase};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Ok(pass) = Passphrase::new(&text) {
        let assessment = pass.assess();
        assert!(assessment.entropy_bits.is_finite() && assessment.entropy_bits >= 0.0);
        let strong = assessment.is_strong();
        assert_eq!(StrongPassphrase::try_from(pass).is_ok(), strong);
    }
});
