//! DE: Einstiegspunkt des Binaries `keyforge`. CLI (Schritt 4) und API (Schritt 5) folgen.
//! EN: Entry point of the `keyforge` binary. CLI (step 4) and API (step 5) will follow.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    // DE: Vorläufig nur Versionsausgabe, noch keine Funktionen.
    // EN: Version output only for now, no functionality yet.
    println!(
        "keyforge {} – Grundgerüst / scaffold",
        pqc_keyforge::VERSION
    );
    ExitCode::SUCCESS
}
