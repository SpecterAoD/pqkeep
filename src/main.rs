//! DE: Einstiegspunkt des Binaries `keyforge` (CLI). Die API folgt in Schritt 5.
//! EN: Entry point of the `keyforge` binary (CLI). The API follows in step 5.

#![forbid(unsafe_code)]

mod cli;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::run()
}
