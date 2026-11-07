//! DE: Einstiegspunkt des Binaries `keyforge` (CLI und, mit Feature `api`, `keyforge serve`).
//! EN: Entry point of the `keyforge` binary (CLI and, with feature `api`, `keyforge serve`).

#![forbid(unsafe_code)]

mod cli;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::run()
}
