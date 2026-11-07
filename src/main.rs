//! DE: Einstiegspunkt des Binaries `pqkeep` (CLI und, mit Feature `api`, `pqkeep serve`).
//! EN: Entry point of the `pqkeep` binary (CLI and, with feature `api`, `pqkeep serve`).

#![forbid(unsafe_code)]

mod cli;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::run()
}
