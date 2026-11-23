//! DE: Isolierte Plattform-FFI; Secret-Speicherbesitz bleibt im Root-Projekt.
//! EN: Isolated platform FFI; root retains ownership of protected secret storage.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(any(windows, test))]
mod wer;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{current_wer_flags, is_console, suppress_wer_heap_reporting, write_console};
