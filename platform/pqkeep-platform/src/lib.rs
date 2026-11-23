//! DE: Isolierte Plattform-FFI; Secret-Speicherbesitz bleibt im Root-Projekt.
//! EN: Isolated platform FFI; root retains ownership of protected secret storage.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::write_console;
