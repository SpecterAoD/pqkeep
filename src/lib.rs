//! DE: PQKeep – Core-Bibliothek zur Erzeugung und sicheren Speicherung von
//! Post-Quanten-Schlüsseln (ML-KEM, ML-DSA) und AES-256-Schlüsseln.
//! CLI und API bauen ausschließlich auf dieser Bibliothek auf.
//!
//! EN: PQKeep – core library for generating and securely storing
//! post-quantum keys (ML-KEM, ML-DSA) and AES-256 keys.
//! The CLI and API are built exclusively on top of this library.

#![forbid(unsafe_code)]

#[cfg(feature = "api")]
pub mod api;
pub mod build_info;
pub mod crypto;
pub mod envelope;
pub mod error;
pub mod files;
mod fs_identity;
mod fsutil;
pub mod hardening;
pub mod security;
pub mod sign;

pub use error::{Error, Result};

/// DE: Version der Bibliothek (aus `Cargo.toml`).
/// EN: Library version (from `Cargo.toml`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
#[path = "envelope/fault_tests.rs"]
mod envelope_fault_tests;
#[cfg(test)]
#[path = "crypto/factor_fault_tests.rs"]
mod factor_fault_tests;
#[cfg(test)]
mod fault_fixture_tests;
#[cfg(test)]
mod fault_io_tests;
#[cfg(test)]
mod fault_scope_tests;
#[cfg(test)]
mod fault_writer_tests;
#[cfg(test)]
#[path = "files/fault_tests.rs"]
mod files_fault_tests;
#[cfg(test)]
#[path = "files/recovery_tests.rs"]
mod files_recovery_tests;

#[cfg(test)]
mod crash_driver_tests;
#[cfg(test)]
mod crash_recovery_tests;

#[cfg(test)]
mod rekey_fault_tests;

#[cfg(test)]
mod rekey_crash_tests;

#[cfg(test)]
mod locked_owner_test_support;
