//! DE: PQC KeyForge – Core-Bibliothek zur Erzeugung und sicheren Speicherung von
//! Post-Quanten-Schlüsseln (ML-KEM, ML-DSA) und AES-256-Schlüsseln.
//! CLI und API bauen ausschließlich auf dieser Bibliothek auf.
//!
//! EN: PQC KeyForge – core library for generating and securely storing
//! post-quantum keys (ML-KEM, ML-DSA) and AES-256 keys.
//! The CLI and API are built exclusively on top of this library.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod error;

pub use error::{Error, Result};

/// DE: Version der Bibliothek (aus `Cargo.toml`).
/// EN: Library version (from `Cargo.toml`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
