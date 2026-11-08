//! DE: Container-Format (Spezifikation Abschnitt 4): JSON mit Magic und Version,
//! Klartext-Metadaten (über AAD authentifiziert, **nicht verschlüsselt**),
//! öffentlichem Schlüssel und dem mit Passphrase geschützten Seed bzw. AES-Schlüssel.
//! Format-Doku: `docs/FORMAT.md`.
//!
//! EN: Container format (specification section 4): JSON with magic and version,
//! plaintext metadata (authenticated via AAD, **not encrypted**), public key and
//! the passphrase-protected seed or AES key. Format docs: `docs/FORMAT.md`.

mod encoding;
mod format;
pub mod io;
mod keyfile;
mod metadata;
mod parse;
mod public;
pub mod time;

pub use encoding::hex_encode;
pub(crate) use encoding::{b64_decode, b64_encode, hex_decode};
pub use format::{FORMAT_VERSION, MAGIC};
pub use io::{
    FileWarning, Overwrite, load, load_public, read_limited, save, save_public, write_atomic,
};
pub(crate) use keyfile::fingerprint;
pub use keyfile::{KEY_ID_LEN, KeyFile, MAX_FILE_BYTES, UnlockedKey};
pub use metadata::{MAX_ACCOUNT_TYPE_CHARS, MAX_FIELD_CHARS, Metadata};
pub use public::{PUBLIC_MAGIC, PublicKeyFile};
