//! DE: Zentrale Fehlertypen. Fehlertexte enthalten niemals Geheimnisse oder
//! Eingabedaten, nur die Fehlerart und ggf. einen festen Feldnamen.
//!
//! EN: Central error types. Error messages never contain secrets or input
//! data, only the kind of error and, where useful, a fixed field name.

use thiserror::Error as ThisError;

/// DE: Ergebnistyp der Bibliothek.
/// EN: Result type of the library.
pub type Result<T> = std::result::Result<T, Error>;

/// DE: Alle Fehler der Bibliothek. Texte sind zweisprachig (DE / EN).
/// EN: All library errors. Messages are bilingual (DE / EN).
#[derive(Debug, ThisError, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// DE: Ungültige Eingabe; `field` ist ein fester Name, nie der Wert.
    /// EN: Invalid input; `field` is a fixed name, never the value.
    #[error("Ungültige Eingabe im Feld „{field}“ / invalid input in field '{field}'")]
    InvalidInput {
        /// DE: Name des Feldes. EN: Name of the field.
        field: &'static str,
    },

    /// DE: Kryptografische Operation fehlgeschlagen (bewusst ohne Details).
    /// EN: Cryptographic operation failed (deliberately without details).
    #[error("Kryptografische Operation fehlgeschlagen / cryptographic operation failed")]
    Crypto,

    /// DE: Entschlüsselung fehlgeschlagen: falsche Passphrase oder manipulierte Daten.
    /// Bewusst nicht unterscheidbar. EN: Decryption failed: wrong passphrase or
    /// tampered data. Deliberately indistinguishable.
    #[error(
        "Entschlüsselung fehlgeschlagen (falsche Passphrase oder manipulierte Daten) / decryption failed (wrong passphrase or tampered data)"
    )]
    Decrypt,

    /// DE: KDF-Parameter außerhalb der zulässigen Grenzen.
    /// EN: KDF parameters outside the permitted bounds.
    #[error("KDF-Parameter unzulässig / KDF parameters not permitted")]
    KdfParams,

    /// DE: Passphrase erfüllt die Regeln nicht (Details über `security::Rejection`).
    /// EN: Passphrase does not meet the rules (details via `security::Rejection`).
    #[error("Passphrase zu schwach / passphrase too weak")]
    WeakPassphrase,

    /// DE: Betriebssystem liefert keinen Zufall. EN: Operating system provides no randomness.
    #[error("Zufallsquelle nicht verfügbar / random source unavailable")]
    Rng,

    /// DE: Nicht unterstützte Version oder nicht unterstützter Algorithmus.
    /// EN: Unsupported version or algorithm.
    #[error("Nicht unterstützt / unsupported")]
    Unsupported,

    /// DE: Ein-/Ausgabefehler; nur die Fehlerart, kein Pfad.
    /// EN: I/O error; only the error kind, no path.
    #[error("Ein-/Ausgabefehler / I/O error: {0}")]
    Io(std::io::ErrorKind),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        // DE: Nur die Art übernehmen, damit keine Pfade in Meldungen landen.
        // EN: Keep only the kind so that no paths end up in messages.
        Self::Io(err.kind())
    }
}
