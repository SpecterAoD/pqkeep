//! DE: Klartext-Metadaten eines Schlüssels. Sie sind **nicht verschlüsselt**, aber
//! über die AAD gegen Änderung geschützt. Achtung: personenbezogene Daten!
//! Regeln: NFC-normalisiert, keine Steuerzeichen, Längengrenzen, Name Pflicht.
//!
//! EN: Plaintext metadata of a key. They are **not encrypted** but protected
//! against modification via the AAD. Caution: personal data!
//! Rules: NFC-normalised, no control characters, length limits, name required.

use unicode_normalization::{UnicodeNormalization, is_nfc};

use crate::{Error, Result};

/// DE: Höchstlänge für Textfelder in Zeichen. EN: Maximum length of text fields in characters.
pub const MAX_FIELD_CHARS: usize = 128;
/// DE: Höchstlänge für den Account-Typ. EN: Maximum length of the account type.
pub const MAX_ACCOUNT_TYPE_CHARS: usize = 64;

/// DE: Metadaten (Name Pflicht, Rest optional). EN: Metadata (name required, rest optional).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Metadata {
    /// DE: Name. EN: Name.
    pub name: String,
    /// DE: Organisation. EN: Organisation.
    pub organization: Option<String>,
    /// DE: Firma. EN: Company.
    pub company: Option<String>,
    /// DE: Abteilung. EN: Department.
    pub department: Option<String>,
    /// DE: Account-Typ. EN: Account type.
    pub account_type: Option<String>,
}

impl Metadata {
    /// DE: Nur mit Namen. EN: With name only.
    #[must_use]
    pub fn with_name(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            ..Self::default()
        }
    }

    /// DE: Normalisiert alle Felder (NFC) und prüft sie. Für neue Schlüssel.
    /// EN: Normalises all fields (NFC) and validates them. For new keys.
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] mit dem Feldnamen / with the field name.
    pub fn normalized(&self) -> Result<Self> {
        let nfc = |s: &String| s.nfc().collect::<String>();
        let out = Self {
            name: nfc(&self.name),
            organization: self.organization.as_ref().map(nfc),
            company: self.company.as_ref().map(nfc),
            department: self.department.as_ref().map(nfc),
            account_type: self.account_type.as_ref().map(nfc),
        };
        out.validate()?;
        Ok(out)
    }

    /// DE: Prüft die Regeln (beim Laden: Text muss bereits NFC sein).
    /// EN: Validates the rules (when loading: text must already be NFC).
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] mit dem Feldnamen / with the field name.
    pub fn validate(&self) -> Result<()> {
        check(&self.name, "name", MAX_FIELD_CHARS)?;
        let optional = [
            (&self.organization, "organization", MAX_FIELD_CHARS),
            (&self.company, "company", MAX_FIELD_CHARS),
            (&self.department, "department", MAX_FIELD_CHARS),
            (&self.account_type, "account_type", MAX_ACCOUNT_TYPE_CHARS),
        ];
        for (value, field, max) in optional {
            if let Some(v) = value {
                check(v, field, max)?;
            }
        }
        Ok(())
    }

    /// DE: Felder in fester Reihenfolge (für die AAD). EN: Fields in fixed order (for the AAD).
    pub(crate) fn fields(&self) -> [(&'static str, Option<&str>); 5] {
        [
            ("name", Some(self.name.as_str())),
            ("organization", self.organization.as_deref()),
            ("company", self.company.as_deref()),
            ("department", self.department.as_deref()),
            ("account_type", self.account_type.as_deref()),
        ]
    }
}

fn check(value: &str, field: &'static str, max: usize) -> Result<()> {
    let chars = value.chars().count();
    let ok = chars > 0
        && chars <= max
        && !value.trim().is_empty()
        && !value.chars().any(char::is_control)
        && is_nfc(value);
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidInput { field })
    }
}
