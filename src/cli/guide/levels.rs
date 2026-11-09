//! DE: Algorithmen mit Zweck, NIST-Sicherheitskategorie und Erklärung für den geführten Ablauf.
//! Kategorie nach FIPS 203/204: 1 ≈ AES-128, 3 ≈ AES-192, 5 ≈ AES-256 (Schlüsselsuche).
//! EN: Algorithms with purpose, NIST security category and explanation for the guided flow.
//! Category per FIPS 203/204: 1 ≈ AES-128, 3 ≈ AES-192, 5 ≈ AES-256 (key search).

use pqkeep::security::Lang;

/// DE: Wofür der Schlüssel dient. EN: What the key is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// DE: Dateien für mich verschlüsseln lassen (ML-KEM). EN: Receive encrypted files (ML-KEM).
    Encrypt,
    /// DE: Dateien signieren (ML-DSA). EN: Sign files (ML-DSA).
    Sign,
    /// DE: Symmetrischer Schlüssel (AES-256). EN: Symmetric key (AES-256).
    Symmetric,
}

/// DE: Eine Auswahl im Ablauf. EN: One choice in the flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Level {
    /// DE: Wert für `--algorithm`. EN: Value for `--algorithm`.
    pub id: &'static str,
    pub purpose: Purpose,
    /// DE: NIST-Kategorie (AES: 5). EN: NIST category (AES: 5).
    pub category: u8,
    /// DE: Empfohlene Auswahl. EN: Recommended choice.
    pub recommended: bool,
    de: &'static str,
    en: &'static str,
}

impl Level {
    /// DE: Anzeigezeile. EN: Display line.
    pub fn label(&self, lang: Lang) -> String {
        let (cat, note) = match lang {
            Lang::De => ("NIST-Kategorie", self.de),
            Lang::En => ("NIST category", self.en),
        };
        format!(
            "{:<12} {cat} {} – {note}",
            self.id.to_uppercase(),
            self.category
        )
    }
}

const fn level(
    id: &'static str,
    purpose: Purpose,
    category: u8,
    rec: bool,
    de: &'static str,
    en: &'static str,
) -> Level {
    Level {
        id,
        purpose,
        category,
        recommended: rec,
        de,
        en,
    }
}

/// DE: Alle Stufen, stärkste zuerst. EN: All levels, strongest first.
pub const LEVELS: [Level; 7] = [
    level(
        "ml-kem-1024",
        Purpose::Encrypt,
        5,
        true,
        "höchste Stärke, empfohlen für langfristige Geheimnisse (öffentl. Schlüssel 1568 Byte)",
        "highest strength, recommended for long-term secrets (public key 1568 bytes)",
    ),
    level(
        "ml-kem-768",
        Purpose::Encrypt,
        3,
        false,
        "Standard, guter Kompromiss aus Stärke und Größe (1184 Byte)",
        "default, good balance of strength and size (1184 bytes)",
    ),
    level(
        "ml-kem-512",
        Purpose::Encrypt,
        1,
        false,
        "kleinste Stufe, nur für kurzlebige Daten (800 Byte)",
        "smallest level, only for short-lived data (800 bytes)",
    ),
    level(
        "ml-dsa-87",
        Purpose::Sign,
        5,
        true,
        "höchste Stärke, nötig für „pqkeep sign“ (Signatur 4627 Byte)",
        "highest strength, required for \"pqkeep sign\" (signature 4627 bytes)",
    ),
    level(
        "ml-dsa-65",
        Purpose::Sign,
        3,
        false,
        "Standard – „pqkeep sign“ nutzt derzeit nur ML-DSA-87",
        "default – \"pqkeep sign\" currently uses ML-DSA-87 only",
    ),
    level(
        "ml-dsa-44",
        Purpose::Sign,
        2,
        false,
        "kleinste Stufe – nicht für „pqkeep sign“",
        "smallest level – not for \"pqkeep sign\"",
    ),
    level(
        "aes-256",
        Purpose::Symmetric,
        5,
        true,
        "symmetrischer 256-Bit-Schlüssel (Kategorie 5 ist so definiert)",
        "symmetric 256-bit key (category 5 is defined by it)",
    ),
];

/// DE: Stufen eines Zwecks. EN: Levels of one purpose.
pub fn for_purpose(purpose: Purpose) -> Vec<Level> {
    LEVELS
        .iter()
        .copied()
        .filter(|l| l.purpose == purpose)
        .collect()
}

#[cfg(test)]
#[path = "levels_tests.rs"]
mod levels_tests;
