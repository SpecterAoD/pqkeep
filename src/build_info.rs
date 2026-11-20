//! DE: Build-Kanal. Vorschau-Builds (`preview`) werden nur beim Bauen über die Umgebungsvariablen
//! `PQKEEP_CHANNEL` und `PQKEEP_BUILD_ID` gekennzeichnet. Ohne diese Variablen (Betas, Releases,
//! normale Entwicklung) ist die Ausgabe unverändert. Das JSON-Schema (`docs/JSON.md`) bleibt gleich.
//! EN: Build channel. Preview builds (`preview`) are marked only at build time through the
//! environment variables `PQKEEP_CHANNEL` and `PQKEEP_BUILD_ID`. Without them (betas, releases,
//! normal development) the output is unchanged. The JSON schema (`docs/JSON.md`) stays the same.

use std::sync::OnceLock;

use crate::VERSION;

/// DE: Kanal zur Bauzeit (`PQKEEP_CHANNEL`); Betas und Releases haben keinen.
/// EN: Channel at build time (`PQKEEP_CHANNEL`); betas and releases have none.
pub const CHANNEL: Option<&str> = option_env!("PQKEEP_CHANNEL");

/// DE: Kennung des Vorschau-Builds, z. B. `20261123.a1b2c3d` (`PQKEEP_BUILD_ID`).
/// EN: Identifier of the preview build, e.g. `20261123.a1b2c3d` (`PQKEEP_BUILD_ID`).
pub const BUILD_ID: Option<&str> = option_env!("PQKEEP_BUILD_ID");

/// DE: Längste erlaubte Build-Kennung. EN: Longest accepted build identifier.
const MAX_ID_LEN: usize = 40;

/// DE: Ist dieses Programm ein Vorschau-Build? EN: Is this program a preview build?
#[must_use]
pub fn is_preview() -> bool {
    is_preview_channel(CHANNEL)
}

/// DE: Nur der Kanal `preview` kennzeichnet eine Vorschau. EN: Only channel `preview` marks a preview.
#[must_use]
pub fn is_preview_channel(channel: Option<&str>) -> bool {
    channel == Some("preview")
}

/// DE: Die Kennung darf nur Buchstaben, Ziffern, `.` und `-` enthalten (keine Steuerzeichen).
/// EN: The identifier may contain only letters, digits, `.` and `-` (no control characters).
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// DE: Versionszeile für Kanal und Kennung: `0.1.0-beta.3` oder `0.1.0-beta.3+preview.<Kennung>`.
/// EN: Version line for channel and identifier: `0.1.0-beta.3` or `0.1.0-beta.3+preview.<id>`.
#[must_use]
pub fn format_version(version: &str, channel: Option<&str>, id: Option<&str>) -> String {
    if !is_preview_channel(channel) {
        return version.to_owned();
    }
    match id.filter(|i| valid_id(i)) {
        Some(id) => format!("{version}+preview.{id}"),
        None => format!("{version}+preview"),
    }
}

/// DE: Versionszeile dieses Builds (für `--version`). EN: Version line of this build (for `--version`).
#[must_use]
pub fn version_line() -> &'static str {
    static LINE: OnceLock<String> = OnceLock::new();
    LINE.get_or_init(|| format_version(VERSION, CHANNEL, BUILD_ID))
}

/// DE: Fenstertitel; bei Vorschau-Builds mit Zusatz „PREVIEW“. EN: Window title; with "PREVIEW" on previews.
#[must_use]
pub fn window_title(title: &str) -> String {
    if is_preview() {
        format!("{title} – PREVIEW")
    } else {
        title.to_owned()
    }
}

#[cfg(test)]
#[path = "build_info_tests.rs"]
mod build_info_tests;
