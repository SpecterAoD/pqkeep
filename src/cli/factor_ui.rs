//! DE: Faktordatei in Menü, geführtem Ablauf und Kontextmenü (U0-3): gemeinsame Texte und die
//! Entscheidung, welche zusätzlichen Angaben `decrypt` für eine Datei braucht. Gelesen werden nur
//! der Header bzw. die (verschlüsselte) Schlüsseldatei – keine Geheimnisse. Weitergegeben wird
//! immer nur der Pfad der Faktordatei; die Arbeit macht der Kindprozess mit voller Sandbox.
//! EN: Factor file in menu, guided flow and context menu (U0-3): shared texts and the decision
//! which additional input `decrypt` needs for a file. Only the header or the (encrypted) key file
//! is read – no secrets. Only the path of the factor file is ever passed on; the work is done by
//! the child process with the full sandbox.

use std::path::Path;

use pqkeep::envelope;
use pqkeep::security::Lang;

use super::factor_cmd::FLAG;
use super::io::{CliResult, Failure};
use super::unlock::Access;

/// DE: Texte einer Sprache. EN: Texts of one language.
#[allow(missing_docs)]
pub struct UiTexts {
    pub menu_out: &'static str,
    pub menu_optional: &'static str,
    pub needed: &'static str,
    pub existing: &'static str,
    pub guide_use: &'static str,
    pub guide_choice: &'static str,
    pub guide_new: &'static str,
    pub label: &'static str,
    pub pick: &'static str,
    pub filter: &'static str,
}

static DE: UiTexts = UiTexts {
    menu_out: "Zieldatei der neuen Faktordatei (z. B. auf einem USB-Stick)",
    menu_optional: "Faktordatei zusätzlich zur Passphrase (leer = keine)",
    needed: "Dafür ist zusätzlich die Faktordatei nötig – Pfad der Faktordatei",
    existing: "Vorhandene Faktordatei (neu erzeugen mit „pqkeep factor“ oder im Menü)",
    guide_use: "Zusätzlich mit einer Faktordatei schützen (zweiter Faktor, z. B. auf einem USB-Stick)?",
    guide_choice: "Vorhandene Faktordatei verwenden|Neue Faktordatei erzeugen",
    guide_new: "Dateiname der neuen Faktordatei",
    label: "Faktordatei",
    pick: "Faktordatei wählen (zusätzlich zur Passphrase)",
    filter: "Alle Dateien (*)",
};

static EN: UiTexts = UiTexts {
    menu_out: "Target of the new factor file (e.g. on a USB stick)",
    menu_optional: "Factor file in addition to the passphrase (empty = none)",
    needed: "This additionally needs the factor file – path of the factor file",
    existing: "Existing factor file (create one with \"pqkeep factor\" or in the menu)",
    guide_use: "Additionally protect with a factor file (second factor, e.g. on a USB stick)?",
    guide_choice: "Use an existing factor file|Create a new factor file",
    guide_new: "File name of the new factor file",
    label: "Factor file",
    pick: "Pick the factor file (in addition to the passphrase)",
    filter: "All files (*)",
};

/// DE: Texte für `lang`. EN: Texts for `lang`.
pub fn ui_texts(lang: Lang) -> &'static UiTexts {
    if lang == Lang::De { &DE } else { &EN }
}

/// DE: Wonach gefragt wird. EN: What is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ask {
    /// DE: Eigene Schlüsseldatei. EN: Own key file.
    Key,
    /// DE: Faktordatei. EN: Factor file.
    Factor,
}

/// DE: Zusätzliche Argumente für `decrypt`. EN: Additional arguments for `decrypt`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Extra {
    /// DE: `--key <pfad>` und/oder `--factor-file <pfad>`. EN: `--key` and/or `--factor-file`.
    pub args: Vec<String>,
    /// DE: Entsperrt wird mit Schlüsseldatei. EN: Unlocking uses a key file.
    pub key: bool,
}

impl Extra {
    /// DE: Argumente als `&str`. EN: Arguments as `&str`.
    pub fn refs(&self) -> Vec<&str> {
        self.args.iter().map(String::as_str).collect()
    }
}

/// DE: Braucht diese Schlüsseldatei eine Faktordatei? Bei Lesefehlern `false` – den Fehler meldet
/// dann der eigentliche Befehl. EN: Does this key file need a factor file? `false` on read
/// errors – the actual command then reports the error.
pub fn key_needs(path: &Path) -> bool {
    envelope::load(path).is_ok_and(|(key, _)| key.needs_factor())
}

/// DE: Fragt genau das ab, was die Zugänge verlangen: Schlüsseldatei bei Empfänger-Dateien,
/// Faktordatei, wenn der Passphrase-Zugang oder die gewählte Schlüsseldatei sie braucht.
/// EN: Asks exactly for what the access slots require: key file for recipient files, factor file
/// if the passphrase slot or the chosen key file needs it.
pub fn plan(
    access: Access,
    key_needs: impl Fn(&Path) -> bool,
    mut ask: impl FnMut(Ask) -> CliResult<String>,
) -> CliResult<Extra> {
    let mut extra = Extra {
        args: Vec::new(),
        key: access.use_key(false),
    };
    let factor = if extra.key {
        let key = ask(Ask::Key)?;
        let needed = key_needs(Path::new(&key));
        extra.args.extend(["--key".to_owned(), key]);
        needed
    } else {
        access.passphrase == Some(true)
    };
    if factor {
        let path = ask(Ask::Factor)?;
        extra.args.extend([FLAG.to_owned(), path]);
    }
    Ok(extra)
}

/// DE: Wie [`plan`], liest dazu den Header von `source` (v1 oder v2).
/// EN: Like [`plan`], reading the header of `source` (v1 or v2) for it.
pub fn for_decrypt(
    source: &Path,
    lang: Lang,
    ask: impl FnMut(Ask) -> CliResult<String>,
) -> CliResult<Extra> {
    let access = Access::read(source).map_err(|e| Failure::from_error(&e, lang))?;
    plan(access, key_needs, ask)
}

#[cfg(test)]
#[path = "factor_ui_tests.rs"]
mod factor_ui_tests;
