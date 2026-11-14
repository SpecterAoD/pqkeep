//! DE: Mehrere Empfänger in Menü und Kontextmenü (#47): eine gemeinsame Sammelschleife – erster
//! Empfänger, dann „weiterer?“ bis Nein bzw. leer oder bis 64. Hier werden nur Pfade gesammelt;
//! Typ, Doppel und Anzahl prüft der Kindprozess (`recipients.rs`) und meldet Fehler, bevor etwas
//! geschrieben wird.
//! EN: Several recipients in menu and context menu (#47): one shared collecting loop – first
//! recipient, then "another?" until no/empty or up to 64. Only paths are collected here; kind,
//! duplicates and count are checked by the child process (`recipients.rs`), which reports errors
//! before anything is written.

use pqkeep::files::MAX_RECIPIENTS;
use pqkeep::security::Lang;

use super::io::CliResult;

/// DE: Texte. EN: Texts.
pub struct RecipientUiTexts {
    /// DE: Menü: weiterer Empfänger. EN: Menu: another recipient.
    pub menu_more: &'static str,
    /// DE: Kontextmenü: weiteren hinzufügen? EN: Context menu: add another?
    pub more: &'static str,
    /// DE: Menü: zusätzlich eigene Passphrase? EN: Menu: also an own passphrase?
    pub with_pass: &'static str,
}

const DE: RecipientUiTexts = RecipientUiTexts {
    menu_more: "Weiterer Empfänger (leer = fertig)",
    more: "Weiteren Empfänger hinzufügen?",
    with_pass: "Zusätzlich eine eigene Passphrase setzen (Format v2)?",
};

const EN: RecipientUiTexts = RecipientUiTexts {
    menu_more: "Another recipient (empty = done)",
    more: "Add another recipient?",
    with_pass: "Also set an own passphrase (format v2)?",
};

/// DE: Texte in der gewählten Sprache. EN: Texts in the chosen language.
pub fn texts(lang: Lang) -> &'static RecipientUiTexts {
    match lang {
        Lang::De => &DE,
        Lang::En => &EN,
    }
}

/// DE: Sammelt Empfänger ab `first`; `next` liefert den nächsten oder `None` (fertig). Bei 64 ist
/// Schluss, ohne weiter zu fragen. Abbruch (`Err`) bricht alles ab.
/// EN: Collects recipients starting with `first`; `next` returns the next one or `None` (done).
/// At 64 it stops without asking further. Cancelling (`Err`) aborts everything.
pub fn collect(
    first: String,
    mut next: impl FnMut() -> CliResult<Option<String>>,
) -> CliResult<Vec<String>> {
    let mut all = vec![first];
    while all.len() < MAX_RECIPIENTS {
        match next()? {
            Some(path) => all.push(path),
            None => break,
        }
    }
    Ok(all)
}

/// DE: `--to <pfad>` je Empfänger. EN: `--to <path>` per recipient.
pub fn to_args(paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .flat_map(|p| ["--to".to_owned(), p.clone()])
        .collect()
}

#[cfg(test)]
#[path = "recipients_ui_tests.rs"]
mod tests;
