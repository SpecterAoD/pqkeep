//! DE: Faktordatei im geführten Ablauf „Schlüssel erstellen“: vorhandene Datei verwenden oder
//! eine neue erzeugen lassen (`pqkeep factor`). Der Ablauf kennt nur den Pfad, nie den Inhalt.
//! EN: Factor file in the guided flow "create a key": use an existing file or have a new one
//! created (`pqkeep factor`). The flow only knows the path, never the content.

use std::path::Path;

use pqkeep::security::Lang;

use super::keygen::suggest;
use super::text::guide_texts;
use super::{confirm, input, path, select};
use crate::cli::factor_cmd::FLAG;
use crate::cli::factor_ui::ui_texts;
use crate::cli::io::CliResult;

/// DE: Gewählte Faktordatei. EN: Chosen factor file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactorPlan {
    pub path: String,
    /// DE: Erst erzeugen (`pqkeep factor`). EN: Create it first (`pqkeep factor`).
    pub create: bool,
}

impl FactorPlan {
    /// DE: Argumente für `pqkeep factor`, falls neu. EN: Arguments for `pqkeep factor` if new.
    pub fn create_args(&self) -> Option<Vec<String>> {
        self.create
            .then(|| ["factor", "--out", &self.path].map(str::to_owned).to_vec())
    }

    /// DE: `--factor-file <pfad>` für `generate`. EN: `--factor-file <path>` for `generate`.
    pub fn use_args(&self) -> [String; 2] {
        [FLAG.to_owned(), self.path.clone()]
    }

    /// DE: Zeile für die Zusammenfassung. EN: Line for the summary.
    pub fn summary(&self, lang: Lang) -> String {
        format!("{}: {}", ui_texts(lang).label, self.path)
    }
}

/// DE: Fragt nach der Faktordatei (Vorgabe: keine). `given` = schon per `--factor-file` gewählt.
/// EN: Asks for the factor file (default: none). `given` = already chosen with `--factor-file`.
pub fn ask(lang: Lang, name: &str, given: Option<String>) -> CliResult<Option<FactorPlan>> {
    let (g, f) = (guide_texts(lang), ui_texts(lang));
    if let Some(path) = given {
        return Ok(Some(FactorPlan {
            path,
            create: false,
        }));
    }
    if !confirm(f.guide_use, false)? {
        return Ok(None);
    }
    let choices: Vec<&str> = f.guide_choice.split('|').collect();
    if select(f.label, &choices, 0)? == 0 {
        let path = path(f.label, None, true, g.not_found)?;
        return Ok(Some(FactorPlan {
            path,
            create: false,
        }));
    }
    // DE: Eine Faktordatei wird nie überschrieben – so lange fragen, bis der Name frei ist.
    // EN: A factor file is never overwritten – ask until the name is free.
    loop {
        let default = suggest(Path::new("."), name, ".factor");
        let path = input(f.guide_new, Some(&default), false)?;
        if !Path::new(&path).exists() {
            return Ok(Some(FactorPlan { path, create: true }));
        }
        eprintln!("{}", g.exists);
    }
}
