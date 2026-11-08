//! DE: Planung für `integrate` unter Windows, ohne Registry-Zugriff (daher auch unter Linux
//! testbar): Menüeinträge („Verben“) unter `HKCU\Software\Classes`, Prüfung des Programmpfads und
//! eine eindeutige Textform eines Eintrags für die Prüfsumme im Manifest.
//! EN: Planning for `integrate` on Windows without registry access (hence testable on Linux too):
//! menu entries ("verbs") under `HKCU\Software\Classes`, program path check and an unambiguous
//! text form of an entry for the checksum in the manifest.

use crate::cli::integrate_text::IntegrateTexts;

/// DE: Name des Unterschlüssels mit der Befehlszeile. EN: Name of the subkey with the command line.
pub const COMMAND_KEY: &str = "command";

/// DE: Ein geplanter Menüeintrag. EN: One planned menu entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verb {
    /// DE: Pfad relativ zur Klassen-Wurzel. EN: Path relative to the classes root.
    pub path: String,
    /// DE: Werte (`REG_SZ`) des Verb-Schlüssels. EN: Values (`REG_SZ`) of the verb key.
    pub values: Vec<(String, String)>,
    /// DE: Befehlszeile (Standardwert von `command`). EN: Command line (default value of `command`).
    pub command: String,
}

/// DE: Gelesener Zustand eines Eintrags (Werte als Name, Typ, Daten). EN: Read state of an entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub values: Vec<(String, String, String)>,
    pub subkeys: Vec<String>,
    pub command_values: Vec<(String, String, String)>,
    pub command_subkeys: Vec<String>,
}

/// DE: Typkennung für `REG_SZ` in der Textform. EN: Type tag for `REG_SZ` in the text form.
pub const SZ: &str = "sz";

impl Verb {
    /// DE: Zustand, wie ihn `install` hinterlässt. EN: State as left behind by `install`.
    pub fn snapshot(&self) -> Snapshot {
        let sz = |(n, d): &(String, String)| (n.clone(), SZ.to_owned(), d.clone());
        Snapshot {
            values: self.values.iter().map(sz).collect(),
            subkeys: vec![COMMAND_KEY.to_owned()],
            command_values: vec![(String::new(), SZ.to_owned(), self.command.clone())],
            command_subkeys: Vec::new(),
        }
    }
}

impl Snapshot {
    /// DE: Eindeutige Textform (sortiert, Felder mit Längenpräfix). Groß-/Kleinschreibung der
    /// Namen zählt nicht (wie in der Registry).
    /// EN: Unambiguous text form (sorted, length-prefixed fields). Name case does not matter
    /// (as in the registry).
    pub fn canonical(&self) -> String {
        let field = |s: &str| format!("{}:{s};", s.len());
        let vals = |v: &[(String, String, String)]| {
            let mut v: Vec<String> = v
                .iter()
                .map(|(n, t, d)| field(&n.to_lowercase()) + &field(t) + &field(d))
                .collect();
            v.sort();
            v.concat()
        };
        let keys = |k: &[String]| {
            let mut k: Vec<String> = k.iter().map(|n| field(&n.to_lowercase())).collect();
            k.sort();
            k.concat()
        };
        format!(
            "v{}|k{}|cv{}|ck{}",
            vals(&self.values),
            keys(&self.subkeys),
            vals(&self.command_values),
            keys(&self.command_subkeys)
        )
    }
}

/// DE: Plant alle Einträge: Dateien und Ordner verschlüsseln, `.pqkf` entschlüsseln. Nur
/// Einzelauswahl (`MultiSelectModel=Single`), Mehrfachauswahl folgt mit U4-4. Der Pfad aus dem
/// Explorer steht als genau ein Argument nach `--`.
/// EN: Plans all entries: encrypt files and folders, decrypt `.pqkf`. Single selection only
/// (`MultiSelectModel=Single`), multi-selection follows with U4-4. The path from Explorer is
/// exactly one argument after `--`.
pub fn plan(s: &IntegrateTexts, bin: &str, launcher: Option<&str>) -> Vec<Verb> {
    // DE: Mit Startprogramm (`pqkeepw.exe`): Fenster ohne Konsole; es ergänzt `context --dialog`.
    // EN: With launcher (`pqkeepw.exe`): windows without a console; it adds `context --dialog`.
    let command = |action: &str| match launcher {
        Some(w) => format!("\"{w}\" {action} -- \"%1\""),
        None => format!("\"{bin}\" context {action} -- \"%1\""),
    };
    let verb = |path: &str, action: &str, name: &str| Verb {
        path: path.to_owned(),
        values: vec![
            ("MUIVerb".to_owned(), name.to_owned()),
            ("Icon".to_owned(), format!("{bin},0")),
            ("MultiSelectModel".to_owned(), "Single".to_owned()),
        ],
        command: command(action),
    };
    vec![
        verb(r"*\shell\PQKeep.Encrypt", "encrypt", s.name_encrypt),
        verb(r"Directory\shell\PQKeep.Encrypt", "encrypt", s.name_encrypt),
        verb(
            r"SystemFileAssociations\.pqkf\shell\PQKeep.Decrypt",
            "decrypt",
            s.name_decrypt,
        ),
    ]
}

/// DE: Programmpfad geeignet? Absolut mit Laufwerksbuchstabe (kein Netzpfad, kein `\\?\`),
/// endet auf `.exe`, keine Zeichen `"` `%` oder Steuerzeichen, nicht unter einem Temp-Ordner.
/// EN: Program path suitable? Absolute with drive letter (no network path, no `\\?\`), ends in
/// `.exe`, no `"` `%` or control characters, not below a temp folder.
pub fn safe_windows_path(path: &str, temp_dirs: &[String]) -> bool {
    let b = path.as_bytes();
    let drive = b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
    let clean = !path.chars().any(|c| c == '"' || c == '%' || c.is_control());
    let lower = path.to_lowercase();
    let exe = std::path::Path::new(path)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("exe"));
    let in_temp = temp_dirs.iter().filter(|t| !t.is_empty()).any(|t| {
        let t = t.trim_end_matches('\\').to_lowercase();
        lower.starts_with(&(t + "\\"))
    });
    drive && clean && exe && !in_temp
}

#[cfg(test)]
#[path = "winplan_tests.rs"]
mod winplan_tests;
