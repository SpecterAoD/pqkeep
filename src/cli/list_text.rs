//! DE: Hilfetexte für die ausdrückliche Metadatenausgabe. EN: Explicit metadata-output help.

use pqkeep::security::Lang;

pub struct ListTexts {
    pub about: &'static str,
    pub after: &'static str,
    pub source: &'static str,
    pub json: &'static str,
    pub verified: &'static str,
    pub file: &'static str,
    pub directory: &'static str,
}

const DE: ListTexts = ListTexts {
    about: "Archivnamen und Größen erst nach vollständiger Prüfung anzeigen, ohne Extraktion",
    after: "Beispiele:\n  pqkeep list backup.pqkf\n  pqkeep list backup.pqkf --key backup.key.json --json\n\nZeigt bewusst vertrauliche Archivpfade und Größen auf stdout. Keine Dateiinhalte, keine Ausgabedatei oder Temporärdatei. Alle Inhalte werden vollständig geprüft; erst danach erscheint die Liste. Geprüfte Containerintegrität beweist keine Absenderidentität. Grenzen: 10.000 Einträge, 16 MiB UTF-8-Pfadbytes; bei Überschreitung keine Teilliste. Spalten: Typ, Bytes (- bei Ordner), zitierter Pfad. Zusammenfassung: Dateien / Ordner / Bytes. JSON: eigenes Schema pqkeep-list/1. Alte JSON-Befehle bleiben unverändert.",
    source: "Eine verschlüsselte Datei (.pqkf)",
    json: "Archivliste als JSON auf stdout (Schema pqkeep-list/1; enthält bewusst Archivpfade)",
    verified: "Containerintegrität vollständig geprüft; keine Bestätigung der Absenderidentität",
    file: "Datei",
    directory: "Ordner",
};

const EN: ListTexts = ListTexts {
    about: "Show archive names and sizes after complete verification, without extraction",
    after: "Examples:\n  pqkeep list backup.pqkf\n  pqkeep list backup.pqkf --key backup.key.json --json\n\nDeliberately exposes confidential archive paths and sizes on stdout. No file contents, output file or temporary file. All contents are checked completely before the list appears. Verified container integrity does not prove sender identity. Limits: 10,000 entries, 16 MiB UTF-8 path bytes; no partial list on overflow. Columns: kind, bytes (- for directory), quoted path. Summary: files / directories / bytes. JSON uses separate schema pqkeep-list/1. Existing JSON commands stay unchanged.",
    source: "One encrypted file (.pqkf)",
    json: "Archive list as JSON on stdout (schema pqkeep-list/1; deliberately includes archive paths)",
    verified: "Container integrity fully checked; sender identity is not established",
    file: "file",
    directory: "directory",
};

pub fn texts(lang: Lang) -> &'static ListTexts {
    match lang {
        Lang::De => &DE,
        Lang::En => &EN,
    }
}
