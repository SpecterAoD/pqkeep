//! DE: Liste der von `pqkeep integrate` geschriebenen Dateien und Einträge samt SHA3-256. Nur unveränderte
//! eigene Dateien werden ersetzt oder entfernt; fremde oder vom Nutzer geänderte bleiben stehen.
//! EN: List of files and entries written by `pqkeep integrate` with SHA3-256. Only unchanged own files are
//! replaced or removed; foreign or user-modified files stay.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use pqkeep::envelope::hex_encode;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// DE: Ein geschriebener Eintrag. EN: One written entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// DE/EN: Absoluter Pfad / absolute path.
    pub path: PathBuf,
    /// DE/EN: SHA3-256 (hex) des Inhalts / of the content.
    pub sha3: String,
}

/// DE: Ein Eintrag in einer Datei, die auch fremde Einträge enthält (Thunar `uca.xml`).
/// EN: One entry inside a file that also holds foreign entries (Thunar `uca.xml`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Shared {
    /// DE/EN: Absoluter Pfad der Datei / absolute path of the file.
    pub path: PathBuf,
    /// DE/EN: Kennung des Eintrags (`unique-id`) / id of the entry (`unique-id`).
    pub id: String,
    /// DE/EN: SHA3-256 (hex) des Eintrags / of the entry.
    pub sha3: String,
}

/// DE: Gesamte Liste. EN: Whole list.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// DE/EN: Formatversion / format version.
    pub version: u32,
    /// DE/EN: Eingetragener Programmpfad / registered program path.
    pub binary: String,
    /// DE/EN: Geschriebene Dateien / written files.
    pub files: Vec<Entry>,
    /// DE: Start-Modus der Einträge (`dialog`/`terminal`; leer bei alten Listen).
    /// EN: Launch mode of the entries (`dialog`/`terminal`; empty for old lists).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mode: String,
    /// DE: Einträge in gemeinsamen Dateien (ab Version 2; fehlt in älteren Listen).
    /// EN: Entries inside shared files (since version 2; absent in older lists).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<Shared>,
}

/// DE/EN: SHA3-256 als Hex / SHA3-256 as hex.
pub fn digest(data: &[u8]) -> String {
    hex_encode(&Sha3_256::digest(data))
}

impl Manifest {
    /// DE: Lädt die Liste; fehlt sie, ist sie leer. EN: Loads the list; empty if missing.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        match fs::read(path) {
            Ok(data) => serde_json::from_slice(&data).map_err(|_| ErrorKind::InvalidData.into()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// DE/EN: Gespeicherte Prüfsumme einer Datei / stored checksum of a file.
    pub fn recorded(&self, path: &Path) -> Option<&str> {
        self.files
            .iter()
            .find(|e| e.path == path)
            .map(|e| e.sha3.as_str())
    }

    /// DE/EN: Eintrag setzen oder ersetzen / set or replace an entry.
    pub fn record(&mut self, path: &Path, sha3: String) {
        self.files.retain(|e| e.path != path);
        self.files.push(Entry {
            path: path.to_path_buf(),
            sha3,
        });
    }

    /// DE/EN: Gespeicherte Prüfsumme eines Eintrags / stored checksum of an entry.
    #[cfg(target_os = "linux")]
    pub fn recorded_entry(&self, path: &Path, id: &str) -> Option<&str> {
        let found = self.entries.iter().find(|e| e.path == path && e.id == id);
        found.map(|e| e.sha3.as_str())
    }

    /// DE/EN: Eintrag in gemeinsamer Datei setzen oder ersetzen / set or replace a shared entry.
    #[cfg(target_os = "linux")]
    pub fn record_entry(&mut self, path: &Path, id: &str, sha3: String) {
        self.entries.retain(|e| e.path != path || e.id != id);
        self.entries.push(Shared {
            path: path.to_path_buf(),
            id: id.to_owned(),
            sha3,
        });
    }

    /// DE: Formatversion: 2, sobald Einträge in gemeinsamen Dateien vorkommen, sonst 1.
    /// EN: Format version: 2 as soon as entries in shared files exist, otherwise 1.
    #[cfg(target_os = "linux")]
    pub fn current_version(&self) -> u32 {
        if self.entries.is_empty() { 1 } else { 2 }
    }
}

/// DE: Zustand einer Zieldatei. EN: State of a target file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileState {
    /// DE/EN: Existiert nicht / does not exist.
    Missing,
    /// DE/EN: Eigene, unveränderte Datei / own unchanged file.
    Ours,
    /// DE/EN: Fremd oder geändert – nicht anfassen / foreign or modified – do not touch.
    Foreign,
}

/// DE: Ermittelt den Zustand anhand der Liste. EN: Determines the state from the list.
#[cfg(target_os = "linux")]
pub fn state(manifest: &Manifest, path: &Path) -> std::io::Result<FileState> {
    match fs::read(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(FileState::Missing),
        Err(e) => Err(e),
        Ok(data) => Ok(match manifest.recorded(path) {
            Some(h) if h == digest(&data) => FileState::Ours,
            _ => FileState::Foreign,
        }),
    }
}
