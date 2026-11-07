//! DE: Sandbox (SPEC Schritt 5a, nur Linux): Nach dem Start schränkt sich der Prozess
//! unumkehrbar ein. **Landlock** begrenzt Dateizugriffe (und TCP), **Seccomp-BPF**
//! begrenzt Systemaufrufe. Beides wirkt auf alle Threads, die *danach* entstehen;
//! deshalb muss [`apply`] vor dem Start weiterer Threads (z. B. tokio) laufen.
//!
//! - Landlock nicht verfügbar (alter Kernel): Warnung statt Abbruch.
//! - Seccomp auf nicht unterstützter Architektur (nur `x86_64`/`aarch64`): Warnung.
//! - Seccomp-Fehler auf unterstützter Architektur: Abbruch ([`Error::Sandbox`]).
//! - Windows: kein gleichwertiges Verfahren; [`apply`] meldet „nicht unterstützt“.
//!
//! EN: Sandbox (SPEC step 5a, Linux only): after start the process restricts itself
//! irreversibly. **Landlock** limits file access (and TCP), **seccomp-BPF** limits
//! system calls. Both apply to all threads created *afterwards*; hence [`apply`]
//! must run before further threads (e.g. tokio) are started.
//!
//! - Landlock unavailable (old kernel): warning instead of abort.
//! - Seccomp on an unsupported architecture (`x86_64`/`aarch64` only): warning.
//! - Seccomp failure on a supported architecture: abort ([`Error::Sandbox`]).
//! - Windows: no equivalent mechanism; [`apply`] reports "unsupported".

#[cfg(target_os = "linux")]
mod landlock;
#[cfg(target_os = "linux")]
mod seccomp;
#[cfg(target_os = "linux")]
mod syscalls;

#[cfg(target_os = "linux")]
use crate::Error;
use std::path::PathBuf;

use crate::Result;

/// DE: Einsatzprofil. EN: Usage profile.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Profile {
    /// DE: REST-API nach dem Binden des Sockets: kein Dateizugriff, keine neuen
    /// Sockets, nur `accept` auf dem vorhandenen.
    /// EN: REST API after binding the socket: no file access, no new sockets,
    /// only `accept` on the existing one.
    Api,
    /// DE: Ein CLI-Befehl: nur die genannten Pfade, Terminal, kein Netzwerk.
    /// EN: One CLI command: only the named paths, terminal, no network.
    Cli(CliAccess),
}

/// DE: Freigegebene Pfade eines CLI-Befehls. Alle Pfade müssen existieren.
/// EN: Permitted paths of a CLI command. All paths must exist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliAccess {
    /// DE: Nur lesen (Datei oder Ordner rekursiv). EN: Read only (file or directory recursively).
    pub read: Vec<PathBuf>,
    /// DE: Zielordner: anlegen, schreiben, umbenennen, entfernen (rekursiv).
    /// EN: Target directories: create, write, rename, remove (recursively).
    pub write_dirs: Vec<PathBuf>,
}

/// DE: Zustand einer Schutzschicht. EN: State of one protection layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// DE: Vollständig aktiv. EN: Fully active.
    Full,
    /// DE: Teilweise aktiv (älterer Kernel). EN: Partially active (older kernel).
    Partial,
    /// DE: Vom System nicht unterstützt. EN: Not supported by the system.
    Unsupported,
    /// DE: Vom Nutzer abgeschaltet (`--no-sandbox`). EN: Disabled by the user (`--no-sandbox`).
    Disabled,
}

impl Status {
    /// DE: Kurzname für Ausgaben. EN: Short name for output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
            Self::Unsupported => "unsupported",
            Self::Disabled => "disabled",
        }
    }
}

/// DE: Ergebnis von [`apply`]. EN: Result of [`apply`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxReport {
    /// DE: Landlock (Dateien, TCP). EN: Landlock (files, TCP).
    pub landlock: Status,
    /// DE: Seccomp (Systemaufrufe). EN: Seccomp (system calls).
    pub seccomp: Status,
}

impl SandboxReport {
    /// DE: Bericht für `--no-sandbox`. EN: Report for `--no-sandbox`.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            landlock: Status::Disabled,
            seccomp: Status::Disabled,
        }
    }

    /// DE: `true`, wenn beide Schichten vollständig aktiv sind.
    /// EN: `true` if both layers are fully active.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.landlock == Status::Full && self.seccomp == Status::Full
    }
}

/// DE: Aktiviert die Sandbox für `profile` (unumkehrbar, wirkt auf den aufrufenden
/// Thread und alle danach erzeugten).
/// EN: Enables the sandbox for `profile` (irreversible, applies to the calling thread
/// and all threads created afterwards).
///
/// # Errors
/// DE/EN: [`Error::Sandbox`], wenn eine Landlock-Regel nicht angelegt werden kann
/// oder Seccomp auf einer unterstützten Architektur scheitert / if a Landlock rule
/// cannot be created or seccomp fails on a supported architecture.
#[cfg(target_os = "linux")]
pub fn apply(profile: &Profile) -> Result<SandboxReport> {
    let landlock = landlock::restrict(profile).map_err(|()| Error::Sandbox)?;
    let seccomp = seccomp::install(profile).map_err(|()| Error::Sandbox)?;
    Ok(SandboxReport { landlock, seccomp })
}

/// DE: Nicht-Linux: keine Sandbox (dokumentierte Lücke).
/// EN: Non-Linux: no sandbox (documented gap).
///
/// # Errors
/// DE/EN: keine / none.
#[cfg(not(target_os = "linux"))]
pub fn apply(profile: &Profile) -> Result<SandboxReport> {
    let _ = profile;
    Ok(SandboxReport {
        landlock: Status::Unsupported,
        seccomp: Status::Unsupported,
    })
}
