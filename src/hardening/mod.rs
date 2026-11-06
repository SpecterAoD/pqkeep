//! DE: Prozess- und Speicherhärtung (Spezifikation 3.1/5b), ohne eigenen
//! `unsafe`-Code: Core-Dump-Sperre (Linux über `rustix`) und Sperren von
//! Speicherseiten mit Geheimnissen (über `region`). Alles „best effort“:
//! Fehlschläge brechen nicht ab, sondern werden im Bericht ausgewiesen.
//! CLI und API rufen [`harden_process`] als Erstes beim Start auf.
//!
//! EN: Process and memory hardening (specification 3.1/5b), without own
//! `unsafe` code: core dump suppression (Linux via `rustix`) and locking of
//! memory pages holding secrets (via `region`). All best effort: failures do
//! not abort but are reported. CLI and API call [`harden_process`] first thing.

pub mod memlock;

/// DE: Ergebnis der Prozesshärtung. EN: Result of process hardening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardeningReport {
    /// DE: Core-Dump-Größe auf 0 gesetzt. EN: Core dump size set to 0.
    pub core_dumps_disabled: bool,
    /// DE: Prozess nicht dumpbar (auch kein ptrace durch denselben Benutzer).
    /// EN: Process not dumpable (also no ptrace by the same user).
    pub not_dumpable: bool,
}

impl HardeningReport {
    /// DE: `true`, wenn alle Maßnahmen gegriffen haben. EN: `true` if all measures applied.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.core_dumps_disabled && self.not_dumpable
    }
}

/// DE: Sperrt Core Dumps für diesen Prozess (Linux). Unter Windows lässt sich die
/// Fehlerberichterstattung (WER) nicht zuverlässig vom Programm abschalten; siehe
/// `docs/MEMORY_HARDENING.md`. Mehrfacher Aufruf ist unschädlich.
/// EN: Disables core dumps for this process (Linux). On Windows, error reporting
/// (WER) cannot be reliably disabled by the program; see `docs/MEMORY_HARDENING.md`.
/// Calling it more than once is harmless.
#[must_use]
pub fn harden_process() -> HardeningReport {
    platform::harden()
}

#[cfg(target_os = "linux")]
mod platform {
    use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};

    use super::HardeningReport;

    pub(super) fn harden() -> HardeningReport {
        let zero = Rlimit {
            current: Some(0),
            maximum: Some(0),
        };
        HardeningReport {
            core_dumps_disabled: setrlimit(Resource::Core, zero).is_ok(),
            not_dumpable: set_dumpable_behavior(DumpableBehavior::NotDumpable).is_ok(),
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::HardeningReport;

    pub(super) fn harden() -> HardeningReport {
        HardeningReport {
            core_dumps_disabled: false,
            not_dumpable: false,
        }
    }
}
