//! DE: Prozess- und Speicherhärtung (Spezifikation 3.1/5b), ohne eigenen
//! `unsafe`-Code: Core-Dump-Sperre (Linux über `rustix`) und Sperren von
//! Speicherseiten mit Geheimnissen (über `region`). Secret-Speichersperren sind zwingend;
//! die getrennte Prozesshärtung meldet OS-bedingte Grenzen im Bericht.
//! CLI-Start ruft [`harden_process`] auf; Bibliotheks-Embedder wählen ihre Host-Policy selbst.
//!
//! EN: Process and memory hardening (specification 3.1/5b), without own
//! `unsafe` code: core dump suppression (Linux via `rustix`) and locking of
//! memory pages holding secrets (via `region`). Secret locks are mandatory;
//! separate process hardening reports OS-dependent limits. CLI startup calls [`harden_process`];
//! library embedders explicitly choose their own host policy.

mod lock_registry;
mod lock_registry_storage;
pub mod memlock;
pub mod sandbox;

/// DE: Ergebnis der Prozesshärtung. EN: Result of process hardening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardeningReport {
    /// DE: Core-Dump-Größe auf 0 gesetzt. EN: Core dump size set to 0.
    pub core_dumps_disabled: bool,
    /// DE: Prozess nicht dumpbar (auch kein ptrace durch denselben Benutzer).
    /// EN: Process not dumpable (also no ptrace by the same user).
    pub not_dumpable: bool,
    /// DE: Windows-WER-NOHEAP bestätigt, keine vollständige Dumpsperre.
    /// EN: Windows WER NOHEAP confirmed, not a complete dump barrier.
    pub wer_heap_reporting_disabled: bool,
}

impl HardeningReport {
    /// DE: Linux-Core-/Dumpable-Schutz bestätigt; Windows-NOHEAP ist davon getrennt.
    /// EN: Linux core/dumpability protection confirmed; Windows NOHEAP is separate.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.core_dumps_disabled && self.not_dumpable
    }
}

/// DE: Sperrt Core Dumps für diesen Prozess (Linux). Unter Windows lässt sich die
/// Fehlerberichterstattung (WER) nicht zuverlässig vom Programm abschalten; siehe
/// `docs/MEMORY_HARDENING.md`. NOHEAP wird separat ergänzt und nachgeprüft.
/// Mehrfacher Aufruf ist unschädlich; beim Start vor anderen Policy-Änderungen aufrufen.
/// EN: Disables core dumps for this process (Linux). On Windows, error reporting
/// (WER) cannot be reliably disabled by the program; see `docs/MEMORY_HARDENING.md`.
/// NOHEAP is added and verified separately. Repeated calls are harmless; invoke during
/// startup before other host policy changes. Direct library calls do not harden implicitly.
#[must_use]
pub fn harden_process() -> HardeningReport {
    platform::harden()
}

/// DE: Liest aktuelle Prozessfähigkeiten ohne Änderung der Host-Policy.
/// Unbekannte/fehlgeschlagene Abfragen liefern keine bestätigte Fähigkeit.
/// Kein vollständiger Schutz gegen privilegierten Zugriff oder externe Dumps.
/// EN: Read current process capabilities without changing host policy.
/// Unknown/failed queries never confirm a capability. This is not complete
/// protection against privileged access or external dumps.
#[must_use]
pub fn observe_process() -> HardeningReport {
    platform::observe()
}

#[cfg(target_os = "linux")]
mod platform {
    use rustix::process::{
        DumpableBehavior, Resource, Rlimit, dumpable_behavior, set_dumpable_behavior, setrlimit,
    };

    use super::HardeningReport;

    pub(super) fn harden() -> HardeningReport {
        raise_lock_capability();
        let zero = Rlimit {
            current: Some(0),
            maximum: Some(0),
        };
        let core_set = setrlimit(Resource::Core, zero).is_ok();
        let dumpable_set = set_dumpable_behavior(DumpableBehavior::NotDumpable).is_ok();
        let actual = observe();
        HardeningReport {
            core_dumps_disabled: core_set && actual.core_dumps_disabled,
            not_dumpable: dumpable_set && actual.not_dumpable,
            wer_heap_reporting_disabled: false,
        }
    }

    pub(super) fn observe() -> HardeningReport {
        HardeningReport {
            core_dumps_disabled: pqkeep_platform::core_limits_disabled().unwrap_or(false),
            not_dumpable: matches!(dumpable_behavior(), Ok(DumpableBehavior::NotDumpable)),
            wer_heap_reporting_disabled: false,
        }
    }

    /// DE: Das Debian-Paket gibt `CAP_IPC_LOCK` nur als „permitted“ (#325): so startet das
    /// Programm auch dort, wo die Fähigkeit fehlt (Container), statt mit `EPERM` abzubrechen. Hier
    /// wird sie – falls erlaubt – für diesen Thread wirksam gemacht, vor allen weiteren Threads.
    /// Nichts sonst ändert sich; ohne sie gilt `RLIMIT_MEMLOCK` wie bisher.
    /// EN: The Debian package grants `CAP_IPC_LOCK` as "permitted" only (#325) so the program also
    /// starts where the capability is missing (containers) instead of failing with `EPERM`. Here it
    /// is made effective for this thread – if permitted – before any further threads. Nothing else
    /// changes; without it `RLIMIT_MEMLOCK` applies as before.
    fn raise_lock_capability() {
        use rustix::thread::{CapabilitySet, capabilities, set_capabilities};
        if let Ok(mut sets) = capabilities(None)
            && sets.permitted.contains(CapabilitySet::IPC_LOCK)
            && !sets.effective.contains(CapabilitySet::IPC_LOCK)
        {
            sets.effective |= CapabilitySet::IPC_LOCK;
            let _ = set_capabilities(None, sets);
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::HardeningReport;

    pub(super) fn harden() -> HardeningReport {
        HardeningReport {
            core_dumps_disabled: false,
            not_dumpable: false,
            wer_heap_reporting_disabled: pqkeep_platform::suppress_wer_heap_reporting().is_ok(),
        }
    }

    pub(super) fn observe() -> HardeningReport {
        HardeningReport {
            core_dumps_disabled: false,
            not_dumpable: false,
            wer_heap_reporting_disabled: matches!(
                pqkeep_platform::current_wer_flags(),
                Ok(pqkeep_platform::WerFlags::Present(flags)) if flags & 1 != 0
            ),
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use super::HardeningReport;

    pub(super) fn harden() -> HardeningReport {
        HardeningReport {
            core_dumps_disabled: false,
            not_dumpable: false,
            wer_heap_reporting_disabled: false,
        }
    }

    pub(super) fn observe() -> HardeningReport {
        harden()
    }
}
