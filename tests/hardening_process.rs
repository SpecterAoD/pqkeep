//! DE: Prozesshärtung: Core Dumps gesperrt, Prozess nicht dumpbar (Linux).
//! Eigene Testdatei, da die Einstellungen den ganzen Testprozess betreffen.
//! EN: Process hardening: core dumps disabled, process not dumpable (Linux).
//! Own test file because the settings affect the whole test process.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use pqkeep::hardening::harden_process;

#[test]
fn harden_process_applies_and_is_idempotent() {
    let first = harden_process();
    let second = harden_process();
    assert_eq!(first, second);
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{DumpableBehavior, Resource, dumpable_behavior, getrlimit};
        assert!(first.complete(), "{first:?}");
        let core = getrlimit(Resource::Core);
        assert_eq!(core.current, Some(0));
        assert_eq!(core.maximum, Some(0));
        assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
    }
    #[cfg(not(target_os = "linux"))]
    {
        // DE: Außerhalb von Linux nur dokumentiert (siehe docs/MEMORY_HARDENING.md).
        // EN: Outside Linux only documented (see docs/MEMORY_HARDENING.md).
        assert!(!first.complete());
    }
}
