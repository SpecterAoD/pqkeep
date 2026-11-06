//! DE: Rauchtest: Das Binary startet und beendet sich erfolgreich.
//! EN: Smoke test: the binary starts and exits successfully.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

#[test]
fn binary_runs_and_prints_version() {
    let out = Command::new(env!("CARGO_BIN_EXE_keyforge"))
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}
