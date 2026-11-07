//! DE: Rauchtest: Das Binary startet; `--version` liefert die Version, ohne
//! Argumente erscheint die Hilfe mit Exit-Code 2.
//! EN: Smoke test: the binary starts; `--version` prints the version, without
//! arguments the help appears with exit code 2.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

#[test]
fn version_and_no_args() {
    let dir = std::env::temp_dir();
    let (code, out, _) = common::keyforge(&["--version"], "", &dir);
    assert_eq!(code, 0);
    assert!(out.contains(env!("CARGO_PKG_VERSION")));
    let (code, _, err) = common::keyforge(&["--lang", "en"], "", &dir);
    assert_eq!(code, 2);
    assert!(err.contains("generate"));
}
