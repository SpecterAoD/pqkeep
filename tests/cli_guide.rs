//! DE: Geführter Ablauf (G2) startet nie ohne Terminal oder mit `--batch`: fehlende Angaben
//! ergeben dann einen klaren Aufruffehler (Exit 2) – Skripte bleiben nie an einer Frage hängen.
//! EN: The guided flow (G2) never starts without a terminal or with `--batch`: missing input
//! then is a clear usage error (exit 2) – scripts never hang on a question.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

fn run(args: &[&str]) -> (i32, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut full = vec!["--lang", "en"];
    full.extend_from_slice(args);
    common::pqkeep(&full, "", dir.path())
}

#[test]
fn missing_input_without_terminal_is_a_usage_error() {
    for (args, hint) in [
        (&["generate"][..], "--name"),
        (&["generate", "--name", "Anna"], "--out"),
        (&["sign"], "--key"),
        (&["verify"], "--pub"),
        (&["--batch", "generate"], "--name"),
        (&["--batch", "sign"], "--key"),
    ] {
        let (code, out, err) = run(args);
        assert_eq!(code, 2, "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: {out}");
        assert!(err.contains(hint), "{args:?}: {err}");
    }
}
