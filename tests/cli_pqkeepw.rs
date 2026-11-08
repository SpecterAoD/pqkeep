//! DE: Startprogramm `pqkeepw`: unter Windows reicht es an `pqkeep context --dialog` weiter
//! (ohne Argumente → Bedienfehler 2, kein Fenster), anderswo beendet es sich mit 2.
//! EN: Launcher `pqkeepw`: on Windows it hands over to `pqkeep context --dialog` (without
//! arguments → usage error 2, no window), elsewhere it exits with 2.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::{Command, Stdio};

#[test]
fn launcher_without_arguments_is_a_usage_error() {
    let status = Command::new(env!("CARGO_BIN_EXE_pqkeepw"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
}
