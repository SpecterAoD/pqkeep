//! DE: Hinweise auf stderr, die für Menschen am Terminal gedacht sind. Fensterabläufe
//! (Kontextmenü) lesen die Fehlerausgabe ihres Kindprozesses und werten jede Zeile als Warnung:
//! Eine root-Warnung würde dort einen vollständigen Erfolg als „unvollständig“ anzeigen.
//! Der Kindprozess bekommt deshalb eine Markierung und lässt die root-Warnung weg.
//! EN: Notices on stderr meant for humans at a terminal. Window flows (context menu) read the
//! error output of their child process and treat every line as a warning: a root warning would
//! make a complete success look "incomplete" there. The child process therefore gets a marker
//! and leaves the root warning out.

use std::process::Command;

/// DE: Markierung für Kindprozesse der Fensterabläufe. EN: Marker for child processes of window flows.
pub const DIALOG_CHILD_ENV: &str = "PQKEEP_DIALOG_CHILD";

/// DE: Läuft dieser Prozess als Kind eines Fensterablaufs? EN: Is this process a child of a window flow?
pub fn is_dialog_child() -> bool {
    std::env::var_os(DIALOG_CHILD_ENV).is_some()
}

/// DE: Markiert einen Kindprozess eines Fensterablaufs. EN: Marks a child process of a window flow.
pub fn mark_dialog_child(cmd: &mut Command) {
    cmd.env(DIALOG_CHILD_ENV, "1");
}

/// DE: Soll die root-Warnung erscheinen? EN: Should the root warning appear?
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn root_warning_wanted(is_root: bool, dialog_child: bool) -> bool {
    is_root && !dialog_child
}

#[cfg(test)]
#[path = "notices_tests.rs"]
mod notices_tests;
