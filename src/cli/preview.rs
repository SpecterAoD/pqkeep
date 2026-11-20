//! DE: Hinweis bei Vorschau-Builds (`docs/RELEASE.md`). Er erscheint auf stderr, nur wenn stderr
//! ein Terminal ist (Skripte und `--json` bleiben unberührt), und einmal je Menüsitzung: Die
//! Kindprozesse des Menüs erben eine Markierung und zeigen ihn nicht noch einmal.
//! EN: Notice for preview builds (`docs/RELEASE.md`). It appears on stderr, only when stderr is a
//! terminal (scripts and `--json` stay untouched), and once per menu session: the menu's child
//! processes inherit a marker and do not show it again.

use std::io::IsTerminal;

use pqkeep::build_info;

use super::text::Texts;

/// DE: Markierung für Kindprozesse. EN: Marker for child processes.
pub const SHOWN_ENV: &str = "PQKEEP_PREVIEW_BANNER_SHOWN";

/// DE: Soll der Hinweis erscheinen? EN: Should the notice appear?
pub fn wanted(preview: bool, terminal: bool, already_shown: bool) -> bool {
    preview && terminal && !already_shown
}

/// DE: Zeigt den Hinweis, falls nötig. EN: Shows the notice if needed.
pub fn show(t: &Texts) {
    let shown = std::env::var_os(SHOWN_ENV).is_some();
    if wanted(
        build_info::is_preview(),
        std::io::stderr().is_terminal(),
        shown,
    ) {
        eprintln!("{}", t.msg_preview_banner);
    }
}

/// DE: Kindprozess des Menüs: Markierung nur bei Vorschau-Builds setzen (Releases unverändert).
/// EN: Menu child process: set the marker on preview builds only (releases unchanged).
pub fn mark_child(cmd: &mut std::process::Command) {
    if build_info::is_preview() {
        cmd.env(SHOWN_ENV, "1");
    }
}

#[cfg(test)]
#[path = "preview_tests.rs"]
mod preview_tests;
