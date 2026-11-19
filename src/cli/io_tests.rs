#![allow(clippy::unwrap_used, clippy::expect_used)]

use dialoguer::theme::Theme;

use super::LocalTheme;

/// DE: Fehler bei der Passphrase-Wiederholung mit lokalisiertem Präfix statt „error:“ (#256).
/// EN: Passphrase confirmation error with a localised prefix instead of "error:" (#256).
#[test]
fn local_theme_uses_the_given_error_label() {
    let mut out = String::new();
    LocalTheme("Fehler")
        .format_error(&mut out, "Die Eingaben stimmen nicht überein.")
        .unwrap();
    assert_eq!(out, "Fehler: Die Eingaben stimmen nicht überein.");
    assert!(!out.contains("error:"));
}
