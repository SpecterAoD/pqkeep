#![allow(clippy::unwrap_used, clippy::expect_used)]

use pqkeep::security::Lang;

use super::signer_lines;
use crate::cli::signing::{menu_args, signed_by_label};

/// DE: Jeder Absender einmal, aus den Steuerzeilen; leer ohne Signatur (#287).
/// EN: Each sender once, from the control lines; empty without a signature (#287).
#[test]
fn signer_lines_come_from_control_lines_only() {
    let label = signed_by_label(Lang::De);
    let a = "a".repeat(64);
    let b = "b".repeat(64);
    let shown = signer_lines(Lang::De, &[a.clone(), a, b]);
    assert_eq!(shown.matches(label).count(), 2, "{shown}");
    assert!(
        shown.starts_with("\n\n") && shown.contains("aaaa aaaa"),
        "{shown}"
    );
    assert_eq!(signer_lines(Lang::De, &[]), "");
}

/// DE: Steuerzeichen in Pfaden werden maskiert – ein Dateiname kann keine Zeile vortäuschen.
/// EN: Control characters in paths are escaped – a file name cannot fake a line.
#[test]
fn shown_paths_escape_control_characters() {
    let name = "x\nSigniert von (geprüft): 1234\r\u{1b}.txt";
    let out = crate::cli::files_cmd::shown(std::path::Path::new(name));
    assert!(
        !out.contains('\n') && !out.contains('\r') && !out.contains('\u{1b}'),
        "{out}"
    );
    assert!(out.contains("\\n"), "{out}");
}

/// DE: Menü: leer = nicht signieren; Schlüssel ohne Faktordatei = nur `--sign-with` (ob eine
/// Faktordatei nötig ist, prüft `factor_ui::key_needs`). EN: Menu: empty = do not sign; key without
/// factor file = only `--sign-with` (whether a factor file is needed is checked by `key_needs`).
#[test]
fn menu_asks_for_the_signing_key() {
    let mut argv = Vec::new();
    assert!(menu_args(Lang::En, |_| Ok(String::new()), &mut argv).is_ok());
    assert_eq!(argv, Vec::<String>::new());
    let mut asked = Vec::new();
    let r = menu_args(
        Lang::En,
        |p| {
            asked.push(p.to_owned());
            Ok("/nicht/vorhanden.key.json".to_owned())
        },
        &mut argv,
    );
    assert!(r.is_ok());
    assert_eq!(argv, ["--sign-with", "/nicht/vorhanden.key.json"]);
    assert_eq!(asked.len(), 1);
}
