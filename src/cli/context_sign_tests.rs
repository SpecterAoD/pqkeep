#![allow(clippy::unwrap_used, clippy::expect_used)]

use pqkeep::security::Lang;

use super::signer_lines;
use crate::cli::signing::{menu_args, signed_by_label};

/// DE: Jeder Absender einmal, nur Absenderzeilen, leer ohne Signatur (#287).
/// EN: Each sender once, sender lines only, empty without a signature (#287).
#[test]
fn signer_lines_are_unique_and_only_present_for_signed_files() {
    let label = signed_by_label(Lang::De);
    let out = format!(
        "Entschlüsselt: a\n{label}: aaaa bbbb\nEntschlüsselt: b\n{label}: aaaa bbbb\n{label}: cccc dddd"
    );
    assert_eq!(
        signer_lines(Lang::De, &out),
        format!("\n\n{label}: aaaa bbbb\n{label}: cccc dddd")
    );
    assert_eq!(
        signer_lines(
            Lang::De,
            "Entschlüsselt: a\nDateien / Ordner / Bytes: 1 / 0 / 2"
        ),
        ""
    );
    // DE: Andere Sprache, andere Beschriftung. EN: Other language, other label.
    assert_eq!(signer_lines(Lang::En, &out), "");
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
