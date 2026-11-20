use super::wanted;
use crate::cli::text::texts;
use pqkeep::security::Lang;

/// DE: Der Hinweis erscheint nur bei Vorschau, auf einem Terminal und beim ersten Prozess.
/// EN: The notice appears only on a preview, on a terminal and in the first process.
#[test]
fn banner_only_for_preview_on_a_terminal_once() {
    assert!(wanted(true, true, false));
    assert!(!wanted(false, true, false), "never on betas and releases");
    assert!(!wanted(true, false, false), "not in scripts or pipes");
    assert!(
        !wanted(true, true, true),
        "not again in menu child processes"
    );
}

/// DE: Beide Sprachen haben einen Text, der Vorschau und Release-Abgrenzung nennt.
/// EN: Both languages have a text that names the preview and the difference to a release.
#[test]
fn banner_texts_exist_in_both_languages() {
    let de = texts(Lang::De).msg_preview_banner;
    let en = texts(Lang::En).msg_preview_banner;
    assert!(de.contains("VORSCHAU") && de.contains("Release"));
    assert!(en.contains("PREVIEW") && en.contains("release"));
}
