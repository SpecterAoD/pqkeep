use super::{
    BUILD_ID, CHANNEL, format_version, is_preview, is_preview_channel, version_line, window_title,
};
use crate::VERSION;

/// DE: Ohne Kanal bleibt die Versionszeile exakt die Cargo-Version (Betas, Releases).
/// EN: Without a channel the version line stays exactly the Cargo version (betas, releases).
#[test]
fn no_channel_keeps_the_plain_version() {
    assert_eq!(format_version("0.1.0-beta.3", None, None), "0.1.0-beta.3");
    assert_eq!(
        format_version("0.1.0-beta.3", None, Some("20261123.a1b2c3d")),
        "0.1.0-beta.3"
    );
}

/// DE: Nur `preview` kennzeichnet eine Vorschau; andere Werte ändern nichts.
/// EN: Only `preview` marks a preview; other values change nothing.
#[test]
fn only_the_preview_channel_marks_a_preview() {
    assert!(is_preview_channel(Some("preview")));
    assert!(!is_preview_channel(Some("release")));
    assert!(!is_preview_channel(Some("")));
    assert!(!is_preview_channel(None));
    assert_eq!(format_version("1.0.0", Some("nightly"), Some("x")), "1.0.0");
}

/// DE: Vorschau mit Kennung ergibt `+preview.<Kennung>` (SemVer-Build-Metadaten).
/// EN: A preview with an identifier gives `+preview.<id>` (`SemVer` build metadata).
#[test]
fn preview_adds_build_metadata() {
    assert_eq!(
        format_version("0.1.0-beta.3", Some("preview"), Some("20261123.a1b2c3d")),
        "0.1.0-beta.3+preview.20261123.a1b2c3d"
    );
    assert_eq!(
        format_version("0.1.0-beta.3", Some("preview"), None),
        "0.1.0-beta.3+preview"
    );
}

/// DE: Ungültige Kennungen (leer, zu lang, Steuerzeichen, Leerzeichen) werden nicht ausgegeben.
/// EN: Invalid identifiers (empty, too long, control characters, spaces) are not printed.
#[test]
fn invalid_identifiers_are_dropped() {
    let long = "a".repeat(41);
    for bad in ["", "a b", "a\nb", "a\x1b[31m", "ä", long.as_str()] {
        assert_eq!(
            format_version("1.0.0", Some("preview"), Some(bad)),
            "1.0.0+preview",
            "{bad:?}"
        );
    }
    let max = "a".repeat(40);
    assert_eq!(
        format_version("1.0.0", Some("preview"), Some(&max)),
        format!("1.0.0+preview.{max}")
    );
}

/// DE: Ein Standard-Build (ohne Build-Variablen) trägt nie einen Kanal.
/// EN: A default build (without the build variables) never carries a channel.
#[test]
fn default_build_has_no_channel() {
    if CHANNEL.is_none() {
        assert!(!is_preview());
        assert_eq!(version_line(), VERSION);
        assert_eq!(window_title("PQKeep"), "PQKeep");
        assert!(BUILD_ID.is_none() || !is_preview());
    } else {
        assert!(version_line().starts_with(VERSION));
    }
}

/// DE: Die Versionszeile eines Vorschau-Builds enthält immer `+preview`.
/// EN: The version line of a preview build always contains `+preview`.
#[test]
fn preview_build_is_visible_in_the_version_line() {
    if is_preview() {
        assert!(version_line().contains("+preview"));
        assert!(window_title("PQKeep").contains("PREVIEW"));
    }
}
