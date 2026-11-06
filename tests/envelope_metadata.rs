//! DE: Metadaten: Pflichtfeld, Längen, Steuerzeichen, NFC; Zeitstempel RFC 3339.
//! EN: Metadata: required field, lengths, control characters, NFC; RFC 3339 timestamps.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::unnecessary_wraps)]

use pqc_keyforge::Error;
use pqc_keyforge::envelope::time::{format_unix, parse_rfc3339};
use pqc_keyforge::envelope::{MAX_ACCOUNT_TYPE_CHARS, MAX_FIELD_CHARS, Metadata};

fn err(field: &'static str) -> Option<Error> {
    Some(Error::InvalidInput { field })
}

#[test]
fn valid_metadata() {
    let m = Metadata {
        name: "Jürgen Müller".to_owned(),
        organization: Some("Stadtwerke Süd".to_owned()),
        company: Some("Beispiel GmbH & Co. KG".to_owned()),
        department: Some("IT/Sicherheit".to_owned()),
        account_type: Some("Dienstkonto".to_owned()),
    };
    assert!(m.validate().is_ok());
    assert_eq!(m.normalized().unwrap(), m);
}

#[test]
fn name_required_and_not_blank() {
    for bad in ["", "   ", "\t"] {
        assert_eq!(
            Metadata::with_name(bad).validate().err(),
            err("name"),
            "{bad:?}"
        );
    }
}

#[test]
fn length_limits_in_characters() {
    let ok = "ä".repeat(MAX_FIELD_CHARS);
    assert!(Metadata::with_name(&ok).validate().is_ok());
    let long = "ä".repeat(MAX_FIELD_CHARS + 1);
    assert_eq!(Metadata::with_name(&long).validate().err(), err("name"));
    let mut m = Metadata::with_name("x");
    m.account_type = Some("a".repeat(MAX_ACCOUNT_TYPE_CHARS + 1));
    assert_eq!(m.validate().err(), err("account_type"));
}

#[test]
fn control_characters_and_empty_optionals_rejected() {
    let mut m = Metadata::with_name("x");
    m.department = Some("IT\nAdmin".to_owned());
    assert_eq!(m.validate().err(), err("department"));
    let mut m = Metadata::with_name("x");
    m.company = Some(String::new());
    assert_eq!(m.validate().err(), err("company"));
    assert_eq!(Metadata::with_name("a\u{0}b").validate().err(), err("name"));
}

#[test]
fn non_nfc_rejected_on_read_but_normalised_on_create() {
    let m = Metadata::with_name("Jose\u{301}");
    assert_eq!(m.validate().err(), err("name"));
    assert_eq!(m.normalized().unwrap().name, "Jos\u{e9}");
}

#[test]
fn rfc3339_roundtrip_and_known_values() {
    assert_eq!(format_unix(0), "1970-01-01T00:00:00Z");
    assert_eq!(format_unix(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(format_unix(1_793_995_200), "2026-11-06T20:00:00Z");
    assert_eq!(format_unix(253_402_300_799), "9999-12-31T23:59:59Z");
    for secs in [0, 59, 86_399, 951_782_400, 1_709_164_800, 4_102_444_800] {
        assert_eq!(parse_rfc3339(&format_unix(secs)).unwrap(), secs);
    }
}

#[test]
fn rfc3339_strict() {
    for bad in [
        "2026-11-06T18:00:00+01:00",
        "2026-11-06T18:00:00.5Z",
        "2026-11-06t18:00:00z",
        "2026-11-6T18:00:00Z",
        "2026-02-29T00:00:00Z",
        "1900-02-29T00:00:00Z",
        "1969-12-31T23:59:59Z",
        "2026-11-06T24:00:00Z",
        "2026-11-06T18:60:00Z",
        "2026-11-06T18:00:60Z",
        "+026-11-06T18:00:00Z",
        "２026-11-06T18:00:00Z",
    ] {
        assert!(parse_rfc3339(bad).is_err(), "{bad}");
    }
    assert!(parse_rfc3339("2024-02-29T00:00:00Z").is_ok());
    assert!(parse_rfc3339("2000-02-29T00:00:00Z").is_ok());
}
