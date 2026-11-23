//! DE: Fallible Text-/JSON-Ausgabe ohne globale Hooks. EN: Fallible output without global hooks.

#![allow(clippy::unwrap_used)]

use super::*;
use serde_json::json;

struct FailedWriter {
    flush: bool,
}

impl Write for FailedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.flush {
            Ok(buf.len())
        } else {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::PermissionDenied.into())
    }
}

#[test]
fn text_and_json_propagate_write_and_flush_errors() {
    let listing = Listing {
        entries: Vec::new(),
        report: files::Report::default(),
    };
    for flush in [false, true] {
        let mut writer = FailedWriter { flush };
        assert!(write_text(&mut writer, &listing, Lang::En).is_err());
        assert!(write_json(&mut writer, &json!({"ok":true})).is_err());
        assert!(super::super::list_json::write(&mut writer, &listing, "fixture").is_err());
    }
}

/// DE: Neue Borrowed-Ausgabe erhält Schema und JSON-Escaping ohne Value-Pfadkopie.
/// EN: Borrowed output preserves the schema and escaping without a Value path copy.
#[test]
fn borrowed_list_output_preserves_the_existing_envelope() {
    let listing = Listing {
        entries: vec![files::ListEntry {
            path: files::ConfidentialText::from_text("ä/b\u{202e}").unwrap(),
            kind: EntryKind::File,
            bytes: Some(17),
        }],
        report: files::Report {
            files: 1,
            directories: 0,
            bytes: 17,
            ..files::Report::default()
        },
    };
    let mut out = Vec::new();
    super::super::list_json::write(&mut out, &listing, "source.pqkf").unwrap();
    assert_eq!(out.last(), Some(&b'\n'));
    assert_eq!(std::str::from_utf8(&out).unwrap().lines().count(), 1);
    assert_eq!(
        serde_json::from_slice::<Value>(&out).unwrap(),
        json!({
            "authentication":"container_integrity", "command":"list", "exit_code":0,
            "ok":true, "schema":SCHEMA, "source":"source.pqkf",
            "entries":[{"bytes":17,"kind":"file","path":"ä/b\u{202e}"}],
            "summary":{"bytes":17,"directories":0,"files":1}
        })
    );
    assert_eq!(format!("{listing:?}"), "Listing([REDACTED])");
}

#[test]
fn text_quotes_names_and_json_is_one_line() {
    let listing = Listing {
        entries: vec![files::ListEntry {
            path: files::ConfidentialText::from_text("a\u{202e}b").unwrap(),
            kind: EntryKind::File,
            bytes: Some(0),
        }],
        report: files::Report::default(),
    };
    let mut out = Vec::new();
    write_text(&mut out, &listing, Lang::En).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(!text.contains('\u{202e}'));
    let mut out = Vec::new();
    write_json(&mut out, &json!({"path":"ä/b"})).unwrap();
    assert_eq!(std::str::from_utf8(&out).unwrap().lines().count(), 1);
    assert_eq!(
        serde_json::from_slice::<Value>(&out).unwrap()["path"],
        "ä/b"
    );
}
