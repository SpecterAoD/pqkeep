//! DE: Fallible Text-/JSON-Ausgabe ohne globale Hooks. EN: Fallible output without global hooks.

#![allow(clippy::unwrap_used)]

use super::*;

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
    }
}

#[test]
fn text_quotes_names_and_json_is_one_line() {
    let listing = Listing {
        entries: vec![files::ListEntry {
            path: "a\u{202e}b".into(),
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
