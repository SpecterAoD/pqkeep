//! DE: Geprüfte Pfade als Borrowed Views direkt serialisieren, ohne Value-Kopien.
//! EN: Serialize verified paths as borrowed views directly, without Value copies.

use pqkeep::files::{EntryKind, ListEntry, Listing};
use serde::{Serialize, Serializer, ser::SerializeSeq};
use std::io::{self, Write};

struct Entries<'a>(&'a [ListEntry]);

#[derive(Serialize)]
struct Entry<'a> {
    bytes: Option<u64>,
    kind: &'static str,
    path: &'a str,
}

impl Serialize for Entries<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for entry in self.0 {
            let path = entry
                .path
                .expose()
                .map_err(|_| serde::ser::Error::custom("invalid protected archive path"))?;
            let kind = match entry.kind {
                EntryKind::File => "file",
                EntryKind::Directory => "directory",
            };
            sequence.serialize_element(&Entry {
                bytes: entry.bytes,
                kind,
                path,
            })?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct Summary {
    bytes: u64,
    directories: u64,
    files: u64,
}

#[derive(Serialize)]
struct Envelope<'a> {
    authentication: &'static str,
    command: &'static str,
    entries: Entries<'a>,
    exit_code: u8,
    ok: bool,
    schema: &'static str,
    source: &'a str,
    summary: Summary,
}

pub(super) fn write(out: &mut impl Write, listing: &Listing, source: &str) -> io::Result<()> {
    let report = &listing.report;
    let envelope = Envelope {
        authentication: "container_integrity",
        command: "list",
        entries: Entries(&listing.entries),
        exit_code: 0,
        ok: true,
        schema: super::list_cmd::SCHEMA,
        source,
        summary: Summary {
            bytes: report.bytes,
            directories: report.directories,
            files: report.files,
        },
    };
    serde_json::to_writer(&mut *out, &envelope).map_err(io::Error::other)?;
    out.write_all(b"\n")?;
    out.flush()
}
