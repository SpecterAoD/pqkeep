//! DE: Thunars „Benutzerdefinierte Aktionen“ (`uca.xml`) als Text bearbeiten – ohne XML-Bibliothek
//! und bewusst streng: akzeptiert wird nur der Aufbau, den Thunar selbst schreibt (ein
//! `<actions>`-Rahmen, darin nicht verschachtelte `<action>`-Blöcke, keine Kommentare, DOCTYPE oder
//! CDATA). Alles andere gilt als unbekannt und wird nicht angefasst. Eigene Blöcke tragen eine feste
//! `<unique-id>`; fremde Blöcke bleiben Byte für Byte erhalten.
//! EN: Edit Thunar's "custom actions" (`uca.xml`) as text – without an XML library and deliberately
//! strict: only the layout Thunar itself writes is accepted (one `<actions>` frame containing
//! non-nested `<action>` blocks, no comments, DOCTYPE or CDATA). Anything else counts as unknown and
//! is left alone. Own blocks carry a fixed `<unique-id>`; foreign blocks are kept byte for byte.

use std::ops::Range;

use super::manifest::{FileState, digest};

/// DE: Größte akzeptierte Datei (1 MiB). EN: Largest accepted file (1 MiB).
pub const MAX_BYTES: usize = 1 << 20;

/// DE: Kopf, wie Thunar ihn schreibt. EN: Header as Thunar writes it.
const HEADER: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

const OPEN: &str = "<actions>";
const CLOSE: &str = "</actions>";
const BLOCK_OPEN: &str = "<action>";
const BLOCK_CLOSE: &str = "</action>";
const ID_OPEN: &str = "<unique-id>";
const ID_CLOSE: &str = "</unique-id>";

/// DE: Zeilen, die Thunar je nach Version schreibt oder weglässt (leer = ohne Bedeutung).
/// EN: Lines Thunar writes or omits depending on its version (empty = no meaning).
const OPTIONAL_LINES: [&str; 2] = ["\t<submenu></submenu>\n", "\t<range></range>\n"];

/// DE: Maskiert Text wie `GLib` (`g_markup_escape_text`). EN: Escapes text like `GLib` does.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&apos;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

/// DE: Leere Datei ohne Aktionen. EN: Empty file without actions.
pub fn empty() -> String {
    format!("{HEADER}{OPEN}\n{CLOSE}\n")
}

/// DE: Ausgangsdatei aus der systemweiten Vorgabe: deren Aktionen ab `<actions>`, mit neuem Kopf
/// (die Vorgabe beginnt mit DOCTYPE und Kommentar). `None`, wenn der Rest nicht dem strengen Aufbau
/// entspricht. EN: Starting file from the system-wide default: its actions from `<actions>` on, with
/// a fresh header (the default starts with a DOCTYPE and a comment). `None` if the rest does not
/// match the strict layout.
pub fn seed(system: &str) -> Option<String> {
    let start = system.find(OPEN)?;
    let doc = format!("{HEADER}{}", &system[start..]);
    valid(&doc).then_some(doc)
}

/// DE: Bereiche aller `<action>`-Blöcke mit ihrer `unique-id` (leer, wenn keine); `None`, wenn der
/// Aufbau nicht dem erwarteten entspricht.
/// EN: Ranges of all `<action>` blocks with their `unique-id` (empty if none); `None` if the layout
/// is not the expected one.
fn blocks(doc: &str) -> Option<Vec<(&str, Range<usize>)>> {
    let single = |pat: &str| doc.match_indices(pat).count() == 1;
    if doc.len() > MAX_BYTES || doc.contains("<!") || !single(OPEN) || !single(CLOSE) {
        return None;
    }
    let (open, close) = (doc.find(OPEN)?, doc.find(CLOSE)?);
    let head = doc[..open].trim();
    let head_ok = head.is_empty()
        || (head.starts_with("<?xml") && head.ends_with("?>") && head.matches('<').count() == 1);
    if !head_ok || close < open || !doc[close + CLOSE.len()..].trim().is_empty() {
        return None;
    }
    let mut out = Vec::new();
    let mut pos = open + OPEN.len();
    while let Some(offset) = doc[pos..close].find(BLOCK_OPEN) {
        let start = pos + offset;
        let inner = start + BLOCK_OPEN.len();
        let end = inner + doc[inner..close].find(BLOCK_CLOSE)?;
        let body = &doc[inner..end];
        if !doc[pos..start].trim().is_empty() || body.contains(BLOCK_OPEN) {
            return None;
        }
        out.push((block_id(body)?, start..end + BLOCK_CLOSE.len()));
        pos = end + BLOCK_CLOSE.len();
    }
    doc[pos..close].trim().is_empty().then_some(out)
}

/// DE: `unique-id` eines Blocks; mehr als eine ist ein Fehler. EN: A block's `unique-id`; more than
/// one is an error.
fn block_id(body: &str) -> Option<&str> {
    match body.matches(ID_OPEN).count() {
        0 => Some(""),
        1 => {
            let start = body.find(ID_OPEN)? + ID_OPEN.len();
            let len = body[start..].find(ID_CLOSE)?;
            Some(&body[start..start + len])
        }
        _ => None,
    }
}

/// DE: `true`, wenn die Datei den erwarteten Aufbau hat. EN: `true` if the file has the expected layout.
pub fn valid(doc: &str) -> bool {
    blocks(doc).is_some()
}

/// DE: Prüfsumme eines Blocks, unabhängig davon, ob Thunar ihn inzwischen neu geschrieben hat
/// (leere `<submenu>`-/`<range>`-Zeilen je nach Version).
/// EN: Checksum of a block, independent of Thunar having rewritten it meanwhile (empty
/// `<submenu>`/`<range>` lines depending on the version).
pub fn fingerprint(block: &str) -> String {
    let mut text = block.to_owned();
    for line in OPTIONAL_LINES {
        text = text.replace(line, "");
    }
    digest(text.as_bytes())
}

fn find(doc: &str, id: &str) -> Vec<Range<usize>> {
    let all = blocks(doc).unwrap_or_default();
    let own = all.into_iter().filter(|(found, _)| *found == id);
    own.map(|(_, range)| range).collect()
}

/// DE: Zustand des Blocks mit dieser `unique-id`: fehlt, eigener unveränderter (Prüfsumme wie
/// `recorded` oder wie `wanted`) oder fremd/geändert/doppelt.
/// EN: State of the block with this `unique-id`: missing, own and unchanged (checksum equals
/// `recorded` or `wanted`), or foreign/modified/duplicated.
pub fn state(doc: &str, id: &str, recorded: Option<&str>, wanted: Option<&str>) -> FileState {
    match find(doc, id).as_slice() {
        [] => FileState::Missing,
        [range] => {
            let current = fingerprint(&doc[range.clone()]);
            if [recorded, wanted].contains(&Some(current.as_str())) {
                FileState::Ours
            } else {
                FileState::Foreign
            }
        }
        _ => FileState::Foreign,
    }
}

/// DE: Ersetzt den Block mit dieser `unique-id` oder fügt ihn vor `</actions>` an.
/// EN: Replaces the block with this `unique-id` or appends it before `</actions>`.
pub fn upsert(doc: &str, id: &str, block: &str) -> String {
    if let Some(range) = find(doc, id).first() {
        return format!("{}{block}{}", &doc[..range.start], &doc[range.end..]);
    }
    let close = doc.find(CLOSE).unwrap_or(doc.len());
    let (before, after) = doc.split_at(close);
    let gap = if before.ends_with('\n') { "" } else { "\n" };
    format!("{before}{gap}{block}\n{after}")
}

/// DE: Entfernt den Block mit dieser `unique-id` samt Zeilenende.
/// EN: Removes the block with this `unique-id` including its line end.
pub fn remove(doc: &str, id: &str) -> String {
    let Some(range) = find(doc, id).into_iter().next() else {
        return doc.to_owned();
    };
    let rest = &doc[range.end..];
    format!(
        "{}{}",
        &doc[..range.start],
        rest.strip_prefix('\n').unwrap_or(rest)
    )
}

#[cfg(test)]
#[path = "uca_tests.rs"]
mod uca_tests;
