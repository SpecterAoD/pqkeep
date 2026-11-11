#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{MAX_BYTES, empty, escape, fingerprint, remove, seed, state, upsert, valid};
use crate::cli::integrate::manifest::FileState;

/// DE: Datei, wie Thunar 4.18 sie schreibt, mit einer fremden Aktion.
/// EN: File as Thunar 4.18 writes it, with one foreign action.
const FOREIGN: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<actions>\n<action>\n\
    \t<icon>utilities-terminal</icon>\n\t<name>Terminal &amp; mehr</name>\n\t<submenu></submenu>\n\
    \t<unique-id>1700000000000000-1</unique-id>\n\t<command>exo-open --launch TerminalEmulator %f</command>\n\
    \t<description></description>\n\t<range></range>\n\t<patterns>*</patterns>\n\t<directories/>\n\
    </action>\n</actions>\n";

fn block(id: &str, name: &str) -> String {
    format!(
        "<action>\n\t<name>{}</name>\n\t<submenu></submenu>\n\t<unique-id>{id}</unique-id>\n\
         \t<range></range>\n</action>",
        escape(name)
    )
}

#[test]
fn escape_matches_glib() {
    assert_eq!(
        escape("a&b<c>d'e\"f ü"),
        "a&amp;b&lt;c&gt;d&apos;e&quot;f ü"
    );
}

#[test]
fn only_the_layout_thunar_writes_is_accepted() {
    assert!(valid(FOREIGN) && valid(&empty()));
    assert!(valid("<actions>\n  <action>\n  </action>\n\n</actions>"));
    let bad = [
        String::new(),
        "<actions>".to_owned(),
        FOREIGN.replace("<actions>", "<!-- x -->\n<actions>"),
        FOREIGN.replace("<actions>", "<!DOCTYPE actions>\n<actions>"),
        FOREIGN.replace("<icon>", "<![CDATA[<action>]]><icon>"),
        FOREIGN.replace("<icon>", "<action><icon>"),
        FOREIGN.replace("</actions>", "</actions><actions></actions>"),
        FOREIGN.replace("</actions>\n", "</actions>\nMüll"),
        FOREIGN.replace("<actions>\n", "<actions>\nText"),
        FOREIGN.replace("</action>\n", "</action>\n<other/>\n"),
        FOREIGN.replace("<actions>", "<actions version=\"2\">"),
        FOREIGN.replace("<?xml", "<x/><?xml"),
        FOREIGN.replace("<range>", "<unique-id>2</unique-id><range>"),
        FOREIGN.replace("</action>\n", ""),
        format!("{FOREIGN}{}", " ".repeat(MAX_BYTES)),
    ];
    for doc in bad {
        assert!(!valid(&doc), "{}", &doc[..doc.len().min(200)]);
    }
}

#[test]
fn own_blocks_are_added_and_removed_without_touching_foreign_bytes() {
    let (enc, dec) = (block("pqkeep-encrypt", "E"), block("pqkeep-decrypt", "D"));
    let doc = upsert(
        &upsert(FOREIGN, "pqkeep-encrypt", &enc),
        "pqkeep-decrypt",
        &dec,
    );
    assert!(valid(&doc));
    let foreign_part = &FOREIGN[..FOREIGN.len() - "</actions>\n".len()];
    assert!(doc.starts_with(foreign_part) && doc.ends_with("</action>\n</actions>\n"));
    // DE: Ersetzen an Ort und Stelle. EN: Replacing in place.
    let changed = upsert(&doc, "pqkeep-encrypt", &block("pqkeep-encrypt", "Neu"));
    assert!(changed.find("Neu").unwrap() < changed.find("pqkeep-decrypt").unwrap());
    assert_eq!(changed.matches("pqkeep-encrypt").count(), 1);
    let back = remove(&remove(&changed, "pqkeep-decrypt"), "pqkeep-encrypt");
    assert_eq!(back, FOREIGN);
    assert_eq!(remove(FOREIGN, "pqkeep-encrypt"), FOREIGN);
    // DE: Datei ohne Zeilenende vor dem Abschluss. EN: File without a line end before the close.
    assert!(valid(&upsert(
        "<actions></actions>",
        "pqkeep-encrypt",
        &enc
    )));
}

#[test]
fn state_distinguishes_missing_own_and_foreign() {
    let enc = block("pqkeep-encrypt", "E");
    let sum = fingerprint(&enc);
    let doc = upsert(FOREIGN, "pqkeep-encrypt", &enc);
    let st = |d: &str, rec: Option<&str>| state(d, "pqkeep-encrypt", rec, None);
    assert_eq!(st(FOREIGN, Some(&sum)), FileState::Missing);
    assert_eq!(st(&doc, Some(&sum)), FileState::Ours);
    assert_eq!(st(&doc, None), FileState::Foreign);
    assert_eq!(
        state(&doc, "pqkeep-encrypt", None, Some(&sum)),
        FileState::Ours
    );
    assert_eq!(
        st(&doc.replace("<name>E<", "<name>Mein<"), Some(&sum)),
        FileState::Foreign
    );
    // DE: Doppelte Kennung: nicht anfassen. EN: Duplicated id: do not touch.
    let twice = doc.replace("</actions>", &format!("{enc}\n</actions>"));
    assert_eq!(st(&twice, Some(&sum)), FileState::Foreign);
    // DE: Von Thunar 4.16 neu geschrieben (ohne submenu/range): weiterhin unser Eintrag.
    // EN: Rewritten by Thunar 4.16 (no submenu/range): still our entry.
    let old = doc
        .replace("\t<submenu></submenu>\n", "")
        .replace("\t<range></range>\n", "");
    assert_ne!(old, doc);
    assert_eq!(st(&old, Some(&sum)), FileState::Ours);
}

#[test]
fn hostile_names_cannot_break_out_of_the_block() {
    let nasty = "</name></action><action><command>rm -rf ~</command>&amp;<!--";
    let doc = upsert(FOREIGN, "pqkeep-encrypt", &block("pqkeep-encrypt", nasty));
    assert!(valid(&doc));
    assert_eq!(doc.matches("<action>").count(), 2);
    assert_eq!(doc.matches("<command>").count(), 1);
}

#[test]
fn seed_takes_the_actions_of_the_system_default() {
    let system = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE actions [\n  <!ELEMENT actions (action)+>\n]>\n\n\
        <!--\n  Default\n-->\n\n<actions>\n\n  <action>\n    <icon>utilities-terminal</icon>\n    \
        <name>Open Terminal Here</name>\n    <name xml:lang=\"de\">Terminal hier öffnen</name>\n  </action>\n\n</actions>\n";
    let doc = seed(system).unwrap();
    assert!(valid(&doc) && doc.contains("Terminal hier öffnen") && !doc.contains("<!"));
    assert!(seed("kein XML").is_none());
    assert!(seed("<actions><!-- x --></actions>").is_none());
}
