//! DE: Tests (U01, #47): Sammelschleife für mehrere Empfänger in Menü und Kontextmenü.
//! EN: Tests (U01, #47): collecting loop for several recipients in menu and context menu.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use pqkeep::files::MAX_RECIPIENTS;
use pqkeep::security::Lang;

use super::{collect, texts, to_args};
use crate::cli::io::Failure;

#[test]
fn u01_collects_in_order_until_done() {
    let mut answers = vec![Some("/k/b.pub.json"), Some("/k/c.pub.json"), None].into_iter();
    let mut asked = 0;
    let all = collect("/k/a.pub.json".to_owned(), || {
        asked += 1;
        Ok(answers.next().unwrap().map(str::to_owned))
    })
    .ok()
    .unwrap();
    assert_eq!(all, ["/k/a.pub.json", "/k/b.pub.json", "/k/c.pub.json"]);
    assert_eq!(asked, 3);
    assert_eq!(
        to_args(&all[..2]),
        ["--to", "/k/a.pub.json", "--to", "/k/b.pub.json"]
    );
}

#[test]
fn u01_single_recipient_and_limit() {
    let one = collect("a".to_owned(), || Ok(None)).ok().unwrap();
    assert_eq!(one, ["a"]);
    // DE: Bei 64 wird nicht weiter gefragt. EN: At 64 nothing more is asked.
    let mut asked = 0;
    let all = collect("0".to_owned(), || {
        asked += 1;
        Ok(Some(asked.to_string()))
    })
    .ok()
    .unwrap();
    assert_eq!(all.len(), MAX_RECIPIENTS);
    assert_eq!(asked, MAX_RECIPIENTS - 1);
}

#[test]
fn u01_cancelling_aborts_everything() {
    let mut calls = 0;
    let result = collect("a".to_owned(), || {
        calls += 1;
        if calls == 1 {
            Ok(Some("b".to_owned()))
        } else {
            Err(Failure::new(2, ""))
        }
    });
    assert!(result.is_err());
}

#[test]
fn u01_texts_in_both_languages() {
    assert!(texts(Lang::De).more.contains("Empfänger"));
    assert!(texts(Lang::En).more.contains("recipient"));
    assert!(texts(Lang::De).menu_more.contains("leer"));
    assert!(texts(Lang::En).with_pass.contains("passphrase"));
}
