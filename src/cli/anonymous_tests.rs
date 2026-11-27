#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

fn args(high: bool, paths: &[String]) -> Vec<String> {
    // DE: Rückfrage darf nicht kommen. EN: The question must not be asked.
    let never = || -> CliResult<bool> { Err(Failure::new(code::ERROR, "Rückfrage / question")) };
    deselect_args(high, paths, never).ok().unwrap()
}

#[test]
fn deselect_only_with_level_and_suitable_recipients() {
    assert_eq!(args(false, &["x.pub.json".into()]), Vec::<String>::new());
    assert_eq!(args(true, &[]), Vec::<String>::new());
    // DE: Nicht lesbare Schlüssel: keine Rückfrage (Fehler meldet der Kindprozess).
    // EN: Unreadable keys: no question (the child process reports the error).
    assert_eq!(
        args(true, &["/nicht/da.pub.json".into()]),
        Vec::<String>::new()
    );
    assert!(!possible(&[]));
}

#[test]
fn question_names_experimental_and_deselect() {
    for lang in [Lang::De, Lang::En] {
        let q = keep_question(lang);
        assert!(q.contains("EXPERIMENT") && q.contains("#340"), "{q}");
    }
    assert!(keep_question(Lang::De).contains("abwählen"));
    assert!(keep_question(Lang::En).contains("deselect"));
}
