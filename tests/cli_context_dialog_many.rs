//! DE: Mehrfachauswahl im Fenster-Modus (Linux, Ersatz-zenity): jede einzeln, ein Container mit
//! frei gewähltem Namen, `auto` („Senden an“), mehrere entschlüsseln, Abbrechen mitten drin (keine
//! Reste), Wiederholen nur vor dem ersten Schreiben.
//! EN: Multi-selection in window mode (Linux, fake zenity): each separately, one container with a
//! freely chosen name, `auto` ("Send to"), decrypting several, cancelling midway (no leftovers),
//! retry only before the first write.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::fake_dialog::Env;

fn pass() -> String {
    common::random_passphrase().as_ref().expose_str().to_owned()
}

fn files(e: &Env, names: &[&str]) -> Vec<PathBuf> {
    names
        .iter()
        .map(|n| {
            let p = e.work().join(n);
            fs::write(&p, n.as_bytes()).unwrap();
            p
        })
        .collect()
}

fn refs(list: &[PathBuf]) -> Vec<&Path> {
    list.iter().map(PathBuf::as_path).collect()
}

fn names(dir: &Path) -> Vec<String> {
    let mut n: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    n.sort_unstable();
    n
}

fn last_call(e: &Env) -> String {
    e.calls().last().unwrap().join("\n")
}

#[test]
fn each_separately_then_decrypt_several() {
    let e = Env::new("zenity");
    let src = files(&e, &["a.txt", "b ä.txt", "c.txt"]);
    let p = pass();
    e.answer(&[(0, "0\n"), (0, "0\n"), (0, &format!("{p}\n{p}\n")), (0, "")]);
    assert_eq!(e.context_many("encrypt", &refs(&src)), 0);
    assert!(last_call(&e).contains("Done: 3 / 3"), "{:?}", e.calls());
    for s in &src {
        fs::remove_file(s).unwrap();
    }
    let enc: Vec<PathBuf> = ["a.txt.pqkf", "b ä.txt.pqkf", "c.txt.pqkf"]
        .iter()
        .map(|n| e.work().join(n))
        .collect();
    e.answer(&[(0, &format!("{p}\n")), (0, "")]);
    assert_eq!(e.context_many("decrypt", &refs(&enc)), 0);
    assert_eq!(
        fs::read(e.work().join("b ä.txt")).unwrap(),
        "b ä.txt".as_bytes()
    );
}

#[test]
fn container_with_free_name_and_auto_decrypt() {
    let e = Env::new("zenity");
    let src = files(&e, &["a.txt", "b.txt"]);
    let p = pass();
    e.answer(&[
        (0, "1\n"),
        (0, "Belege 2026\n"),
        (0, "0\n"),
        (0, &format!("{p}\n{p}\n")),
        (0, ""),
    ]);
    assert_eq!(e.context_many("encrypt", &refs(&src)), 0);
    let calls = e.calls();
    assert!(calls[1].contains(&"--entry".to_owned()), "{calls:?}");
    let container = e.work().join("Belege 2026.pqkf");
    assert!(container.is_file());
    e.answer(&[(0, &format!("{p}\n")), (0, "")]);
    assert_eq!(e.context_many("auto", &[&container]), 0);
    assert_eq!(names(&e.work().join("Belege 2026")), ["a.txt", "b.txt"]);
}

#[test]
fn auto_with_mixed_selection_encrypts_and_bad_name_is_refused() {
    let e = Env::new("zenity");
    let mut src = files(&e, &["a.txt"]);
    src.push(e.work().join("x.pqkf"));
    fs::write(&src[1], b"x").unwrap();
    e.answer(&[(0, "1\n"), (0, "../weg\n"), (0, "")]);
    assert_ne!(e.context_many("auto", &refs(&src)), 0);
    let calls = e.calls();
    assert!(calls[0].contains(&"--list".to_owned()), "{calls:?}");
    assert!(last_call(&e).contains("Invalid name"));
}

#[test]
fn cancel_midway_leaves_no_temporary_files() {
    let e = Env::new("zenity");
    let list: Vec<String> = (0..6).map(|i| format!("f{i}.txt")).collect();
    let src = files(&e, &list.iter().map(String::as_str).collect::<Vec<_>>());
    let p = pass();
    e.cancel_after("0.5");
    e.answer(&[(0, "0\n"), (0, "0\n"), (0, &format!("{p}\n{p}\n")), (0, "")]);
    assert_eq!(e.context_many("encrypt", &refs(&src)), 2);
    assert!(last_call(&e).contains("Cancelled"), "{:?}", e.calls());
    let left = names(e.work());
    assert!(left.iter().all(|n| !n.contains(".tmp-")), "{left:?}");
    let done = left
        .iter()
        .filter(|n| Path::new(n).extension().is_some_and(|x| x == "pqkf"))
        .count();
    assert!(done < 6, "{left:?}");
}

#[test]
fn weak_passphrase_may_be_retried_but_wrong_one_not() {
    let e = Env::new("zenity");
    let src = files(&e, &["a.txt", "b.txt"]);
    let p = pass();
    e.answer(&[
        (0, "0\n"),
        (0, "0\n"),
        (0, "abc\nabc\n"),
        (0, ""),
        (0, ""),
        (0, &format!("{p}\n{p}\n")),
        (0, ""),
    ]);
    assert_eq!(e.context_many("encrypt", &refs(&src)), 0);
    assert!(e.calls()[4].contains(&"--question".to_owned()));
    let enc = [e.work().join("a.txt.pqkf"), e.work().join("b.txt.pqkf")];
    e.answer(&[(0, &format!("{}\n", pass())), (0, "")]);
    assert_ne!(e.context_many("decrypt", &refs(&enc)), 0);
    let calls = e.calls();
    assert!(calls[1].contains(&"--error".to_owned()), "{calls:?}");
    assert_eq!(calls.len(), 2, "keine Wiederholung / no retry");
}
