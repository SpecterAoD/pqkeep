//! DE: Tests der Argumentlisten für zenity und kdialog. EN: Tests of the zenity/kdialog arguments.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

fn z(req: &Request<'_>) -> Vec<String> {
    args(Kind::Zenity, "PQKeep", req).unwrap()
}

fn k(req: &Request<'_>) -> Vec<String> {
    args(Kind::Kdialog, "PQKeep", req).unwrap()
}

#[test]
fn zenity_messages_are_literal() {
    let text = "<b>bericht & co</b>.pdf";
    for req in [
        Request::Info { text },
        Request::Warning { text },
        Request::Error { text },
        Request::Question { text },
    ] {
        let a = z(&req);
        assert_eq!(a[0], "--title=PQKeep");
        assert!(a.contains(&"--no-markup".to_owned()), "{a:?}");
        assert!(a.contains(&format!("--text={text}")));
    }
}

#[test]
fn choose_lists_index_and_label() {
    let items = ["Mit Passphrase", "Für einen Empfänger"];
    let a = z(&Request::Choose {
        text: "Wie?",
        items: &items,
    });
    assert!(a.ends_with(&[
        "0".to_owned(),
        items[0].to_owned(),
        "1".to_owned(),
        items[1].to_owned()
    ]));
    assert!(a.contains(&"--print-column=1".to_owned()));
    let a = k(&Request::Choose {
        text: "Wie?",
        items: &items,
    });
    assert_eq!(&a[2..4], ["--menu", "Wie?"]);
    assert_eq!(&a[4..], ["0", items[0], "1", items[1]]);
}

#[test]
fn open_file_uses_filter_and_start_folder() {
    let req = Request::OpenFile {
        prompt: "Schlüssel wählen",
        start: "/home/anna/Schlüssel",
        pattern: "*.pub.json",
        label: "Öffentliche Schlüssel",
    };
    let a = z(&req);
    assert_eq!(a[0], "--title=Schlüssel wählen");
    assert!(a.contains(&"--filename=/home/anna/Schlüssel/".to_owned()));
    assert!(a.contains(&"--file-filter=Öffentliche Schlüssel | *.pub.json".to_owned()));
    let a = k(&req);
    assert_eq!(&a[..2], ["--title", "Schlüssel wählen"]);
    assert_eq!(
        &a[2..],
        [
            "--getopenfilename",
            "/home/anna/Schlüssel",
            "*.pub.json|Öffentliche Schlüssel"
        ]
    );
}

#[test]
fn new_password_asks_twice_with_newline_separator() {
    let req = Request::NewPassword {
        text: "Neue Passphrase",
        first: "Passphrase",
        second: "Wiederholen",
    };
    let a = z(&req);
    assert!(a.contains(&"--forms".to_owned()));
    assert!(a.contains(&"--add-password=Passphrase".to_owned()));
    assert!(a.contains(&"--add-password=Wiederholen".to_owned()));
    assert!(a.contains(&"--separator=\n".to_owned()));
    assert!(!Kind::Zenity.confirms_itself());
    assert_eq!(&k(&req)[2..], ["--newpassword", "Neue Passphrase"]);
    assert!(Kind::Kdialog.confirms_itself());
}

#[test]
fn password_and_progress() {
    assert!(z(&Request::Password { text: "x" }).contains(&"--password".to_owned()));
    assert_eq!(
        &k(&Request::Password { text: "x" })[2..],
        ["--password", "x"]
    );
    let p = z(&Request::Progress {
        text: "Bitte warten",
        cancel: false,
    });
    assert!(p.contains(&"--no-cancel".to_owned()));
    assert!(p.contains(&"--pulsate".to_owned()) && p.contains(&"--auto-close".to_owned()));
    assert!(
        args(
            Kind::Kdialog,
            "PQKeep",
            &Request::Progress {
                text: "x",
                cancel: true
            }
        )
        .is_none()
    );
}

#[test]
fn warning_uses_the_tools_warning_window() {
    assert!(z(&Request::Warning { text: "x" }).contains(&"--warning".to_owned()));
    assert_eq!(&k(&Request::Warning { text: "x" })[2..], ["--sorry", "x"]);
}

#[test]
fn texts_starting_with_dash_stay_values() {
    // DE: Bei zenity hängt der Text am Schalter (`--text=…`), bei kdialog folgt er ihm.
    // EN: zenity attaches the text to the flag (`--text=…`), kdialog puts it after the flag.
    let a = z(&Request::Info { text: "--version" });
    assert!(a.contains(&"--text=--version".to_owned()));
    let a = k(&Request::Info { text: "--version" });
    assert_eq!(&a[2..], ["--msgbox", "--version"]);
}

#[test]
fn entry_and_cancelable_progress() {
    let req = Request::Entry {
        text: "Name",
        default: "Steuer 2026.pqkf",
    };
    let a = z(&req);
    assert!(a.contains(&"--entry".to_owned()));
    assert!(a.contains(&"--entry-text=Steuer 2026.pqkf".to_owned()));
    assert_eq!(&k(&req)[2..], ["--inputbox", "Name", "Steuer 2026.pqkf"]);
    let p = z(&Request::Progress {
        text: "x",
        cancel: true,
    });
    assert!(!p.contains(&"--no-cancel".to_owned()));
}
