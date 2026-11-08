//! DE: Argumentlisten für die Fenster-Werkzeuge zenity und kdialog (reine Funktionen, ohne
//! Prozessstart, daher überall testbar). Texte gehen immer als eigenes Argument hinein, nie über
//! eine Shell; zenity zeigt Texte mit `--no-markup` wörtlich an.
//! EN: Argument lists for the window tools zenity and kdialog (pure functions without starting
//! processes, hence testable anywhere). Texts are always passed as separate arguments, never via a
//! shell; zenity shows texts literally with `--no-markup`.

/// DE: Unterstütztes Werkzeug. EN: Supported tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// GNOME/GTK (`zenity`)
    Zenity,
    /// KDE/Qt (`kdialog`)
    Kdialog,
}

/// DE: Eine Anfrage an das Werkzeug. EN: One request to the tool.
#[derive(Debug, Clone, Copy)]
pub enum Request<'a> {
    /// DE: Auswahl aus einer Liste; Ausgabe = Index. EN: Choice from a list; output = index.
    Choose { text: &'a str, items: &'a [&'a str] },
    /// DE: Datei öffnen mit Filter (z. B. `*.pub.json`); `prompt` wird Fenstertitel.
    /// EN: Open a file with filter (e.g. `*.pub.json`); `prompt` becomes the window title.
    OpenFile {
        prompt: &'a str,
        start: &'a str,
        pattern: &'a str,
        label: &'a str,
    },
    /// DE: Ja/Nein; Ja = Exit-Code 0. EN: Yes/no; yes = exit code 0.
    Question { text: &'a str },
    /// DE/EN: Hinweis / information.
    Info { text: &'a str },
    /// DE/EN: Warnung / warning.
    Warning { text: &'a str },
    /// DE/EN: Fehler / error.
    Error { text: &'a str },
    /// DE: Passphrase einmal. EN: Passphrase once.
    Password { text: &'a str },
    /// DE: Neue Passphrase mit Wiederholung. EN: New passphrase with repetition.
    NewPassword {
        text: &'a str,
        first: &'a str,
        second: &'a str,
    },
    /// DE: Pulsierender Fortschritt (nur zenity). EN: Pulsating progress (zenity only).
    Progress { text: &'a str },
}

impl Kind {
    /// DE: Gibt kdialog bei `NewPassword` nur eine Zeile aus (vergleicht selbst)?
    /// EN: Does kdialog output only one line for `NewPassword` (compares itself)?
    pub fn confirms_itself(self) -> bool {
        self == Self::Kdialog
    }
}

fn owned(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

/// DE: Argumente für `kind`; `None`, wenn das Werkzeug die Anfrage nicht kennt.
/// EN: Arguments for `kind`; `None` if the tool does not support the request.
pub fn args(kind: Kind, title: &str, req: &Request<'_>) -> Option<Vec<String>> {
    let title = match *req {
        Request::OpenFile { prompt, .. } => prompt,
        _ => title,
    };
    match kind {
        Kind::Zenity => Some(zenity(title, req)),
        Kind::Kdialog => kdialog(title, req),
    }
}

fn zenity(title: &str, req: &Request<'_>) -> Vec<String> {
    let mut a = vec![format!("--title={title}")];
    match *req {
        Request::Choose { text, items } => zenity_list(&mut a, text, items),
        Request::OpenFile {
            start,
            pattern,
            label,
            ..
        } => {
            a.push("--file-selection".to_owned());
            a.push(format!("--filename={start}/"));
            a.push(format!("--file-filter={label} | {pattern}"));
            a.push("--file-filter=* | *".to_owned());
        }
        Request::Question { text } => a.extend([q("--question"), nm(), t(text)]),
        Request::Info { text } => a.extend([q("--info"), nm(), t(text)]),
        Request::Warning { text } => a.extend([q("--warning"), nm(), t(text)]),
        Request::Error { text } => a.extend([q("--error"), nm(), t(text)]),
        Request::Password { .. } => a.push("--password".to_owned()),
        Request::NewPassword {
            text,
            first,
            second,
        } => {
            a.extend([q("--forms"), t(text)]);
            a.push(format!("--add-password={first}"));
            a.push(format!("--add-password={second}"));
            a.push("--separator=\n".to_owned());
        }
        Request::Progress { text } => {
            a.extend(owned(&[
                "--progress",
                "--pulsate",
                "--auto-close",
                "--no-cancel",
            ]));
            a.push(t(text));
        }
    }
    a
}

/// DE: Liste mit verborgener Index-Spalte; ausgegeben wird der Index.
/// EN: List with a hidden index column; the index is printed.
fn zenity_list(a: &mut Vec<String>, text: &str, items: &[&str]) {
    a.extend(owned(&[
        "--list",
        "--hide-header",
        "--width=480",
        "--height=260",
    ]));
    a.extend(owned(&["--column=n", "--column=label", "--hide-column=1"]));
    a.push("--print-column=1".to_owned());
    a.push(format!("--text={text}"));
    for (i, item) in items.iter().enumerate() {
        a.push(i.to_string());
        a.push((*item).to_owned());
    }
}

fn q(flag: &str) -> String {
    flag.to_owned()
}

fn nm() -> String {
    "--no-markup".to_owned()
}

fn t(text: &str) -> String {
    format!("--text={text}")
}

fn kdialog(title: &str, req: &Request<'_>) -> Option<Vec<String>> {
    let mut a = owned(&["--title", title]);
    match *req {
        Request::Choose { text, items } => {
            a.extend(owned(&["--menu", text]));
            for (i, item) in items.iter().enumerate() {
                a.push(i.to_string());
                a.push((*item).to_owned());
            }
        }
        Request::OpenFile {
            start,
            pattern,
            label,
            ..
        } => a.extend([
            q("--getopenfilename"),
            start.to_owned(),
            format!("{pattern}|{label}"),
        ]),
        Request::Question { text } => a.extend(owned(&["--yesno", text])),
        Request::Info { text } => a.extend(owned(&["--msgbox", text])),
        Request::Warning { text } => a.extend(owned(&["--sorry", text])),
        Request::Error { text } => a.extend(owned(&["--error", text])),
        Request::Password { text } => a.extend(owned(&["--password", text])),
        Request::NewPassword { text, .. } => a.extend(owned(&["--newpassword", text])),
        Request::Progress { .. } => return None,
    }
    Some(a)
}

#[cfg(test)]
#[path = "args_tests.rs"]
mod args_tests;
