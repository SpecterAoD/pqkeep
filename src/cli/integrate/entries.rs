//! DE: Inhalte der Kontextmenü-Einträge für Nemo, Nautilus und Dolphin. Programm- und
//! Terminalpfade sind vorab geprüft (keine Anführungszeichen, Backticks, Dollar, Backslash, Prozent
//! und keine Steuerzeichen), daher genügt
//! einfaches Quoting. Der Dateiname aus dem Dateimanager steht immer nach `--` und als genau ein
//! Argument; `pqkeep context` akzeptiert genau einen Pfad, eingeschleuste Optionen sind so wirkungslos.
//! EN: Contents of the context menu entries for Nemo, Nautilus and Dolphin. Program and terminal
//! paths are checked beforehand (no quotes, backticks, dollar, backslash, percent and no control
//! characters), so simple quoting
//! suffices. The file name from the file manager always comes after `--` as exactly one argument;
//! `pqkeep context` accepts exactly one path, so injected options have no effect.

/// DE: Zeichen, die in Aktionsdateien oder Shell-Zeilen Sonderbedeutung haben.
/// EN: Characters with special meaning in action files or shell lines.
const FORBIDDEN: &[char] = &['"', '\'', '`', '$', '\\', '%'];

/// DE: Aktion im Menü. EN: Menu action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// DE/EN: Verschlüsseln (Dateien und Ordner) / encrypt (files and directories).
    Encrypt,
    /// DE/EN: Entschlüsseln (`.pqkf`) / decrypt (`.pqkf`).
    Decrypt,
}

impl Action {
    /// DE/EN: Argument für `pqkeep context` / argument for `pqkeep context`.
    pub fn arg(self) -> &'static str {
        match self {
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
        }
    }
}

/// DE: Terminal mit den Argumenten, nach denen der auszuführende Befehl folgt.
/// EN: Terminal with the arguments after which the command to run follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terminal {
    /// DE/EN: Absoluter Pfad / absolute path.
    pub path: String,
    /// DE/EN: z. B. `--` (gnome-terminal) oder `-e` / e.g. `--` or `-e`.
    pub exec_flag: &'static str,
}

/// DE: Start über ein Terminal oder direkt mit Fenstern (`context --dialog`).
/// EN: Start via a terminal or directly with windows (`context --dialog`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Launch<'a> {
    /// DE/EN: Terminal / terminal.
    Terminal(&'a Terminal),
    /// DE/EN: Fenster (zenity/kdialog) / windows (zenity/kdialog).
    Dialog,
}

/// DE: `true`, wenn der Pfad ohne Sonderzeichen sicher eingebettet werden kann.
/// EN: `true` if the path can be embedded safely without special characters.
pub fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && !path
            .chars()
            .any(|c| c.is_control() || FORBIDDEN.contains(&c))
}

/// DE: Nemo-Aktion (`Terminal=true`: Nemo öffnet das eingestellte Terminal; mit Fenstern `false`).
/// EN: Nemo action (`Terminal=true`: Nemo opens the configured terminal; with windows `false`).
pub fn nemo(action: Action, name: &str, comment: &str, bin: &str, dialog: bool) -> String {
    let extensions = match action {
        Action::Encrypt => "any;",
        Action::Decrypt => "pqkf;",
    };
    format!(
        "[Nemo Action]\n# pqkeep integrate – {remove}\nActive=true\nName={name}\nComment={comment}\n\
         Exec=\"{bin}\" context {flag}{arg} -- %F\nIcon-Name=dialog-password\nSelection=s\n\
         Extensions={extensions}\nTerminal={terminal}\n",
        remove = "pqkeep integrate uninstall",
        arg = action.arg(),
        flag = if dialog { "--dialog " } else { "" },
        terminal = !dialog,
    )
}

/// DE: Nautilus-Skript (Dateiname = Menüeintrag); bricht bei Mehrfachauswahl ab.
/// EN: Nautilus script (file name = menu entry); stops on multiple selection.
pub fn nautilus(action: Action, bin: &str, launch: Launch<'_>) -> String {
    let Launch::Terminal(term) = launch else {
        return format!(
            "#!/bin/sh\n# pqkeep integrate – pqkeep integrate uninstall\n[ \"$#\" -eq 1 ] || exit 0\n\
             exec '{bin}' context --dialog {arg} -- \"$1\"\n",
            arg = action.arg(),
        );
    };
    format!(
        "#!/bin/sh\n# pqkeep integrate – pqkeep integrate uninstall\n[ \"$#\" -eq 1 ] || exit 0\n\
         exec '{tp}' {flag} '{bin}' context {arg} -- \"$1\"\n",
        tp = term.path,
        flag = term.exec_flag,
        arg = action.arg(),
    )
}

/// DE: Dolphin-Service-Menü (KF5/KF6). EN: Dolphin service menu (KF5/KF6).
pub fn dolphin(action: Action, name: &str, bin: &str, launch: Launch<'_>) -> String {
    let mime = match action {
        Action::Encrypt => "all/allfiles;inode/directory;",
        Action::Decrypt => "all/allfiles;",
    };
    let exec = match launch {
        Launch::Terminal(term) => format!(
            "\"{tp}\" {flag} \"{bin}\" context {arg} -- %f",
            tp = term.path,
            flag = term.exec_flag,
            arg = action.arg()
        ),
        Launch::Dialog => format!("\"{bin}\" context --dialog {} -- %f", action.arg()),
    };
    format!(
        "[Desktop Entry]\n# pqkeep integrate – pqkeep integrate uninstall\nType=Service\n\
         X-KDE-ServiceTypes=KonqPopupMenu/Plugin\nMimeType={mime}\nActions=pqkeep_{arg};\n\n\
         [Desktop Action pqkeep_{arg}]\nName={name}\nIcon=dialog-password\nExec={exec}\n",
        arg = action.arg(),
    )
}

#[cfg(test)]
#[path = "entries_tests.rs"]
mod entries_tests;
