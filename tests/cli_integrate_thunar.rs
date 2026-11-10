//! DE: `pqkeep integrate` für Thunar (Xfce) mit temporärem `XDG_CONFIG_HOME`: Aktionen in
//! `Thunar/uca.xml` eintragen, mit fremden Aktionen zusammenführen, Sicherung, Wiederholen,
//! Entfernen (Byte für Byte wie vorher), geänderte Einträge und unbekannte Dateien bleiben
//! unberührt, Vorgabe des Systems als Ausgangspunkt, sichere Befehlszeile.
//! EN: `pqkeep integrate` for Thunar (Xfce) with a temporary `XDG_CONFIG_HOME`: add actions to
//! `Thunar/uca.xml`, merge with foreign actions, backup, repeat, uninstall (byte for byte as
//! before), modified entries and unknown files stay untouched, system default as the starting
//! point, safe command line.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_pqkeep");

/// DE: Datei, wie Thunar 4.18 sie schreibt, mit einer fremden Aktion.
/// EN: File as Thunar 4.18 writes it, with one foreign action.
const FOREIGN: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<actions>\n<action>\n\
    \t<icon>utilities-terminal</icon>\n\t<name>Terminal &amp; mehr</name>\n\t<submenu></submenu>\n\
    \t<unique-id>1700000000000000-1</unique-id>\n\t<command>exo-open --launch TerminalEmulator %f</command>\n\
    \t<description></description>\n\t<range></range>\n\t<patterns>*</patterns>\n\t<directories/>\n\
    </action>\n</actions>\n";

struct Env {
    dir: tempfile::TempDir,
    fake: PathBuf,
    uca: PathBuf,
}

/// DE: Gefälschte Programme; sie schreiben ihre Argumente NUL-getrennt nach `$RECORD`.
/// EN: Fake programs; they write their arguments NUL-separated to `$RECORD`.
fn env(programs: &[&str]) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let fake = dir.path().join("fakebin");
    fs::create_dir(&fake).unwrap();
    for p in programs {
        let path = fake.join(p);
        fs::write(&path, "#!/bin/sh\nprintf '%s\\0' \"$@\" > \"$RECORD\"\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    Env {
        uca: dir.path().join("config/Thunar/uca.xml"),
        fake,
        dir,
    }
}

fn run(e: &Env, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(BIN)
        .args(["--lang", "en"])
        .args(args)
        .env("HOME", e.dir.path())
        .env("XDG_DATA_HOME", e.dir.path().join("data"))
        .env("XDG_CONFIG_HOME", e.dir.path().join("config"))
        .env("XDG_CONFIG_DIRS", e.dir.path().join("xdg"))
        .env("PATH", &e.fake)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (
        out.status.code().unwrap_or(-1),
        s(&out.stdout),
        s(&out.stderr),
    )
}

fn put(path: &Path, content: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn backups(e: &Env) -> usize {
    let dir = fs::read_dir(e.uca.parent().unwrap()).unwrap();
    dir.filter(|f| {
        let name = f.as_ref().unwrap().file_name();
        name.to_string_lossy().starts_with("uca.xml.pqkeep-bak_")
    })
    .count()
}

fn manifest(e: &Env) -> String {
    fs::read_to_string(e.dir.path().join("data/pqkeep/integration.json")).unwrap_or_default()
}

#[test]
fn install_creates_the_file_and_uninstall_empties_it_again() {
    let e = env(&["thunar", "xfce4-terminal", "gnome-terminal"]);
    let (code, out, err) = run(&e, &["integrate", "install"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.matches("Set up").count(), 2, "{out}");
    let doc = fs::read_to_string(&e.uca).unwrap();
    let bin = fs::canonicalize(BIN).unwrap();
    let term = e.fake.join("xfce4-terminal");
    let command = format!(
        "<command>&quot;{}&quot; -x &quot;{}&quot; context encrypt -- %F</command>",
        term.display(),
        bin.display()
    );
    assert!(doc.contains(&command), "{doc}");
    assert!(doc.contains("<unique-id>pqkeep-decrypt</unique-id>") && doc.contains("*.pqkf"));
    assert_eq!(
        fs::metadata(&e.uca).unwrap().permissions().mode() & 0o777,
        0o644
    );
    let m = manifest(&e);
    assert!(
        m.contains("\"version\": 2") && m.contains("\"id\": \"pqkeep-encrypt\""),
        "{m}"
    );
    assert_eq!(backups(&e), 0, "keine Vorgängerdatei / no previous file");
    let (code, out, _) = run(&e, &["integrate", "install"]);
    assert_eq!(code, 0);
    assert_eq!(out.matches("Unchanged").count(), 2, "{out}");
    assert_eq!(backups(&e), 0);
    let (_, out, _) = run(&e, &["integrate", "status"]);
    assert!(
        out.contains("thunar")
            && out.contains("[pqkeep-encrypt]")
            && out.contains("Mode: Terminal"),
        "{out}"
    );
    let (code, out, err) = run(&e, &["integrate", "uninstall"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.matches("Removed").count(), 2, "{out}");
    let doc = fs::read_to_string(&e.uca).unwrap();
    assert!(!doc.contains("pqkeep") && doc.ends_with("<actions>\n</actions>\n"));
    assert_eq!(backups(&e), 1);
    assert_eq!(manifest(&e), "");
    // DE: Weitere Änderung in derselben Minute: eigene Sicherung. EN: Another change, same minute.
    assert_eq!(run(&e, &["integrate", "install"]).0, 0);
    assert_eq!(backups(&e), 2);
}

#[test]
fn foreign_actions_survive_install_and_uninstall_byte_for_byte() {
    let e = env(&["thunar", "nemo", "zenity"]);
    put(&e.uca, FOREIGN);
    fs::set_permissions(&e.uca, fs::Permissions::from_mode(0o600)).unwrap();
    let (code, out, err) = run(&e, &["integrate", "install"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("Mode: Windows") && out.contains("Backup"),
        "{out}"
    );
    let doc = fs::read_to_string(&e.uca).unwrap();
    assert!(doc.starts_with(&FOREIGN[..FOREIGN.len() - "</actions>\n".len()]));
    assert!(doc.contains("context --dialog encrypt -- %F") && doc.contains("pqkeep-decrypt"));
    assert_eq!(
        fs::metadata(&e.uca).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(backups(&e), 1);
    // DE: Thunar 4.16 schreibt die Datei neu (ohne submenu/range). EN: Thunar 4.16 rewrites it.
    let rewritten = doc
        .replace("\t<submenu></submenu>\n", "")
        .replace("\t<range></range>\n", "");
    fs::write(&e.uca, &rewritten).unwrap();
    let (code, out, err) = run(&e, &["integrate", "uninstall"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.matches("Removed").count(), 4, "{out}{err}");
    let expected = FOREIGN
        .replace("\t<submenu></submenu>\n", "")
        .replace("\t<range></range>\n", "");
    assert_eq!(fs::read_to_string(&e.uca).unwrap(), expected);
}

#[test]
fn modified_and_foreign_entries_with_our_id_stay() {
    let e = env(&["thunar", "zenity"]);
    let taken = FOREIGN.replace("1700000000000000-1", "pqkeep-encrypt");
    put(&e.uca, &taken);
    let (code, out, err) = run(&e, &["integrate", "install"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("Not touched") && err.contains("[pqkeep-encrypt]"),
        "{err}"
    );
    assert_eq!(out.matches("Set up").count(), 1, "{out}");
    let doc = fs::read_to_string(&e.uca).unwrap();
    assert!(doc.contains("Terminal &amp; mehr") && doc.contains("pqkeep-decrypt"));
    let edited = doc.replace("Decrypt with PQKeep", "Mein Name");
    fs::write(&e.uca, &edited).unwrap();
    let (_, out, _) = run(&e, &["integrate", "status"]);
    assert!(out.contains("Not touched"), "{out}");
    let (code, _, err) = run(&e, &["integrate", "uninstall"]);
    assert_eq!(code, 0);
    assert!(err.contains("[pqkeep-decrypt]"), "{err}");
    assert_eq!(fs::read_to_string(&e.uca).unwrap(), edited);
}

#[test]
fn unknown_layout_is_never_touched_and_dry_run_writes_nothing() {
    let e = env(&["thunar", "zenity"]);
    let (code, out, _) = run(&e, &["integrate", "install", "--dry-run"]);
    assert_eq!(code, 0);
    assert!(out.contains("Dry run") && !e.uca.exists(), "{out}");
    let big = format!("{FOREIGN}{}", " ".repeat(1 << 20));
    let invalid = String::from_utf8_lossy(b"<actions>\xff</actions>").into_owned();
    for odd in [
        FOREIGN.replace("<actions>", "<!-- Notiz -->\n<actions>"),
        big,
        "kein XML".to_owned(),
        invalid,
    ] {
        put(&e.uca, &odd);
        let (code, out, err) = run(&e, &["integrate", "install"]);
        assert_eq!(code, 0, "{err}");
        assert!(err.contains("unexpected layout"), "{err}");
        assert!(!out.contains("Set up"), "{out}");
        assert_eq!(fs::read_to_string(&e.uca).unwrap(), odd);
        assert_eq!(backups(&e), 0);
    }
    fs::write(&e.uca, b"<actions>\xff</actions>").unwrap();
    let (code, _, err) = run(&e, &["integrate", "install"]);
    assert_eq!(code, 0);
    assert!(err.contains("unexpected layout"), "{err}");
    assert_eq!(fs::read(&e.uca).unwrap(), b"<actions>\xff</actions>");
}

#[test]
fn system_default_is_the_starting_point_when_the_file_is_missing() {
    let e = env(&["thunar", "zenity"]);
    let system = e.dir.path().join("xdg/Thunar/uca.xml");
    let default = "<?xml version=\"1.0\"?>\n<!DOCTYPE actions [\n]>\n<!-- Vorgabe -->\n<actions>\n\n  \
        <action>\n    <name>Open Terminal Here</name>\n  </action>\n\n</actions>\n";
    put(&system, default);
    let (code, _, err) = run(&e, &["integrate", "install"]);
    assert_eq!(code, 0, "{err}");
    let doc = fs::read_to_string(&e.uca).unwrap();
    assert!(
        doc.contains("Open Terminal Here") && doc.contains("pqkeep-encrypt") && !doc.contains("<!"),
        "{doc}"
    );
    assert_eq!(fs::read_to_string(&system).unwrap(), default);
    // DE: Vorgabe mit unbekanntem Aufbau: nichts anlegen. EN: Unknown default layout: create nothing.
    fs::remove_file(&e.uca).unwrap();
    fs::remove_dir_all(e.dir.path().join("data")).unwrap();
    put(&system, "<actions><!-- x --></actions>");
    let (code, _, err) = run(&e, &["integrate", "install"]);
    assert_eq!(code, 0);
    assert!(
        err.contains("unexpected layout") && !e.uca.exists(),
        "{err}"
    );
}

/// DE: Die Befehlszeile aus der Datei, wie Thunar sie ausführt (`%F` durch gequotete Pfade ersetzt,
/// dann wie eine Shell zerlegt): jeder Pfad genau ein Argument nach `--`.
/// EN: The command line from the file as Thunar runs it (`%F` replaced by quoted paths, then split
/// like a shell): each path exactly one argument after `--`.
#[test]
fn command_line_passes_hostile_names_as_single_arguments() {
    let e = env(&["thunar", "xfce4-terminal"]);
    assert_eq!(run(&e, &["integrate", "install"]).0, 0);
    let doc = fs::read_to_string(&e.uca).unwrap();
    let start = doc.find("<command>").unwrap() + "<command>".len();
    let end = doc.find("</command>").unwrap();
    let command = doc[start..end].replace("&quot;", "\"");
    assert!(!command.contains('&'), "{command}");
    let names = ["a b'\"; touch pwned $(id) `id`\n--no-sandbox", "-c"];
    let quoted: Vec<String> = names
        .iter()
        .map(|n| format!("'{}'", n.replace('\'', r"'\''")))
        .collect();
    let record = e.dir.path().join("record");
    let status = Command::new("/bin/sh")
        .args(["-c", &command.replace("%F", &quoted.join(" "))])
        .env("RECORD", &record)
        .current_dir(e.dir.path())
        .status()
        .unwrap();
    assert!(status.success());
    let recorded = fs::read_to_string(&record).unwrap();
    let args: Vec<&str> = recorded.split('\0').filter(|s| !s.is_empty()).collect();
    let bin = fs::canonicalize(BIN).unwrap();
    let expected = [
        "-x",
        bin.to_str().unwrap(),
        "context",
        "encrypt",
        "--",
        names[0],
        names[1],
    ];
    assert_eq!(args, expected);
    assert!(!e.dir.path().join("pwned").exists());
}
