//! DE: Tests der PowerShell-Skripte (Aufbau überall, Syntax zusätzlich unter Windows).
//! EN: Tests of the PowerShell scripts (structure everywhere, syntax additionally on Windows).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

fn all_requests() -> Vec<Request<'static>> {
    vec![
        Request::Info { text: "Fertig" },
        Request::Warning { text: "Achtung" },
        Request::Error { text: "Fehler" },
        Request::Question { text: "Weiter?" },
        Request::OpenFile {
            prompt: "Schlüssel wählen",
            start: r"C:\Users\anna\Documents",
            pattern: "*.pub.json",
            label: "Öffentliche Schlüssel (*.pub.json)",
        },
        Request::Choose {
            text: "Wie?",
            items: &["Mit Passphrase", "Für einen Empfänger"],
        },
        Request::Password { text: "Passphrase" },
        Request::NewPassword {
            text: "Neue Passphrase",
            first: "Passphrase",
            second: "Wiederholen",
        },
        Request::Progress {
            text: "Bitte warten …",
        },
    ]
}

#[test]
fn quote_doubles_all_single_quote_variants() {
    assert_eq!(quote("abc"), "'abc'");
    assert_eq!(quote("O'Brien"), "'O''Brien'");
    assert_eq!(quote("a\u{2019}b"), "'a\u{2019}\u{2019}b'");
    assert_eq!(quote("$(calc) `n \"x\""), "'$(calc) `n \"x\"'");
    assert_eq!(quote("„Zitat“"), "'„Zitat“'");
}

#[test]
fn hostile_text_stays_inside_one_literal() {
    let text = "x'; Start-Process calc; '";
    let s = script("PQKeep", "Abbrechen", &Request::Info { text });
    assert!(s.contains("'x''; Start-Process calc; '''"), "{s}");
}

#[test]
fn every_script_has_prelude_and_error_exit() {
    for req in all_requests() {
        let s = script("PQ'Keep", "Abbrechen", &req);
        assert!(
            s.starts_with("$t = 'PQ''Keep'\n$cancel = 'Abbrechen'\n"),
            "{s}"
        );
        assert!(s.contains("Add-Type -AssemblyName System.Windows.Forms"));
        assert!(s.ends_with("} catch { exit 3 }\n"));
    }
}

#[test]
fn passwords_go_only_to_stdout() {
    let one = script("t", "c", &Request::Password { text: "p" });
    assert!(one.contains("[Console]::Out.Write($a.Text + [char]10)"));
    assert!(one.contains("UseSystemPasswordChar = $true"));
    let two = script(
        "t",
        "c",
        &Request::NewPassword {
            text: "n",
            first: "a",
            second: "b",
        },
    );
    assert!(two.contains("$a.Text + [char]10 + $b.Text + [char]10"));
}

#[test]
fn file_filter_uses_windows_pattern() {
    let s = script("t", "c", &all_requests()[4]);
    assert!(s.contains("$d.Filter = 'Öffentliche Schlüssel (*.pub.json)|*.pub.json|*.*|*.*'"));
    assert!(s.contains(r"$d.InitialDirectory = 'C:\Users\anna\Documents'"));
}

#[test]
fn encoded_command_is_utf16le_base64() {
    let a = args("Write-Output 'ä'");
    assert_eq!(
        &a[..5],
        [
            "-NoProfile",
            "-NonInteractive",
            "-NoLogo",
            "-Sta",
            "-EncodedCommand"
        ]
    );
    let raw = Base64::decode_vec(&a[5]).unwrap();
    let units: Vec<u16> = raw
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    assert_eq!(String::from_utf16(&units).unwrap(), "Write-Output 'ä'");
}

/// DE: Jedes Skript muss für PowerShell syntaktisch gültig sein (nur Parser, keine Ausführung).
/// EN: Every script must be syntactically valid PowerShell (parser only, no execution).
#[cfg(windows)]
#[test]
fn scripts_parse_in_windows_powershell() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let check = "$e = $null; [void][System.Management.Automation.Language.Parser]::ParseInput(\
                 [Console]::In.ReadToEnd(), [ref]$null, [ref]$e); \
                 if ($e.Count) { $e | ForEach-Object { $_.Message }; exit 1 }; exit 0";
    let mut scripts: Vec<String> = all_requests()
        .iter()
        .map(|r| script("PQ'Keep", "Abbrechen", r))
        .collect();
    scripts.push(probe());
    for s in scripts {
        let mut child = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", check])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}\n{s}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}
