//! DE: Fenster unter Windows über PowerShell und Windows Forms (in jedem Windows enthalten, kein
//! eigener `unsafe`-Code). Das Skript ist fest im Programm und wird als `-EncodedCommand`
//! übergeben (keine Skriptdatei, keine Ausführungsrichtlinie nötig). Alle Texte stehen als
//! PowerShell-Literale in einfachen Anführungszeichen – sie werden nie ausgewertet.
//! Ausgabe: UTF-8 ohne BOM; Fehler im Skript → Exit-Code 3.
//! EN: Windows windows via PowerShell and Windows Forms (part of every Windows, no own `unsafe`
//! code). The script is built into the program and passed as `-EncodedCommand` (no script file, no
//! execution policy needed). All texts are single-quoted PowerShell literals – never evaluated.
//! Output: UTF-8 without BOM; script errors → exit code 3.

use base64ct::{Base64, Encoding};

use super::args::Request;

/// DE: Literal in einfachen Anführungszeichen; auch typografische Varianten werden verdoppelt,
/// weil PowerShell sie ebenfalls als Begrenzer behandelt.
/// EN: Single-quoted literal; typographic variants are doubled too, since PowerShell also treats
/// them as delimiters.
pub fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for c in text.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            out.push(c);
        }
        out.push(c);
    }
    out.push('\'');
    out
}

const PRELUDE: &str = r"$ErrorActionPreference = 'Stop'
try {
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch {}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
function New-Form([string]$text, [int]$h) {
  $f = New-Object System.Windows.Forms.Form
  $f.Text = $t; $f.TopMost = $true; $f.StartPosition = 'CenterScreen'
  $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false
  $f.ClientSize = New-Object System.Drawing.Size(420, $h)
  $l = New-Object System.Windows.Forms.Label
  $l.Text = $text; $l.SetBounds(12, 10, 396, 40)
  $ok = New-Object System.Windows.Forms.Button
  $ok.Text = 'OK'; $ok.DialogResult = 'OK'; $ok.SetBounds(232, ($h - 36), 85, 26)
  $c = New-Object System.Windows.Forms.Button
  $c.Text = $cancel; $c.DialogResult = 'Cancel'; $c.SetBounds(323, ($h - 36), 85, 26)
  $f.Controls.AddRange(@($l, $ok, $c)); $f.AcceptButton = $ok; $f.CancelButton = $c
  return $f
}
function Add-Pass($f, [int]$y, [string]$label) {
  $l = New-Object System.Windows.Forms.Label
  $l.Text = $label; $l.SetBounds(12, $y, 396, 18)
  $b = New-Object System.Windows.Forms.TextBox
  $b.UseSystemPasswordChar = $true; $b.SetBounds(12, ($y + 20), 396, 24)
  $f.Controls.AddRange(@($l, $b))
  return $b
}
";

const EPILOGUE: &str = "\n} catch { exit 3 }\n";

const OUT: &str = "[Console]::Out";

/// DE: Vollständiges Skript für eine Anfrage. EN: Complete script for one request.
pub fn script(title: &str, cancel: &str, req: &Request<'_>) -> String {
    let mut s = format!("$t = {}\n$cancel = {}\n", quote(title), quote(cancel));
    s.push_str(PRELUDE);
    s.push_str(&body(req));
    s.push_str(EPILOGUE);
    s
}

fn message(text: &str, icon: &str) -> String {
    format!(
        "[void][System.Windows.Forms.MessageBox]::Show({}, $t, 'OK', '{icon}'); exit 0",
        quote(text)
    )
}

fn body(req: &Request<'_>) -> String {
    match *req {
        Request::Info { text } => message(text, "Information"),
        Request::Warning { text } => message(text, "Warning"),
        Request::Error { text } => message(text, "Error"),
        Request::Question { text } => format!(
            "$r = [System.Windows.Forms.MessageBox]::Show({}, $t, 'YesNo', 'Question')\n\
             if ($r -eq 'Yes') {{ exit 0 }}; exit 1",
            quote(text)
        ),
        Request::OpenFile {
            prompt,
            start,
            pattern,
            label,
        } => open_file(prompt, start, pattern, label),
        Request::Choose { text, items } => choose(text, items),
        Request::Password { text } => format!(
            "$f = New-Form {} 120\n$a = Add-Pass $f 50 ''\n\
             if ($f.ShowDialog() -eq 'OK') {{ {OUT}.Write($a.Text + [char]10); exit 0 }}; exit 1",
            quote(text)
        ),
        Request::NewPassword {
            text,
            first,
            second,
        } => format!(
            "$f = New-Form {} 180\n$a = Add-Pass $f 50 {}\n$b = Add-Pass $f 96 {}\n\
             if ($f.ShowDialog() -eq 'OK') \
             {{ {OUT}.Write($a.Text + [char]10 + $b.Text + [char]10); exit 0 }}; exit 1",
            quote(text),
            quote(first),
            quote(second)
        ),
        Request::Entry { text, default } => format!(
            "$f = New-Form {} 120\n$e = New-Object System.Windows.Forms.TextBox\n\
             $e.Text = {}; $e.SetBounds(12, 50, 396, 24); $f.Controls.Add($e)\n\
             if ($f.ShowDialog() -eq 'OK') {{ {OUT}.WriteLine($e.Text); exit 0 }}; exit 1",
            quote(text),
            quote(default)
        ),
        Request::Progress { text, cancel } => progress(text, cancel),
    }
}

fn open_file(prompt: &str, start: &str, pattern: &str, label: &str) -> String {
    format!(
        "$d = New-Object System.Windows.Forms.OpenFileDialog\n$d.Title = {}\n\
         $d.InitialDirectory = {}\n$d.Filter = {}\n\
         if ($d.ShowDialog() -eq 'OK') {{ {OUT}.WriteLine($d.FileName); exit 0 }}; exit 1",
        quote(prompt),
        quote(start),
        quote(&format!("{label}|{}|*.*|*.*", pattern.replace('/', "\\")))
    )
}

fn choose(text: &str, items: &[&str]) -> String {
    let list: Vec<String> = items.iter().map(|i| quote(i)).collect();
    format!(
        "$f = New-Form {} 220\n$lb = New-Object System.Windows.Forms.ListBox\n\
         $lb.SetBounds(12, 56, 396, 110)\n[void]$lb.Items.AddRange(@({}))\n\
         $lb.SelectedIndex = 0; $f.Controls.Add($lb)\n\
         if ($f.ShowDialog() -eq 'OK' -and $lb.SelectedIndex -ge 0) \
         {{ {OUT}.WriteLine($lb.SelectedIndex); exit 0 }}; exit 1",
        quote(text),
        list.join(", ")
    )
}

fn progress(text: &str, cancel: bool) -> String {
    // DE: Mit Abbrechen-Knopf: Klick → Exit 1. EN: With cancel button: click → exit 1.
    let ending = if cancel {
        "$c = New-Object System.Windows.Forms.Button; $c.Text = $cancel; $c.DialogResult = 'Cancel'\n\
         $c.SetBounds(263, 70, 85, 26); $f.Controls.Add($c); $f.CancelButton = $c\n\
         $f.ClientSize = New-Object System.Drawing.Size(360, 106)\n\
         if ($f.ShowDialog() -eq 'Cancel') { exit 1 }; exit 0"
    } else {
        "[void]$f.ShowDialog(); exit 0"
    };
    format!(
        "$f = New-Object System.Windows.Forms.Form\n$f.Text = $t; $f.ControlBox = $false\n\
         $f.StartPosition = 'CenterScreen'; $f.FormBorderStyle = 'FixedDialog'\n\
         $f.ClientSize = New-Object System.Drawing.Size(360, 80)\n\
         $l = New-Object System.Windows.Forms.Label; $l.Text = {}; $l.SetBounds(12, 12, 336, 20)\n\
         $p = New-Object System.Windows.Forms.ProgressBar; $p.Style = 'Marquee'\n\
         $p.SetBounds(12, 44, 336, 18); $f.Controls.AddRange(@($l, $p))\n{ending}",
        quote(text)
    )
}

/// DE: Prüfskript: volle Sprache und Windows Forms verfügbar? EN: Probe: full language and Forms?
#[cfg_attr(not(windows), allow(dead_code))]
pub fn probe() -> String {
    "$ErrorActionPreference = 'Stop'\ntry {\n\
     if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { exit 3 }\n\
     Add-Type -AssemblyName System.Windows.Forms\nexit 0\n} catch { exit 3 }\n"
        .to_owned()
}

/// DE: Argumente für `powershell.exe` (Skript als UTF-16LE in Base64).
/// EN: Arguments for `powershell.exe` (script as UTF-16LE in Base64).
pub fn args(script: &str) -> Vec<String> {
    let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut a: Vec<String> = ["-NoProfile", "-NonInteractive", "-NoLogo", "-Sta"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    a.push("-EncodedCommand".to_owned());
    a.push(Base64::encode_string(&utf16));
    a
}

#[cfg(test)]
#[path = "powershell_tests.rs"]
mod powershell_tests;
