# Verified platform support / verifizierte Plattformunterstützung (#147 R7)

DE: Eigentümerentscheidung vom23.11.2026: zuerst verifizierte Plattform-/Helper-
Unterstützung entwickeln; keine pauschale Abschaltung bestehender Windows-/GUI-Pfade.
Dieser konkrete Teilplan ergänzt das vorher freigegebene R7. Keine Installation,
Registry-/ACL-/Rechteänderung, keine Deaktivierung von Prüfungen oder Schutzmaßnahmen.
EN: Implement auditable capabilities before claiming support. Keep #128/#149/#150
linked and distinguish application-owned memory from OS/admin-controlled boundaries.

## First adapter / erster Adapter

DE: Neue kleine Apache-2.0-Pfadcrate `platform/pqkeep-platform`, mit exakt vorhandenem
windows-sys0.61.2-Pin. Unsafe ausschließlich in einem kommentierten Windows-FFI-Modul;
Root-`forbid(unsafe_code)` unverändert. Kein neuer Parser/Krypto-/GUI-Stack und keine
Systeminstallation. Safe-API mit geliehenen Handles/Slices, synchronen Aufrufen,
geprüften Längen und generischen Fehlern. Herkunft der Win32-Verträge unten verlinkt.
EN: Separate platform FFI from secret ownership. Root retains its shared page registry,
locks UTF-16 workspace before conversion and wipes before unlocking. Avoid independent
page-lock registries that could prematurely unlock another live owner's shared page.

DE: Zuerst absichtliche Konsolenausgabe: Dateien/Pipes direkt UTF-8, Windows-Konsole
über WriteConsoleW aus vorab gesperrtem UTF-16-Arbeitsbereich. Keine Codepageänderung,
kein LineWriter und keine ungesperrte String-Zwischenkopie. Unicode, kurze Writes,
Write-/Flushfehler, ungültige Eingabe und lebende Workspace-Sperre prüfen.
EN: Preserve intentional disclosure and UTF-8 pipe/JSON contracts; verify the native
console adapter separately rather than inferring console behavior from pipe tests.

DE: Prozessfähigkeiten anschließend einzeln belegen: WerGetFlags/WerSetFlags/read-back
für NOHEAP ist nur eine zusätzliche WER-Minderung, keine vollständige Dumpsperre und
kein Schutz gegen Debugger/Admin/LocalDumps. Bestehende Linux-Fähigkeiten unverändert.
Native positive/negative Tests müssen tatsächliche Ergebnisflags und Fehler nachweisen.
EN: Never map a partial mitigation to core_dumps_disabled/not_dumpable=true. Embedders
retain explicit control of host policy; do not silently harden an unrelated host.

## Helper gate / Helferabnahme

DE: zenity/kdialog/PowerShell-Textboxen bleiben ausdrücklich ungeprüft. Ein eigener
Helper darf nur anhand vorab gesperrter Eingabespeicher, ohne Secret-Widgettext,
Clipboardkopie, Argument-/Logtransport und mit Abbruch-/Pipe-/Kindprozessnachweisen
als unterstützt gelten. Die Schnittstelle bleibt bis zu diesem Nachweis offen,
nicht fälschlich „geschlossen“. Keine pauschale Verweigerung als Implementierungsersatz.
EN: The initial FFI/output adapter is not a completed protected password helper.
Preserve existing non-secret dialogs; do not invent a safety guarantee for widget internals.

## Sources and checks / Quellen und Prüfungen

- [WriteConsoleW](https://learn.microsoft.com/en-us/windows/console/writeconsole):
  Unicode console I/O; redirected handles use file I/O.
- [WerSetFlags](https://learn.microsoft.com/en-us/windows/win32/api/werapi/nf-werapi-wersetflags)
  and [WerGetFlags](https://learn.microsoft.com/en-us/windows/win32/api/werapi/nf-werapi-wergetflags):
  current-process WER flags, HRESULT/read-back checks.
- [LocalDumps](https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps):
  independently configured, DumpType0 means custom dump; not a disable switch.

DE/EN: Native Windows/Linux CI, both features, MSRV1.88, strict Clippy, fmt, limits,
dependency/license/secret/source checks; no claim based on cross-compilation alone.
Rollback: reviewed code revert, no data migration or machine configuration to restore.

## Console and fuzz follow-up / Konsolen- und Fuzz-Abgleich

DE: `GetConsoleMode` unterscheidet echte Konsolen von MSYS-/Cygwin-PTY-Pipes;
`IsTerminal` allein genügt wegen seiner Windows-Heuristik nicht. Der native Test
prüft echte Unicode-Zeichen und getrennt Datei-Handles. Breite Bildschirmglyphen
können beim Lesen mehrerer Zellen weniger UTF-16-Einheiten ergeben; die tatsächliche
Rückgabelänge wird geprüft, die exakte Zeichenprüfung bleibt bestehen.
EN: Classify real console handles before calling WriteConsoleW; keep redirected
and PTY output as UTF-8 byte streams. Respect returned UTF-16 counts rather than
assuming one code unit per screen cell. See the Windows-specific notes in
[IsTerminal](https://doc.rust-lang.org/std/io/trait.IsTerminal.html).

DE: Die acht bestehenden Fuzz-Ziele müssen dieselben geschützten HTTP-/JSON-
Pfadabhängigkeiten und gemeinsamen Registry-Versionen wie der Hauptbuild verwenden.
Der separate Lockfile wird entsprechend abgeglichen; die fallible Token-Hash-API
wird auch im API-Fuzz-Ziel behandelt. Lokaler Build ist kein Fuzz-Laufnachweis.
EN: Align the separate fuzz dependency graph with production, compile all targets,
and retain the existing CI fuzz executions and unchanged security gates.
