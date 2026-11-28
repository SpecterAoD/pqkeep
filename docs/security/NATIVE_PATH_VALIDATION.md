# Native path ingress / Nativer Pfadeingang

DE: Teil von R7/R8 in genau Draft355; kein Abschluss von M1/M3 oder147.
EN: This component protects internal native conversion at actual archive/source
read calls. Caller-owned Path/OsStr memory remains the caller's responsibility.

## Ownership and reached callers / Owner und tatsächliche Caller

DE: NativePath sperrt den konkreten Pufferowner und den UTF8-/UTF16-Puffer vor
privater Befüllung. Linux übernimmt geliehene OsStr-Bytes ohne CString-Staging;
Windows kodiert direkt aus encode_wide in gesperrte Einheiten, auch bei isolierten
Surrogaten. Kein to_string_lossy, gewöhnlicher UTF16-Vec oder privates OsString.
Duplikation ist explizit fallibel; Debug redigiert, kein Clone/Display/Serialize.
EN: Public-empty owners are installed before private population. Existing
SecretBytes/SecretWorkspace and SecretState wipe storage before releasing locks.
Invalid native NUL input is rejected; failed duplication leaves the source intact.

DE: inspect und inspect_v2 sowie der gemeinsame Entschlüsselungs-/Listen-/Check-
Quelleingang und der Quelldatei-Leser beim Verschlüsseln benutzen open_file.
Linux verwendet vorhandenes rustix1.1.6 mit geliehenem CStr und CLOEXEC; dessen
Arg-Implementierung reicht den Borrow direkt durch, ohne CString-Allokation.
EN: Existing package versions/sources are unchanged; only existing dependency
features are added. Missing files keep their I/O classification. A lock failure
refuses ingress before native open; no fallback to unprotected std conversion.

## Windows compatibility and FFI / Kompatibilität und FFI

DE: GetFullPathNameW schreibt direkt in ein gesperrtes Caller-Ziel. Begrenztes
fallibles Wachstum, anschließend Präfix direkt in ein weiteres gesperrtes Ziel.
Die Rust1.88-get_long_path-Verzweigungen einschließlich der248-Einheiten-Grenze,
UNC-/Device-/Verbatim-/NT-Präfixe und relativer Pfade bleiben erhalten; Herkunft
und Anpassung stehen in NOTICE. Kein Wechsel des Arbeitsverzeichnisses.
EN: CreateFileW retains read access, read/write/delete sharing, OPEN_EXISTING,
normal attributes and noninheritance, matching existing std read-open behavior.
No change to link following or source-race guarantees is claimed.

DE: Drei notwendige unsafe-Blöcke sind ausschließlich im schmalen Windows-
Plattformadapter: synchroner nativer Normalisierungsaufruf, synchrones Öffnen,
einmalige Übergabe des neuen Handles an File. Eingabeslice vollständig NUL-geprüft;
Ausgabe exklusiv und längengeprüft; keine gespeicherten Zeiger. Fehler sofort
zurückgeben, bevor ein weiterer Win32-Aufruf den Fehlercode verändern kann.
EN: Root forbids unsafe code. No pointer casts of private records, shared mutable
aliases, rights/token/Registry mutation, new Send/Sync claims or host-policy changes.

## Acceptance and limits / Abnahme und Grenzen

DE: Tests prüfen echte gesperrte Owner, unabhängige fallible Kopien, Wipe/Unwind,
wirkliche Ressourcenverweigerung im begrenzten eigenen Linux-Kind und unveränderte
Elternlimits. Echte Dateiöffnungen decken Unicode, Linux-NonUTF8, EOF und fehlende
Dateien ab. Native Windows-Fälle: relative und lange Pfade, Präfixe,248-Grenze,
Surrogate sowie Ablehnung ungültiger nativer Eingabe vor einem Systemaufruf.
EN: Cross lint only proves compilation, not native execution. Source-bound local
and exact published-head native acceptance must be recorded before row closure.

DE: Lokaler v1-Checkpoint:869 Rust-/Manifestquellen über13 erfolgreiche Befehle
unverändert. Vier strenge Linux-/Windows-Cross-Lints mit/ohne API, je73 Datei-
Testgruppen mit tatsächlichen eigenen Verweigerungskindern und21 ausgewählte
Format-/Sender-/STREAM-Integrationen, Format/Limits/Herkunft/Matrix/Diff bestanden.
EN: Final focused v2 passes all12 commands on869 unchanged source hashes: four
strict lints and six native-path groups per feature configuration, actual bounded
denial/unwind child, format/limits/provider/matrix/diff. It adds Windows owner/page
observations through the existing prelocked query fixture and preserves the old
invalid-NUL I/O class. Source delta is bound to v1; native Windows execution of
the new path tests remains pending.

DE: Offen bleiben gespeicherte SourceEntry-/Skip-/Traversal-Datensätze, gewöhnliche
read_dir-/Metadaten-Ausgaben, Ziel-/Temppfade und deren Schreib-/Publish-/Cleanup-
Adapter, Berichte/Transport sowie Prozess-/GUI-/Host-Verträge. Keine dieser Flächen
wird durch den neuen Leseadapter nachträglich als geschützt erklärt.
EN: OS filesystem naming is an explicit disclosure boundary. Neither it nor scalar
compiler transit excuses known ordinary application-side path allocations.

Sources / Quellen:
- [Rust1.88 Windows path source](https://github.com/rust-lang/rust/blob/1.88.0/library/std/src/sys/path/windows.rs)
- [GetFullPathNameW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfullpathnamew)
- [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)

## Native follow-up / Nativer Folgeabgleich

DE: d818ff3 besteht die vollständigen nativen Windows- und ARM-Jobs. Insbesondere
alle zehn Windows-Pfadfälle mit/ohne API einschließlich physischer Seitensperren,
248-Grenze, langer/relativer Pfade, Surrogate und Fehlerklassen tatsächlich grün.
EN: Full logs are retained; this is native execution, not cross-compilation only.

DE: Linux-x86-CI findet dagegen eine echte Sandbox-Regression: rustix::fs::open
verwendet dort den alten open-Syscall, den die bestehende Allowlist korrekt
verweigert. ARM nutzt bereits openat. Der Adapter fordert nun explizit openat
mit CWD an; Allowlist/Landlock/Flags bleiben unverändert. Die bestehende Sandbox-
Probe prüft zusätzlich tatsächliche native Leseeingänge und fremde Pfadverweigerung
bei nachgewiesen aktivem Seccomp. Der betroffene echte CLI-Ablauf bleibt Teil der
Abnahme; ursprüngliche Fehlerprotokolle werden nicht als Erfolg umgedeutet.
EN: New complete Linux/native acceptance remains required after the targeted fix.

DE: Abschließender lokaler openat-v1-Checkpoint: alle14 Befehle erfolgreich,
Quellen vor/nachher unverändert. Vier strenge Lints, je sechs Pfadgruppen,
echter CLI-Anonymitätsfall und sechs Sandbox-Gruppen in beiden Featurevarianten;
freigegebene native Pfade erreichbar, fremde gesperrt, Seccomp auf Zielarchitektur
nachweislich Full. Keine Allowlist-/Landlock-/Flagänderung.
EN: Complete native reruns for the corrected head remain required; previous
Linux failures retained and not counted as passes. Three unrelated unapproved
local token/thread prototype sources remain excluded and unexecuted.
