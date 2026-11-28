# Prelocked source metadata / Vorab gesperrte Quellmetadaten

DE: Gemeinsamer R7/R8-Draft355; kein Gesamtabschluss. Die tatsächlichen
symlink_metadata-Aufrufe der Quellsammlung verwenden vor Kernel-Ausgabe
gesperrte SDK-/libc-Records. Datei-/Verzeichnis-/Linkart und Länge werden im
selben geschützten Zustand gehalten, ohne privaten std::fs::Metadata-Rückgabewert.
EN: Source path conversion reuses NativePath. The whole native record, Windows
reparse-tag and find fallback records are locked before capture. Public-empty
construction precedes private fields; no ordinary allocation fallback on denial.

## Reached operations / Erreichte Operationen

DE: Einzeldatei-, Top-Level-Mehrfach- und Ordnerprüfung sowie Größenabfrage
echter Quelldateien in walk.rs. Linux nutzt fstatat mit AT_SYMLINK_NOFOLLOW
und geliehenem geschütztem CStr; negativer nativer Größenwert wird abgewiesen.
EN: Windows retains zero-access metadata handles, normal sharing, reparse-point
opening and directory support. Reparse tags are queried only when indicated by
attributes, preserving ordinary FAT-file behavior. Name-surrogate links remain
links instead of being misclassified as ordinary files/directories.

DE: Windows-Sharing-/Zugriffs-Fallback wie beim bestehenden std-Vertrag über
FindFirstFileExW, jedoch direkt ins geschützte SDK-Ziel. Keine Wildcard-Abfrage
durch den Fallback. Suchhandle sofort schließen; ursprünglichen Öffnungsfehler
bei fehlgeschlagener Suche erhalten. Ein direkter nur lesender Testfixture-Aufruf
prüft den Find-Pfad, ohne einen künstlich gewählten Fehler als native Verweigerung
auszugeben. Exklusiv geöffnete normale Dateien garantieren diesen Fehler nicht.
EN: Native metadata may be stale, as with the previous std operation. This does
not solve the separately open source-open/symlink race in338. read_dir, DirEntry,
native traversal/skip/output/report records remain separate real gaps.

## Unsafe boundary / Unsafe-Grenze

DE: Root-forbid bleibt. Plattformcode verwendet tatsächliche SDK-/libc-Typen,
keinen nachgebauten stat-ABI. Notwendige native Aufrufe prüfen lebende NUL-Pfade,
exklusive vollständige Ziele, Ausrichtung, Rückgaben und Handle-Eigentum.
Linux leiht MaybeUninit nur nach erfolgreichem fstatat aus; Fehler lesen keinen
teilinitialisierten Record. Gesamten MaybeUninit-Speicher volatil löschen.
EN: Windows typed SDK defaults and fieldwise volatile wiping avoid unnecessary
assume_init/raw-wipe blocks. Compile-time52/8/592-byte layout checks cover the
complete native/tag/find fields without padding; root SecretState additionally
wipes the full owning allocation and padding before unlock, including unwind.
There is no record Clone/Debug or whole-private-record conversion.

DE: Vorhandene libc0.2.191 und zeroize werden wiederverwendet; nur Abhängigkeits-
kanten erweitert, keine Paketversion/Quelle installiert oder aktualisiert.
EN: No ACL, token, privilege, account, Registry, sandbox or host-policy mutation.

## Verification / Prüfung

DE: Entwickelt sind echte öffentliche Datei-/Verzeichnisreferenzen, Linux-
Dangling-Link, Fehlerklassen, konkrete Owner-/Windows-Seitenbeobachtung und
begrenztes eigenes Speicherfehler-/Unwind-Kind mit unverändertem Elternlimit.
Windows-Fälle für Datei-/Verzeichnis-/Dangling-Links, exklusiven Öffner und
echten direkten Find-Aufruf in vorab gesperrtes Caller-Ziel sind cross-kompiliert;
die tatsächliche native Ausführung steht noch aus.
DE: Lokaler source-metadata-v1-Checkpoint:886 unveränderte Rust-/Manifest-Hashes,
16 erfolgreiche Kommandos. Plattform-All-Feature-Lints auf Linux/Windows-GNU,
acht Plattformtests, vier strenge Root-Lints mit/ohne API auf beiden Zielen,
je92 Dateigruppen mit/ohne API,57 Integrationen. Elf ignorierte Kind-/Race-
Einstiege bleiben sichtbar; tatsächlicher Metadaten-Fehlerkindaufruf bestanden.
EN: Root/platform formatting, limits, strict vendor/matrix and diff checks pass.
Native Windows/ARM64 and usual final gates remain required. No complete metadata,
M1/M3, R7/R8 or147 acceptance is claimed by this document.

Sources / Quellen:
- https://raw.githubusercontent.com/rust-lang/rust/1.88.0/library/std/src/sys/fs/windows.rs
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_attribute_tag_info
- https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-tags
