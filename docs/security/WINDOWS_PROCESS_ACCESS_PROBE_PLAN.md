# Windows own-process access probe / Eigene Windows-Prozessprobe

DE: Konkrete technische Probe unter P2 des freigegebenen gemeinsamen R7/R8-Plans.
Kein Produktions-Gate und kein R7-Abschluss. Neue Rechteänderung ausschließlich
am eigenen kurzlebigen Windows-CI-Testprozess benötigt eine zusätzliche konkrete
Freigabe gemäß globaler AGENTS.md. Vor dieser Freigabe Workflow nicht pushen/ausführen.
EN: Local source development and cross compilation only until that approval.

## Action / Aktion

DE: Neuer eigener Kindprozess `process_access_probe target` öffnet vor der Änderung
ein eigenes nicht vererbbares READ_CONTROL/WRITE_DAC-Handle. Anschließend setzt
er ausschließlich seine Prozessobjekt-DACL auf die feste öffentliche SDDL
`D:P(A;;0x00121001;;;OW)` und liest den tatsächlichen Descriptor zurück.
Owner Rights ersetzt implizite Besitzerrechte; ausdrücklich erlaubt bleiben nur
ReadControl, Synchronize, QueryLimited und Terminate. Kein Token-/Konten-/Thread-/
Registry-/Datei-/Dienstrecht wird verändert. Kein Privileg wird aktiviert.
EN: The second owned inspector attempts only OpenProcess, never memory reading,
writing, thread creation or handle duplication. Sensitive rights must return
AccessDenied; limited query/synchronization must remain available.

DE: Das PowerShell-Skript prüft die vom eigenen Process-Objekt gehaltene PID gegen
die feste READY-Zeile und beendet/reapt ausschließlich beide selbst gestarteten
Kinder. Je Start/Prüfung/Exit zehn Sekunden, eigener Kill/Wait im finally, Joblimit
15 Minuten. Keine unbekannten Zielprozesse, keine Geheimnisse/Testschlüssel.
EN: No installation, administrator command, sudo, credentials or network endpoint.

## Files and risk / Dateien und Risiko

- `platform/pqkeep-platform/examples/process_access_probe.rs`: nur explizites Beispiel,
  Feature `process-access-probe`, vorhandenes windows-sys0.61.2.
- `scripts/test_process_access_probe.ps1`: begrenzter Besitzer-/Inspektorprozess.
- `.github/workflows/process-access-probe.yml`: Windows-CI, contents:read,
  gepinnter bestehender Checkout, kein persistiertes Git-Credential.
- `platform/pqkeep-platform/Cargo.toml`: ausschließlich Dev-Feature/Win32-Authorization.

DE: Die Probe kann Zugriff des eigenen Besitzers auf das Prozessobjekt einschränken.
Das ist beabsichtigt und wird durch den zweiten eigenen Prozess getestet. Ein vorab
geöffnetes Handle bleibt bis zum normalen Ende gehalten. Elternprozess und übrige
Runner-Prozesse werden nicht verändert; bei Fehler beendet nur der eigene Parent
seine beiden bereits gehaltenen Kinder. Neue FFI-Stellen sind einzeln begründet.
EN: No policy application in the normal CLI/library path or implicit example execution.

## Backup and return / Sicherung und Rückweg

DE: Keine persistente Systemkonfiguration wird geschrieben; Prozessende beseitigt
das Testobjekt. Bestehende System-/Konten-/Registry-ACLs bleiben unberührt. Original-
Main und signierter Plan bleiben erhalten; lokale Quellen/Proposal werden vollständig
mit Hashes gesichert. Bei abgelehnter Probe: Workflow nicht veröffentlichen.
EN: Do not weaken a live process policy as an automatic recovery. Terminate only
the own ephemeral test process; no machine rollback or host restart is needed.

## Limits / Grenzen

DE: Selbst erfolgreiche OpenProcess-Verweigerung beweist weder Schutz bestehender
Handles noch Thread-Kontextschutz, WER/LocalDumps-Abwehr, IME-/GUI-Sicherheit oder
Schutz gegen privilegierte Zugriffe. Diese Flächen bleiben eigene R7-Abnahmezeilen.
Keine dieser Grenzen wird aufgrund dieser Probe als geschlossen markiert.
EN: Native execution is mandatory; a successful cross check is not that execution.

Primary sources / Primärquellen:
- https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
- https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-special-identities-groups
- https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings
- https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps
