# Secret lifetime audit plan / Auditplan Secret-Lebensdauer (#147)

DE: Der Eigentümer hat am 23.11.2026 die zuvor empfohlene Bearbeitung von #147 beauftragt.
Erste Phase laut Issue: Analyse/Entwurf, keine produktive Verhaltensänderung. Dieser Plan
wird vor Audit-Ergebnissen und Hilfsproben signiert versioniert. Ein geprüfter PR; kein
Main-Merge, Release, System-/Schutzregelwechsel oder neuer Zugriff auf Fremdsysteme.
EN: Owner requested the recommended #147 audit. Its first phase is analysis/design without
production behavior changes. Commit this plan before audit results/probes. Prepare one
validated PR; no main merge, release, system/protection changes or foreign-system access.

## Baseline and ownership / Ausgangslage und Zuständigkeit

- DE/EN: Main `94b230446026f37ad987995f6ea119cf32ee4fc9`; previous #148/#186 fixes retained.
- DE: #103 ist duplicate geschlossen. #128 besitzt Windows-OS-/Prozessvergleich; vorhandene
  Schutzmaßnahmen aufnehmen, keine zweite Implementierung. #149/#150 besitzen nachgelagerte
  Dump-/Prozesshärtung und Isolationstests. #148-Nacharbeit als Befund behandeln, nicht als
  pauschal erledigt oder bereits autorisierte Laufzeitänderung.
  EN: #103 closed duplicate; coordinate Windows128 and follow-ups149/150. Record remaining
  #148 gaps without claiming they are fixed or authorizing runtime changes.
- DE/EN: #83 stream format, #98/#99 API/core split, GUI/IPC/remote changes remain separate.

## Audit scope / Prüfumfang

1. DE: Secret-Quellen und Kopien inventarisieren: Schlüssel/Seeds, KDF/HKDF/HMAC/AES,
   Klartext/Archiv/STREAM, Serialisierung, Passphrasen/Normalisierung/Bewertung, CLI/API,
   Kindprozesse/FFI. Eigentümer, Puffer, Sperre, Wipe, Fehler-/Dropweg und Herkunft festhalten.
   EN: Inventory sources/copies, owners, buffers, locks, wiping, error/drop paths and evidence
   across keys, providers, payloads, serialization, input, CLI/API and process boundaries.
2. DE: Heap und Stack sowie Klartext und Ciphertext unterscheiden. Auch Standardbibliotheks-
   und Provider-Zwischenkopien prüfen; keine Invariante allein aus einem Typnamen ableiten.
   EN: Distinguish heap/stack and plaintext/ciphertext; inspect std/provider copies explicitly.
3. DE: Linux/Windows-Startup, Dump/Swap/Hibernation, Debugger, Panic/Abort/SIGKILL, Logging,
   Kindprozess-Argumente/Pipes, Fehler und OS-/Compiler-Grenzen getrennt bewerten.
   EN: Review startup, dumps/swap/hibernation, debugging, panic/abort/kill, logging, child
   arguments/pipes, failure handling and OS/compiler limits without unsupported guarantees.
4. DE: Befunde priorisieren, belegte Umsetzung von offenen Fragen/externen Grenzen trennen.
   Engen Behebungsplan mit Dateien, Tests, Risiken und Rückweg vorlegen; kein eigener Krypto-
   oder Speicherprovider, kein ungesperrter Fallback, keine Privilegienausweitung.
   EN: Prioritize findings and propose narrow fixes/tests/rollback. No replacement crypto,
   unlocked fallback, privilege escalation or unproved completion.

## Files and validation / Dateien und Prüfungen

DE: DE/EN-Auditbericht, Inventar und Test-/Grenzenmatrix unter `docs/security/`; Roadmap,
CHANGELOG und bestehende Sicherheitsdokumentation nur entsprechend tatsächlicher Ergebnisse
ergänzen. `src/`, Provider, Cargo-Dateien und CI-Sicherheits-/Workflowkonfiguration bleiben gleich.
EN: Add bilingual audit/inventory/test evidence and factual roadmap/changelog/security links.
No production/provider/dependency or CI security/workflow change in this phase.
DE: Eine isolierte Testdatei darf synthetische Standard-/Providerkopien reproduzieren;
sie läuft in der vorhandenen nativen CI, ändert aber keine Anwendungspfade.
EN: An isolated test file may reproduce synthetic std/provider copies in existing native CI,
without changing application paths or asserting that the reported gaps are repaired.

DE: Nur synthetische, nicht geheime Daten in lokalen Proben. Keine fremden Speicherbereiche,
Swap-/Dump-Extraktion, echten Credentials oder geheimen Logs. Isolation/Lock-Status anhand
eigener Prozessmetadaten und vorhandener Test-APIs prüfen; keine Schutzmaßnahmen abschalten.
EN: Synthetic non-secret probes only; no foreign memory, swap/dump extraction, credentials,
secret logs or disabled controls. Use own-process metadata and existing test APIs.

DE: Prüfungen nachweisbar unterscheiden: Quellreview, lokale Komponentengegenprobe,
vorhandener Test und echte native CI. Relevante Positiv-/Negativ-/Grenz-/Abbruchfälle
kartieren; fmt, Clippy, Tests/deny/Limits und Linux-/Windows-CI für finalen PR auswerten.
Ausstehende externe/Hardware-/OS-Beweise bleiben offen und bekommen Zuständigkeit.
EN: Separate source review, local component probes, existing tests and native CI. Map
positive/negative/boundary/failure evidence; verify final PR checks and preserve honest gaps.

## Completion and rollback / Abschluss und Rückweg

DE: Auditabschluss bedeutet geprüftes Inventar und Behebungs-/Teststrategie, nicht behobene
Laufzeitbefunde oder abgeschlossenen Windows-/Provider-Audit. Issue/Board In progress bis
Review/Merge; kein Auto-Merge. Vollständige Rücknahme aller eigenen Commits isoliert auf
exakten Basisbaum prüfen. Keine Datenkonvertierung, Schlüssel-/Archivänderung oder Deployment.
EN: Completion means a verified inventory and remediation/test strategy, not repaired runtime
findings or a completed external/platform audit. Keep In progress pending review/merge.
Prove exact-tree revert; no data/key/archive changes, migration, deployment or auto-merge.
