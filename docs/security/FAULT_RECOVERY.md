# Deterministic faults and crash recovery / Deterministische Fehler und Wiederanlauf

[English](#english) | [Deutsch](#deutsch)

## English

### Scope and approval

Issue [#152](https://github.com/SpecterAoD/pqkeep/issues/152), M2/P2, depends on completed
[#151](https://github.com/SpecterAoD/pqkeep/issues/151) ([PR #251](https://github.com/SpecterAoD/pqkeep/pull/251)).
The maintainer approved the architecture plan and step A on 2026-11-17 (Europe/Berlin).
Step B was separately approved on 2026-11-17: scoped I/O, envelope and STREAM fault tests are
implemented locally; scoped process-crash/restart tests are added in D.
C was separately approved on 2026-11-17 and is implemented locally: factor, archive/decrypt,
cleanup and Unix parent-sync fault cases plus Windows sharing-lock tests. Validation is recorded
separately; native CI remains pending. D was separately approved on 2026-11-17 and implements
acknowledged child termination/restart and multistage tests locally. E requires renewed approval
under SPEC section 0.2. This document is an
architecture decision for test infrastructure, not a new storage/recovery guarantee.

Reviewed base: `53b0ddf9f563d62f48509ae3db1a54264e7f5152`. Read the existing
[threat model](../THREAT_MODEL.md), [key format](../FORMAT.md), [archive format](../FILE_FORMAT.md),
[v2 decisions D1–D4](../V2_DRAFT.md) and [attack catalogue](ATTACK_TEST_MATRIX.md) together.
No cryptography, key/archive format, dependency, public API or sandbox change is authorized.
Rekey #109 and snapshots #124 remain future test subjects. Context-menu registration,
integration manifests and registry writes are outside this bounded data-file test step.

### Existing write and recovery boundaries

| Path | Observed behavior at the reviewed base | Existing tests |
|---|---|---|
| `envelope/io.rs` | Key/public writes: exclusive adjacent temp, write, file sync, close, hardlink without overwrite or rename with consent; error cleanup | `envelope_io`, `envelope_v2` |
| `crypto/factor.rs` | Generate 32 bytes; exclusive temp, file sync and no-overwrite publication | `crypto_factor` |
| `files/encrypt.rs` | Archive and STREAM into buffered temporary output, finish/flush, file sync, close, publish | `files_roundtrip`, `files_output`, `files_v2_roundtrip` |
| `files/decrypt.rs`, `files/output.rs` | Extract only into a private temp file/tree; verify archive/authentication before final publication; normal Drop cleanup | `files_malicious`, `files_tamper_keys`, `files_v2_tamper` |
| `fsutil.rs` | create_new; Unix file mode 0600; hardlink publication; Unsupported fallback checks existence before rename; parent sync best effort on Unix, empty on non-Unix | `envelope_io`, `files_output` |
| `cli/context_child.rs` | Cancellation kills/waits for the child and removes matching own tagged temps; completed targets remain | `context_child_tests`, timed Linux `cli_context_dialog_many` |

Decrypted Unix directories use 0700. Directory publication is check + rename; source-path and
FAT fallback races remain documented. Nested extracted directories are not recursively synced.
Metadata is inside the authenticated key/container publication unit, not a separate recovery
journal. API generate returns JSON without storing a key; archive operations are not REST
endpoints. API token hashes and CLI detached-signature output use envelope atomic writing.
There is no general startup scavenger or automatic promotion of incomplete temporary files.
Drop cleanup and ignored remove errors do not establish cleanup after forced termination.

### Threat model and invariants

Assets are committed valid keys, factors, archives, sources and authenticated output. Controlled
fault sources are local I/O errors and termination of an isolated test child. Untrusted inputs
include truncated headers, invalid lengths/versions, damaged authenticated metadata/tags,
incomplete archives, occupied targets and foreign temporary files. Only private synthetic test
roots are used; no real user data, full disks, mounts, service restarts or OS OOM experiments.

| ID | Required scoped assertion |
|---|---|
| I1 | Before commit, an existing valid file stays byte-identical and usable; sources/factors/archives stay unchanged. After an explicitly permitted replace, a complete valid new file is allowed; no extra old-version backup is promised. |
| I2 | Primary write, flush, file-sync or publication failure returns an error; killed children never count as success. Existing best-effort parent-sync and secondary cleanup semantics remain explicit. |
| I3 | No final plaintext target before full authentication/archive validation; after publish the result is complete and valid. Low-level STREAM may already return verified chunks and is not the file-publication boundary. |
| I4 | No runtime passphrase, private key, factor or secret content in logs, errors, assertion diffs or uploaded artifacts. Private temporary plaintext after kill remains a possible product limitation, inspected before parent cleanup. |
| I5 | The same initial state, point and byte/occurrence index yield the same defined state outcome. OS randomness remains random; independently generated ciphertext need not match. |
| I6 | Restart never adopts damaged temporary data; valid files reopen, incomplete metadata is rejected, foreign files remain, and only known own synthetic remnants are cleaned. |
| I7 | Existing v1/v2, CLI/API, known-answer and replay behavior remains compatible; synthetic pre-change files remain readable after the change and its revert. This does not establish historical-release-binary testing. |

Commit means a successful hardlink or rename, not successful return to the caller. A process can
die after publishing a complete valid target but before reporting success. A successful hardlink
followed by failed temp unlink can return Err with a valid target. Cleanup must not destroy it.
A replace failure before commit preserves the old key; after commit the complete new key is valid.

**Process crash:** kernel/filesystem remain running. **OS crash:** volatile kernel state can be
lost. **Power loss:** device/controller caches also matter. Kill tests establish only the first
case. Rename, file sync and best-effort parent sync alone prove neither of the latter cases.
Actual panic-abort, OOM, WER/hibernation, AV compatibility, all Linux filesystems, real FAT/network
filesystems, Windows ACL/reparse safety and ARM64 64-KiB pages require separate evidence.
New vulnerabilities follow the private reporting policy in SECURITY.md; discoveries do not
authorize product repairs, public proofs of concept or weakened test expectations.

### Decision: test-only, scoped I/O and acknowledged child termination

Reuse existing Read/Write generics for short writes, Interrupted, WriteZero and flush failures.
For filesystem paths, plan an internal output-file binding: std::fs::File normally, a real-file
Write/flush/sync_all wrapper only under cfg(test). Keep normal syscall order and error contracts.
Add cfg(test) checkpoints without a Cargo feature, CLI/env switch, public API or remote control.
Normal debug/release binaries and the normally linked integration-test library have no hooks.
Lib unit-test children provide injected core evidence; ordinary CLI/API tests remain separate.

Each fault plan has a private root, named point, byte/occurrence index and action, scoped by
thread-local RAII rather than global counters. Verify plan consumption and restore state after
normal unwinding; fail on unsupported nesting/unreached points. Preserve real random temp names.
Model platform-correct ENOSPC/EACCES and write/flush/sync/link/rename/remove outcomes. Otherwise
use real files and publication. No crypto/RNG hooks, new crates or unsafe code are planned.

Points: BeforeOpen, AfterTempCreate, Write(N), BeforeFlush, BeforeFileSync, BeforePublish,
AfterPublish, BeforeHardLink, BeforeRename, BeforeDirSync (Unix only), BeforeRemoveFile, BeforeRemoveDirAll;
AfterFirstOperation is reached in a test-driven sequence of real envelope saves. Ordered
multi-fault plans verify consumption; Pause/PauseAfter blocks only the selected test child.
Observe hardlink publication separately from temp unlink. Synthetic sizes: 0/1/65535/65536/
65537 bytes and several chunks; empty/nested trees; factor-write boundaries 0/1/31/32 bytes.

The parent starts its own lib test binary at an exact test entry and sends a bounded stdin
protocol; secrets travel only through pipes/memory. The child acknowledges the chosen point
without content/secret output and blocks. Only then does the parent kill and wait: SIGKILL on
Linux, native forced termination on Windows. Deadlines are failure watchdogs, never scheduling
triggers or passing skips. A child guard kills/waits on parent test failure; the parent owns the
private TempDir, inspects the state, then removes its own synthetic fixtures. Harden test children
before secrets. Do not add abort tests that can produce WER/minidumps. Windows share_mode(0)
tests model native sharing locks, not a real antivirus product. Never upload raw fixtures/dumps.

Rejected alternatives: time-based kill cannot select a deterministic write point; Read/Write
mocks alone cannot exercise filesystem commit/cleanup; global hooks disturb concurrent tests;
production-activatable fault features violate scope. No new automatic recovery service is added.

### Planned coverage, steps and evidence

REC-005/015 are implemented in B; REC-006–009/014 and FS-009 in C, all recorded as partial.
D implements REC-010–013 locally; all new cases remain partial pending signed source/native CI:

| Planned ID | Scope |
|---|---|
| QA1-REC-005 / QA1-REC-006 | Key replacement before commit / factor creation failures |
| QA1-REC-007 / QA1-REC-008 | Archive encryption failures / decrypt file-tree errors and late tampering |
| QA1-REC-009 / QA1-REC-010 | Primary plus cleanup failures / process death before commit |
| QA1-REC-011 / QA1-REC-012 | Process death after publication / restart with stale temps and incomplete metadata |
| QA1-REC-013 / QA1-REC-014 | Multi-stage interruption / best-effort parent synchronization |
| QA1-REC-015; QA1-FS-009 | Scope isolation and repeatability; native Windows sharing locks |

A: document this design and roadmap. B: scoped adapter, envelope/STREAM controls. C: factor,
archive/decrypt/cleanup and Windows locks. D: acknowledged crash/restart/multi-stage cases.
E: final evidence, native CI, documentation and practical rollback. Renew approval between steps.
Production-source edits are limited to test binding/checkpoints in lib.rs, fsutil.rs,
envelope/io.rs, crypto/factor.rs and files/output.rs, encrypt.rs, decrypt.rs. B changes only
lib.rs/fsutil/envelope plus mechanical output/decrypt type bindings. C adds only factor/output/
fsutil hooks and lib wiring; existing shared output paths avoid additional encrypt/decrypt edits.
D changes only lib test wiring, existing test helpers and CLI tests; no further production I/O edits.
Unexpected architecture changes need another proposal. Test code stays in
separate *_tests.rs or tests/ files within the existing line limits.

A retained 1.0.1. B–D prepare draft 1.1.0 with twelve new partial cases (59 total),
schema 1 and QA1 IDs linked to #152. Original-case V/C/U mappings and all eleven historical
evidence records are unchanged.
The recorded reviewed-source SHA remains the historical #151 anchor, not B–D execution proof.
The original 47 cases and historical baseline are unchanged; REC-015 gains sequence/driver assertions; FS-009 adds CLI cleanup-lock coverage.
New cases stay partial with no evidence_refs until a signed source revision/native CI is recorded;
local uncommitted results use external patch/file hashes, never a fictitious tested commit.
FS-007/008 and REC-002/003 retain untested variants; MEM-006 remains missing for actual OOM.
Local kill tests close only their asserted process-crash scope, never OS/power-loss gaps. Record only real
executions with full SHA, UTC, OS/runner/features, run/job/attempt, exact test references and limits.
Use [DEVELOPMENT.md](../DEVELOPMENT.md) and existing native Linux x86_64/ARM64 and Windows x86_64
CI. No-default runtime remains on Ubuntu latest/Windows latest. No new workflow/job/permission
or fixture upload is planned; existing cargo test discovers the tests. CodeQL excludes test files;
explicit review is still needed. Compilation, cfg exclusions and internal early returns are not
passed assertions. Two ignored private child-entry helpers are invoked explicitly by parent tests,
not counted as passing scenarios. Captured child output is bounded and protocol-checked; stdout
contains no payload. Local Linux SIGKILL proof is separate from pending native Windows/ARM64 CI;
no OS/power-loss durability is established. CLI cleanup tests use a synthetic child-remnant fixture.

### Rollback and completion gate

Back up directly edited files/modes outside the worktree and verify hashes before approved edits.
Use small signed commits. Before merge, practically revert only this work in a separate worktree,
compare the expected base, run fmt/limits/smoke and reopen/check/decrypt synthetic pre-change
v1/v2 keys/factors/archives with unchanged hashes. This is a planned check, not already executed.
Post-merge rollback uses a separate signed revert PR, CI and approval; no data migration.
Done requires approved steps, scoped invariants, positive/negative/boundary/tamper/crash/restart
assertions, actual native Linux/Windows results, all required checks, bilingual docs, truthful
matrix evidence, review and rollback proof. Start the draft PR with Refs #152; no automatic merge,
release or issue closure. A documentation approval alone is not implementation completion.

## Deutsch

### Umfang und Freigabe

Issue [#152](https://github.com/SpecterAoD/pqkeep/issues/152), M2/P2, folgt auf abgeschlossenes
[#151](https://github.com/SpecterAoD/pqkeep/issues/151) ([PR #251](https://github.com/SpecterAoD/pqkeep/pull/251)).
Der Maintainer hat Gesamtentwurf und Schritt A am 17.11.2026 (Europe/Berlin) freigegeben.
B wurde am 17.11.2026 separat freigegeben: Scoped-I/O, Envelope-/STREAM-Fehlertests sind lokal
implementiert. C wurde am 17.11.2026 separat freigegeben und ist lokal implementiert:
Faktor-/Archiv-/Entschlüsselungs-/Cleanup-/Unix-Eltern-sync-Fehler und Windows-Sharing-Locktests.
Validierung getrennt; native CI steht aus. D wurde am 17.11.2026 separat freigegeben:
bestätigte Child-Abbrüche/Neustart-/Mehrstufentests lokal implementiert. E benötigt gemäß
SPEC 0.2 erneute Freigabe. Dies ist eine Architekturentscheidung
für Tests, keine neue Speicher-/Recoverygarantie. Geprüfte Basis ist
`53b0ddf9f563d62f48509ae3db1a54264e7f5152`; bestehendes Threat Model, Formate, D1–D4 und Katalog
gelten gemeinsam (Links oben). Keine Krypto-/Format-/Abhängigkeits-/öffentliche API-/Sandboxänderung.
#109/#124 bleiben spätere Prüfgegenstände; Registrierung, Integrationsmanifeste und Registry außen vor.

### Bestehende Grenzen und Invarianten

Die englische Pfadtabelle bezeichnet dieselben geprüften Schreibwege: Envelope für Schlüssel,
öffentliche Schlüssel, Tokenhash und CLI-Signaturausgabe; Faktor-Erzeugung; Archiv/STREAM-Ausgabe;
Extraktion über TempOutput; gemeinsame fsutil-Veröffentlichung und getaggtes CLI-Abbruch-Cleanup.
Exklusive benachbarte Temps, Unix-Dateirechte 0600/Ordner 0700, Datei-sync und Vollprüfung vor
Publish bestehen. Unix-Eltern-sync ist best effort, nicht-Unix leer. Unterordner werden nicht
rekursiv synchronisiert. Verzeichnis-/FAT-Publish und Source-TOCTOU haben dokumentierte Rennen.
Metadaten gehören zur authentifizierten Datei, kein Recoveryjournal. API generate persistiert
keinen Schlüssel; Archive sind keine REST-Endpunkte. Kein allgemeiner Startup-Scavenger oder
automatisches Übernehmen unvollständiger Temps. Drop/ignorierte remove-Fehler beweisen kein Crash-Cleanup.

Assets: gültige Schlüssel/Faktoren/Archive/Quellen und authentifizierte Ausgabe. Fehlerquellen:
lokale I/O-Fehler und Tod nur eines isolierten Testkindes. Fremde Eingaben: gekürzte Header,
ungültige Längen/Versionen, kaputte Metadaten/Tags/Archive, belegte Ziele und fremde Temps.
Nur private synthetische Testroots; keine Nutzerdaten, vollen Laufwerke, Mounts, Dienstneustarts/OOM.

- **I1:** Vor Commit bestehende gültige Datei bytegleich und nutzbar, Quellen/Faktoren/Archive erhalten.
  Nach ausdrücklich erlaubtem Replace ist die vollständige neue Datei zulässig; kein Extra-Backupversprechen.
- **I2:** Primäre Write-/Flush-/Datei-Sync-/Publishfehler liefern Fehler; kill ist nie Erfolg.
  Best-effort-Eltern-sync und sekundäres Cleanup bleiben ausdrücklich getrennt.
- **I3:** Kein endgültiges Klartextziel vor Vollprüfung; nach Publish vollständig und gültig.
  Bereits geprüfte STREAM-Blöcke sind keine Veröffentlichung durch die Datei-API.
- **I4:** Keine Laufzeit-Geheimnisse in Logs/Fehlern/Assertion-Diffs/Uploads. Temporärer Klartext nach
  kill bleibt mögliche Produktgrenze; Parent prüft ihn vor eigener Testbereinigung.
- **I5:** Gleicher Ausgangszustand/Punkt/Byte- oder Vorkommensindex ergibt denselben Zustandsbefund.
  OS-Zufall bleibt zufällig; unabhängige Chiffrate müssen nicht bytegleich sein.
- **I6:** Kein Übernehmen beschädigter Temps; gültige Dateien öffnen, unvollständige Metadaten
  abweisen, Fremdes erhalten und nur bekannte eigene synthetische Reste entfernen.
- **I7:** v1/v2, CLI/API, KAT und Replay bleiben kompatibel; synthetische Altdateien nach Änderung
  und Revert lesbar. Kein dadurch behaupteter Lauf historischer Release-Binaries.

Commit = erfolgreicher Hardlink/Rename, nicht erfolgreiche Rückkehr zum Aufrufer. Nach Commit
kann das Kind vor Erfolgsmeldung sterben; nach Hardlink kann Temp-Unlink mit Err scheitern, obwohl
das Ziel vollständig ist. Cleanup darf dieses Ziel nicht zerstören. Vor Replace-Commit bleibt
der alte Schlüssel; danach darf der vollständige neue gelten.
Prozesscrash lässt den Kernel laufen, OS-Crash verliert flüchtigen Kernelzustand, Stromverlust
betrifft zusätzlich Geräte-/Controllercache. Kill beweist nur Ersteres. Rename/Datei-sync/
Best-effort-Eltern-sync beweisen keine OS-/Stromausfall-Dauerhaftigkeit. Echter Panic-Abort/OOM,
WER/Hibernation, Antivirus, alle Linux-FS, echtes FAT/Netz-FS, Windows-ACL/Reparse und ARM64 mit
64-KiB-Seiten brauchen eigene Nachweise. Neue Lücken privat nach SECURITY.md behandeln; keine
automatische Reparaturfreigabe, öffentliche PoCs oder abgeschwächten Testerwartungen.

### Architekturentscheidung und geplante Nachweise

Bestehende Read/Write-Generics für kurze Writes, Interrupted/WriteZero und Flushfehler nutzen.
Interne Ausgabedatei-Bindung: normal std::fs::File, nur unter cfg(test) echter Dateiwrapper für
Write/flush/sync_all. Normale Syscallreihenfolge/Fehlerverträge erhalten; nur testgebundene Punkte.
Keine Cargo-Features, CLI-/Umgebungs-Hooks, öffentliche API, Remote-Steuerung, Krypto-/RNG-Hooks,
neuen Crates oder unsafe. Normale Debug-/Release-Binaries und Integrationstest-Library ohne Hooks;
instrumentierte Lib-Tests und normale CLI/API-Nachweise getrennt halten.
Threadlokale RAII-Pläne mit privatem Root, Punkt, Byte-/Vorkommensindex und Aktion; Verbrauch und
Restaurierung prüfen, unzulässiges Verschachteln/unerreichte Punkte scheitern lassen. Echte zufällige
Tempnamen erhalten; ENOSPC/EACCES/write/flush/sync/link/rename/remove plattformgerecht simulieren,
sonst echtes Dateisystem. Benannte Punkte, Grenzgrößen und zwölf reservierte IDs stehen oben;
alle gelten für beide Sprachen. REC-005/015 sind in B, REC-006–009/014 und FS-009 in C
implementiert; D ergänzt REC-010–013 lokal. Alle neuen Fälle bleiben partial bis signierte
Quell-/native CI-Nachweise vorliegen. BeforeHardLink/BeforeRename
unterscheiden Publish-Pfade; BeforeDirSync ist Unix-only. AfterFirstOperation liegt in einer
testgesteuerten Folge echter Envelope-Aufrufe; Pause/PauseAfter blockieren nur das Testkind.
Geordnete Mehrfachpläne prüfen jeden Verbrauch.

Parent startet eigenes Libtest-Binary mit exaktem Testnamen, übergibt begrenztes stdin-Protokoll
und Secrets nur über Pipe/Speicher. Kind bestätigt Punkt ohne Inhaltsausgabe und wartet; erst
dann kill/wait (Linux SIGKILL, Windows harter Abbruch). Fristen sind Watchdogfehler, keine
Zeitsteuerung/erfolgreichen Skips. Child-Guard beendet/wartet auch bei Testfehlern; Parent besitzt
TempDir, prüft Zustand und räumt nur synthetische eigene Daten auf. Kinder vor Secrets härten.
Keine abort-Tests mit WER/Minidumps; Windows share_mode(0) prüft Dateisperren, kein echtes AV.
Keine Rohfixtures/Dumps hochladen. Zeitabbruch ist nicht deterministisch, reine Read/Write-Mocks
erreichen Commit/Cleanup nicht, globale Hooks stören Paralleltests, produktive Fault-Features
widersprechen dem Scope. Keine automatische Recoveryfunktion hinzufügen.

A dokumentiert; B Adapter/Envelope/STREAM; C Faktor/Archive/Decrypt/Cleanup/Windows-Locks;
D bestätigte Crashes/Neustart/Mehrstufen; E Nachweise/CI/Doku/Rollback. Jeweils erneut freigeben.
Produktionsdateien nur lib.rs, fsutil.rs, envelope/io.rs, crypto/factor.rs und files/output.rs,
encrypt.rs, decrypt.rs für Testbindung/Punkte. B ändert lib.rs/fsutil/envelope sowie mechanische
output/decrypt-Typbindungen. C ergänzt nur Faktor-/Output-/fsutil-Punkte und Lib-Verdrahtung;
gemeinsame Ausgabepfade vermeiden weitere encrypt/decrypt-Edits. D ändert nur Lib-Testverdrahtung,
Testhelfer und CLI-Tests, keine weiteren produktiven I/O-Pfade. Unerwartete Architekturänderungen
erneut vorlegen; Tests separat innerhalb bestehender Zeilenlimits.
A beließ 1.0.1. B–D bereiten Entwurf 1.1.0 mit zwölf neuen partial-Fällen (59 gesamt),
Schema 1, QA1 und #152 vor; REC-015 ergänzt Sequenz-Assertions.
Die ursprünglichen 47 Altfälle/V-C-U und elf historischen Nachweise bleiben unverändert; die Review-SHA bezeichnet
weiter den historischen #151-Stand, keinen B–D-Testnachweis. Neue Fälle bleiben partial ohne
evidence_refs bis signierte Quellrevision/native CI vorliegen; lokale uncommittete Ergebnisse
werden extern mit Patch-/Dateihashes belegt, nie mit erfundener Test-SHA.
Breite FS-007/008-, REC-002/003-Lücken und echter OOM MEM-006 bleiben sichtbar.
Nur echte Läufe mit SHA/UTC/OS/Runner/Features/Run/Job/Attempt/Tests/Grenzen erfassen. Bestehende
native Linux-x86_64/ARM64-/Windows-x86_64-CI nutzen; No-default-Runtime auf Ubuntu latest/Windows.
Keine neuen Workflows/Jobs/Rechte/Uploads, Entdeckung über cargo test. CodeQL ignoriert Testdateien,
explizites Review bleibt nötig. Kompilierung/cfg-Ausnahmen/interne Rücksprünge sind keine bestandenen
Assertions. Zwei ignorierte private Child-Einstiege werden von Parent-Tests explizit gestartet,
aber nicht als bestandene Szenarien gezählt. Kindausgaben sind begrenzt/protokollgeprüft, ohne
Payload. Lokale Linux-SIGKILL-Nachweise ersetzen keine native Windows-/ARM64-CI oder
OS-/Stromausfallgarantie. CLI-Cleanup nutzt synthetische, tatsächlich im Kind erzeugte Abbruchreste.

### Rückweg und Abschluss

Betroffene Dateien/Rechte vor freigegebenen Edits außerhalb Worktree sichern, Hashes prüfen;
kleine signierte Commits. Praktische Revertprobe im separaten Worktree: nur eigene Arbeit zurück,
Basisbaum vergleichen, fmt/Limits/Smoke, synthetische v1/v2-Schlüssel/Faktoren/Archive mit
unveränderten Hashes erneut öffnen/check/decrypt. Geplant, noch nicht durchgeführt. Nach Merge
separater signierter Revert-PR mit CI/Freigabe, keine Datenmigration.
Done verlangt freigegebene Schritte, Invarianten im Scope, Positiv-/Negativ-/Grenz-/Tamper-/Crash-/
Neustarttests, echte native Linux-/Windows-Ergebnisse, Pflichtchecks, DE/EN-Doku, ehrliche Matrix,
Review und Rollbacknachweis. Draft-PR zunächst Refs #152; kein automatischer Merge/Release/
Issue-Abschluss. Dokumentationsfreigabe allein schließt die Implementierung nicht ab.
