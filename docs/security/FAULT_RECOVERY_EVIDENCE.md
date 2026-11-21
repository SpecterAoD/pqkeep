# Fault recovery evidence / Nachweise für Fehler und Wiederanlauf

## English

Issue [#152](https://github.com/SpecterAoD/pqkeep/issues/152), A–D approved on 2026-11-17,
E on 2026-11-20. [Merged PR #279](https://github.com/SpecterAoD/pqkeep/pull/279) records final
local checks and PR CI; the owner authorized merge and issue completion on 2026-11-21.
No production deployment. Post-merge test-driver correction: [PR #280](https://github.com/SpecterAoD/pqkeep/pull/280).

### Source and executed assertions

Signed implementation: `ba52dcd99a7326f3bbb2add69dde25deab3dc94f`, based on main
`9683df8ae8f8b284b4854fcd3e9d856a0edd947b`. Four thematic A–D commits and a separate Windows
expectation correction have valid GitHub signatures. CI actually checked out
`aa80258d60a81ef02f97a8b90e91a93505ccaae2`; its complete tree equals the signed implementation.
The evidence/documentation commits in PR #279 preserve product, test, dependency and workflow bytes.

[CI 44820659991](https://github.com/SpecterAoD/pqkeep/actions/runs/44820659991), attempt 1:

| Runner / platform | Job | Default passed | No-default passed |
|---|---|---:|---:|
| Ubuntu latest / Linux x86_64 | [136580413180](https://github.com/SpecterAoD/pqkeep/actions/runs/44820659991/job/136580413180) | 581 | 542 |
| Ubuntu 22.04 / Linux x86_64 | [136580413283](https://github.com/SpecterAoD/pqkeep/actions/runs/44820659991/job/136580413283) | 581 | not run |
| Ubuntu 22.04 ARM / Linux ARM64 | [136580413074](https://github.com/SpecterAoD/pqkeep/actions/runs/44820659991/job/136580413074) | 581 | not run |
| Windows latest / Windows x86_64 | [136580413305](https://github.com/SpecterAoD/pqkeep/actions/runs/44820659991/job/136580413305) | 519 | 482 |

Each suite has zero failed tests and two ignored private child entries explicitly invoked by
parent tests. They are never counted as passed attack scenarios. All applicable named new
assertions were found as passed in each recorded feature/platform log. Unix-only parent/symlink
and directory-sync assertions are excluded from Windows evidence, not counted as passing skips.
ARM64 reports Linux 6.8.0-1070-azure, 4096-byte pages and rustc 1.100.0. Environment values not
printed by other jobs remain unknown. This is no 64-KiB-page or Windows ARM64 result.

All ten CI jobs passed, including native fmt/clippy with both configurations, MSRV, release
binary hardening, limits, cargo-deny and gitleaks. [CodeQL](https://github.com/SpecterAoD/pqkeep/actions/runs/44820660008)
and [dependency review](https://github.com/SpecterAoD/pqkeep/actions/runs/44820660233) passed.
Existing workflows discover the tests; no new jobs, dependencies, privileges or uploads.
Workflow policy is unchanged and not triggered by this PR's paths; its local validator is
included in final local checks. CodeQL excludes test files; those files were explicitly reviewed.

### Initial failure, coverage and limits

The [initial Windows run](https://github.com/SpecterAoD/pqkeep/actions/runs/44819132853/job/136575140904)
failed two lock-test expectations: Rust mapped a sharing violation to Uncategorized instead of
PermissionDenied. The correction first requires raw Windows error 32 from an ordinary open
under the same share_mode(0) lock, then requires exact propagation of its ErrorKind. Preservation,
no-final-plaintext and successful retry checks remain. No product repair or weaker generic
is_err-only expectation was introduced. The failed record is retained beside successful reruns.

Matrix/baseline 1.1.0 has 59 cases: 36 covered, 11 partial, 8 missing, 2 manual,
2 not-applicable. The original 47 cases and eleven historical records remain unchanged. Twelve
new narrowly bounded cases REC-005–015/FS-009 become covered only after all applicable references
have actual native execution proof. Six passed CI records and the initial failed record give
18 evidence records in total. Historical records remain tied to their earlier sources.

Named checkpoints/byte indices select errors; child ACK selects kill/wait, with bounded pipes,
secret-safe output checks and parent-failure reaping. Watchdogs are failure bounds. Native
Windows locks model sharing semantics, not antivirus. Multistage tests drive real core saves,
not a production batch/UI transaction. Process termination retains a running kernel. Parent-sync
is still best effort; own private plaintext temps can survive kill. Broad OOM/race/WER/AV/ACL/
reparse/OS-crash/power-loss gaps remain open. No raw secrets, fixtures, plaintext or dumps uploaded.
Ordinary builds expose no fault feature, environment variable, CLI switch or remote interface.

### Practical rollback and compatibility

A separate worktree practically reverted the four A–D commits and reproduced the exact main
base tree. Formatting, limits, base build and smoke passed. Runtime-generated v1/v2 key files,
v2 factor and v1/v2 passphrase archives plus recipient archives were opened/checked/decrypted
before the change, with the implementation and after revert. Stored keys were actually unlocked
by recipient-archive check/decrypt. All protected source/key/factor/archive hashes stayed equal.
Fixtures lived only in a private temporary directory and were removed. No historical-release-
binary claim. Final test/report-only changes are included in the final PR rollback review.
After merge: separate signed revert PR, CI and explicit approval; no user-data migration.

## Deutsch

Issue #152: A–D am 17.11.2026, E am 20.11.2026 freigegeben. PR #279 erfasst finale lokale
Prüfungen und PR-CI; Merge und Issue-Abschluss am 21.11.2026 ausdrücklich freigegeben.
Kein Produktionsdeployment. Nachträgliche Testtreiberkorrektur: PR #280 (oben verlinkt).

Signierte Implementierung, main-Basis, tatsächlicher CI-Checkout und Joblinks stehen oben.
Vier fachliche Commits plus separate Windows-Testkorrektur gültig GitHub-signiert. Der
CI-Checkout ist vollständig bytegleich zur signierten Quelle; Nachweis-/Dokucommits in PR #279
lassen Produktivcode, Tests, Abhängigkeiten und Workflows unverändert.

Native Ergebnisse: Linux Default je 581; No-default Ubuntu latest 542. Windows 519/482.
Alle Suiten ohne Fehler; jeweils zwei ignorierte private Child-Einstiege werden explizit von
Parenttests gestartet, zählen aber nicht als bestandene Angriffsfälle. Jeder anwendbare neue
Testverweis ist im jeweiligen Plattform-/Featurelog als bestanden nachgewiesen. Unix-only-
Assertions zählen unter Windows nicht als Erfolg. ARM64 mit Linux 6.8.0-1070-azure, 4096-Byte-
Seiten, rustc 1.100.0; nicht ausgegebene Umgebungswerte unknown. Keine Windows-ARM64-/64-KiB-Probe.

Alle zehn CI-Jobs, CodeQL und Dependency Review erfolgreich. Bestehende CI erkennt die Tests;
keine neuen Jobs, Crates, Rechte oder Rohuploads. Workflow-Prüfung mangels betroffener Pfade
nicht gestartet, lokaler Validator in den Abschlusschecks. Testcode trotz CodeQL-Ausnahme
explizit geprüft. Erste Windows-Sperrtests erwarteten fälschlich PermissionDenied statt
Uncategorized. Korrektur fordert zunächst nativen OS-Fehler 32 unter derselben Sperre und danach
exakte ErrorKind-Weitergabe. Bestandsschutz, keine finale Teilausgabe und Retry bleiben bestehen.
Der fehlgeschlagene Lauf bleibt nachvollziehbar erfasst; keine Produktivcode-Reparatur.

Matrix/Baseline 1.1.0: 59 Fälle (36 covered, 11 partial, 8 missing, 2 manual, 2 not-applicable).
Ursprüngliche 47 Fälle und elf historische Nachweise unverändert. Zwölf neue begrenzte Fälle
REC-005–015/FS-009 erst nach nativen Einzelnachweisen covered. Sechs bestandene Datensätze plus
erster Windows-Fehllauf ergeben insgesamt 18. Historische Ergebnisse gelten für ihre Quellen.

Punkt-/Byte-/Vorkommenswahl, ACK vor kill/wait, begrenzte Pipes, geheime Inhalte nicht in Logs
und Child-Reaping bei Parentfehlern. Fristen nur Fehlergrenzen. Windows-Sharing-Locks sind kein
Antivirusnachweis, testgesteuerte Core-Saves keine produktive Batch-/UI-Transaktion. Prozesskill
bei laufendem Kernel; Eltern-sync bleibt best effort, private Klartext-Temps können verbleiben.
Breite OOM-/Race-/WER-/AV-/ACL-/Reparse-/OS-/Stromverlustlücken bleiben offen. Keine Rohsecrets,
Fixtures, Klartexte oder Dumps hochladen; normale Builds haben keine aktivierbaren Fault-Hooks.

Praktische A–D-Rücknahme im eigenen Worktree ergibt exakt die main-Basis. fmt, Limits, Build
und Smoke bestanden. Synthetische v1/v2-Schlüssel und Passphrase-Archive, v2-Faktor sowie
Empfängerarchive vor Änderung, mit Implementierung und nach Revert geöffnet/geprüft/entschlüsselt;
Schlüssel tatsächlich über Empfängerarchive entsperrt. Quellen-/Schlüssel-/Faktor-/Archivhashes
unverändert, private temporäre Fixtures entfernt. Kein historischer Release-Binarytest.
Finale Test-/Berichtsänderungen gehören zum abschließenden PR-Rücksetzreview. Nach Merge
separater signierter Revert-PR mit CI und ausdrücklicher Freigabe, keine Nutzerdatenmigration.

## Post-merge driver regression / Nachträgliche Testtreiberkorrektur

EN: [Main CI 44838917029](https://github.com/SpecterAoD/pqkeep/actions/runs/44838917029/job/136642157083)
exposed a BrokenPipe race: a restart child without a pause could exit before the parent sent
an unneeded continuation byte. This is a test-protocol failure, not a storage failure. The owner
approved PR #280's test-only correction: send continuation only after an acknowledged pause.
The regression forces child exit before finish and failed deterministically on the old driver.
Exit status, bounded output, secret checks and ACK-before-kill assertions remain; no ignored
BrokenPipe, retry, sleep-based scheduling or production changes. Final execution is recorded in
PR #280; the historical native records above retain their original source and counts.

DE: Der verlinkte Main-CI-Lauf zeigte ein BrokenPipe-Rennen: Ein Neustart-Kind ohne Haltepunkt
konnte vor dem unnötigen Fortsetzungsbyte enden. Testprotokollfehler, kein Speicherfehler.
Freigegebene reine Testkorrektur in #280: Fortsetzung nur nach bestätigtem Haltepunkt.
Regression erzwingt Child-Exit vor finish und scheiterte mit altem Treiber deterministisch.
Exitstatus, begrenzte Ausgabe, Secret- und ACK-vor-Kill-Prüfungen bleiben erhalten; kein
ignorierter BrokenPipe, Retry, zeitgesteuerter Ablauf oder Produktivcode-Edit. Finale Ausführung
in PR #280; historische Nachweise oben behalten ihre Quellrevisionen und Testzahlen.
