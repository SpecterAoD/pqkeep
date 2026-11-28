# Attack test matrix and baseline / Angriffstest-Matrix und Baseline

[English](#english) | [Deutsch](#deutsch)

## English

### Scope and approval

Issue [#151](https://github.com/SpecterAoD/pqkeep/issues/151), QA-1. The maintainer approved the
thirteen-file implementation plan on 2026-11-16 before implementation: versioned catalogue and
execution evidence, offline validation, two replay characterization tests, existing CI integration
and bilingual documentation. No production, cryptography, format or dependency changes.
The separate [roadmap draft #247](https://github.com/SpecterAoD/pqkeep/pull/247) remains independent.

The catalogue records existing assertions and missing evidence; it does not certify that every
attack is prevented. Reuse the [v2 catalogue](../V2_TESTS.md), [threat model](../THREAT_MODEL.md) and
[CI policy](CI_SECURITY.md). Related hardening #129 and #147–#150 remains open.
#152 owns deterministic fault/crash/recovery injection, #153 expanded parser/IPC/permission
fuzzing and sanitizer work, #154 reproducible builds, independent audit and the release gate.
Approved #152 A–E finalizes 1.1.0: 59 cases; twelve new bounded cases have native execution proof.
1.2.0 adds QA1-FMT-010 (#44, sender signature in `.pqkf`, format v3): 60 cases; its CI evidence
follows with the next baseline run.
1.3.0 adds QA1-FMT-011 (#316/#83, format v4 stream core): 61 cases; CI evidence follows likewise.
1.4.0 adds QA1-FMT-012 (#316, PADMÉ padding): 62 cases; CI evidence follows likewise.
1.5.0 adds QA1-FMT-013 (#316/#340, anonymous recipients, experimental, partial): 63 cases.
1.6.0 adds QA1-FMT-014 (#316, hidden sender): 64 cases.
1.7.0 adds QA1-FMT-015 (#335, container integrity matrix); QA1-FMT-003 covered, QA1-REC-003 partial (kill test, limit L1 → #338): 65 cases.
1.8.0: QA1-FS-008 partial (#338, deterministic race tests; gaps reproduced, fixes in PR 2–4): 65 cases.
1.9.0: QA1-FS-008 – Linux fixed (GHSA-9vh5-2vch-2r68, handle-based output); Windows and sources open: 65 cases.
[Execution evidence](FAULT_RECOVERY_EVIDENCE.md) pins signed source/CI; broad original gaps stay open.

### Files, status and execution

- [attack-matrix.json](attack-matrix.json) is the authoritative case source, initially 47 cases.
- [attack-baseline.json](attack-baseline.json) contains separately versioned execution records.
- `python3 scripts/check_attack_matrix.py --summary` prints a bilingual table without maintaining
  a second copy. Run from the repository root; omit `--summary` for validation only.
- `python3 -m unittest discover -s scripts -p 'test_attack_matrix.py' -v` tests the validator.

| Coverage status | Meaning |
|---|---|
| `covered` | Existing automatic assertions cover this narrowly described case on its stated platforms |
| `partial` | Some variants, preconditions or evidence are missing |
| `missing` | No dedicated test/evidence found, including guarantees the product does not offer |
| `manual` | Controlled manual verification is needed; not executed merely by documenting it |
| `not-applicable` | The mechanism/component does not apply to this platform or current product; reason required |

`implementation_state` independently distinguishes `implemented`, `documented-only`,
`not-implemented` and `not-applicable`. `automation` distinguishes `automated`, `automatable`,
`manual` and `not-applicable`. Neither field establishes successful execution.
Execution uses `passed`, `failed`, `skipped`, `not-run` or `unknown` in baseline records.
A documented test, successful compilation or green parent job is not a passed security assertion.
Empty evidence references mean **no recorded execution**, even when a test exists.

### Data contract, version 1

Both documents require integer `schema_version: 1`; unknown fields and duplicate JSON keys fail.
Matrix: `matrix_version` (SemVer), `reviewed_source_commit` (full 40-character SHA), `cases`.
Baseline: `baseline_version` (SemVer), matching `matrix_version`, `evidence`.

| Case field | Contract |
|---|---|
| `id`, `category`, `component_paths` | Stable `QA1-<CRY/FMT/FS/MEM/ISO/REC/API/PLT>-NNN`, category, existing component files |
| `scenario`, `expected_behavior`, `boundary`, `preconditions` | Objects with nonempty, equally maintained `de` and `en` text |
| `implementation_state`, `coverage_status`, `automation` | Independent implementation, scoped test coverage and automation states |
| `platforms`, `features` | OS/architecture profiles and relevant default/no-default/api feature conditions; individual test cfg conditions still apply |
| `test_refs` | Path, exact function/symbol, kind and `stage: existing|planned`; empty requires a gap |
| `ci_refs` | Workflow path, job key, runner filter, gate mapping, existing/planned stage |
| `priority`, `issues`, `v2_ids`, `evidence_refs` | Evidence priority P1–P3, issue numbers, existing V/C/U IDs, execution-record IDs |
| `gap`, `next_evidence` | Bilingual missing variant and next evidence step; null only for covered cases |
| `retired`, `replacement` | Keep retired IDs visible; optional replacement must exist and differ |

Test kinds: `rust-integration`, `rust-unit`, `doctest`, `python`, `fuzz`, `manual`.
The validator checks local file/symbol presence, **not** language semantics, compiled attributes,
assertion strength or the truth of a CI result. It never imports referenced files, executes stored
commands or accesses the network. Absolute/traversal paths and symlinks escaping the repository fail.
Planned references cannot establish `covered` or a `passed` result.
Workflow validation recognizes this repository's indented job form; actionlint and existing
workflow policy remain responsible for full workflow checks. `required-except-arm64` maps the
existing CI test jobs: three protected runner checks, optional native ARM64. It changes no rules.

Each evidence record identifies `id`, `source_commit`, observation time `observed_utc`, `origin`
(local/ci), `result`, platform, runner, feature configuration, observed environment, scoped
case/test references and bilingual `limits`. CI requires positive run/job/attempt IDs and the
matching job URL. Local records have null CI identifiers and URL. Kernel, page size or toolchain
not observed are `unknown`. Case/evidence references are reciprocal; a result covers only its
listed test references and environment. Partial/missing variants stay open despite a passing
subset. Historical records are not results on the current revision.

### Maintenance and reproduction

Never reuse IDs. Add cases with a MINOR matrix version; wording/reference corrections without
changed expectations use PATCH. Changed security semantics or incompatible contract require MAJOR
and review. Baseline updates have their own version and pin the matching matrix version.
Keep retired cases with reasons and optional replacement IDs. Git preserves older snapshots.
Review version bumps and ID continuity in the PR; the offline validator cannot infer semantic
changes or historical ID reuse from a shallow checkout.

Record real executions only, with full source SHA, platform/features, UTC observation date,
run/job/attempt and assertion scope. If logs expire, mark the evidence `unknown` and explain the
loss; never reconstruct a green result. Retain sanitized excerpts and hashes outside Git when
needed. Do not commit generated keys, encrypted archives, raw fuzz corpora or secret-bearing logs.
A reporting-only commit may follow a tested revision: record the tested SHA and verify unchanged
relevant product/test/workflow files rather than making a self-referential HEAD claim.

```text
cargo test --locked --test files_replay
cargo test --locked --test files_v2_roundtrip c06_downgrade_and_unknown_versions_are_rejected -- --exact
cargo test --locked --test sandbox_cli -- --nocapture
cargo test --locked --lib crypto::
python3 scripts/check_attack_matrix.py --summary
```

The full local checklist is in [DEVELOPMENT.md](../DEVELOPMENT.md). New runtime tests use existing
runtime-generated keys, helpers and tiny synthetic files. No production data or additional crates.
For Linux sandbox evidence, record actual kernel/Landlock capability and inspect conditional
skips; helper output may be captured even with `--nocapture`. Do not disable protections for tests.

### Baseline and platform boundaries

Initial B1 evidence: [main CI 43879233746](https://github.com/SpecterAoD/pqkeep/actions/runs/43879233746),
`4e34468d5dafacdaed994b9e29def2afa53be72a`. Reviewed logs report 524 Rust tests on Ubuntu latest
x86_64, 524 on native Ubuntu 22.04 ARM64 and 460 on Windows x86_64, including doctests/helper
entry points. Zero `ignored` does not count cfg exclusions or internal early returns.
The baseline lists only observed test symbols; it does not infer active Landlock enforcement
or actual denied locking from a successful parent test. Windows process hardening reports
unsupported; Linux-only tests are not Windows security evidence.

B2: [fuzz run 43667929295](https://github.com/SpecterAoD/pqkeep/actions/runs/43667929295) on
`a52353d062db29ae9d56721a65e9d99ffad1499f`, eight successful jobs, two detailed campaign records
(header v2 and stream tamper). Relevant source/fuzz/lock/config paths were unchanged between B2
and B1; this remains historical evidence. Pinned nightly, bounded time/RSS/maxinput and a seed
make an experiment describable, not bit-identical across environments.

The existing `ci.yml:test` now validates the catalogue and runs its Python tests on all four
native runners. Default Rust tests run on Ubuntu latest, Ubuntu 22.04, Ubuntu 22.04 ARM64 and
Windows latest. No-default runtime tests additionally run once on Ubuntu latest and Windows latest;
Ubuntu 22.04 and ARM64 retain no-default clippy compilation only. No new workflow or required
check is introduced. Fuzz triggers/budgets remain unchanged; a catalogue edit alone does not run fuzzing.

Known limits remain explicit in each case: valid whole-file replay is accepted; no trusted
freshness register/global version floor exists. Relabelled versions, weak KDF settings and modified
slots are rejected within existing tests. Old copies remain readable after recipient changes.
Windows has no equivalent sandbox or dedicated ACL checks; WER suppression is not guaranteed.
Locking is mandatory (see LOCKED_SECRETS.md); zeroization retains compiler/OS limits; abort skips Drop. Ordinary cleanup tests do not prove
SIGKILL/OOM/power-loss recovery. Source/publish/FAT races are documented. STREAM buffers are bounded,
but source/path bookkeeping and Argon2 memory are not constant total process memory.
ARM64 evidence uses 4-KiB pages; 64-KiB kernels need separate controlled verification.
Windows ARM64 is not a current release/CI target. Header fuzzing's 64-KiB input limit does not
reach every allowed large header. These are gaps, not guarantees introduced by this catalogue.

### Rollback

**Implementation evidence (2026-11-16):** [CI 43947063245](https://github.com/SpecterAoD/pqkeep/actions/runs/43947063245)
passed all ten jobs on checkout `c817c4464fc668238394231ca97028e3cba42019`, byte-identical to
signed branch `e735edb83559214c85d5de491f267a4a659f93fe` before this reporting-only update.
Linux default: 526 tests on each runner; no-default: 491 on Ubuntu latest. Windows: 462/429.
The 25 validator tests pass; Windows skips the Unix-only symlink fixture. Added no-default steps
took 96 s (Linux) and 148 s (Windows); catalogue steps <1 s on Linux, 4 s on Windows.
Local checks passed, including both Rust feature suites and all 105 Python tests without skips.
Practical revert of the two implementation commits in a separate worktree produced the exact
recorded base tree; fmt/limits/smoke and re-check/decrypt passed, generated key/archive hashes
unchanged. No production data, merge or deployment. Baseline 1.0.1 links exact new assertions;
the subsequent reporting commit does not alter product, test or workflow code.

Revert the isolated implementation PR through a signed, reviewed PR; validate affected references
and CI, especially if later work depends on the catalogue. No key/archive migration is needed.
A practical pre-merge check uses a separate temporary worktree, reverses only #151 changes,
compares the resulting tree to its recorded base and runs existing checks/smoke tests. Generated
synthetic key/archive hashes must remain unchanged. Preserve existing user work and evidence;
never force-push, remove protections or merge without approval.

## Deutsch

### Umfang und Freigabe

Issue [#151](https://github.com/SpecterAoD/pqkeep/issues/151), QA-1. Der Maintainer hat den Plan mit
13 Dateien am 16.11.2026 vor Umsetzung freigegeben: versionierter Katalog und Ausführungsnachweise,
Offline-Validator, zwei Replay-Verhaltenstests, bestehende CI und zweisprachige Dokumentation.
Keine Änderung von Produktivcode, Kryptografie, Formaten oder Abhängigkeiten. Der separate
[Roadmap-Draft #247](https://github.com/SpecterAoD/pqkeep/pull/247) bleibt eigenständig.

Der Katalog erfasst vorhandene Assertions und fehlende Nachweise; er bescheinigt keine vollständige
Angriffsabwehr. [v2-Katalog](../V2_TESTS.md), [Bedrohungsmodell](../THREAT_MODEL.md) und
[CI-Regeln](CI_SECURITY.md) werden wiederverwendet. #129 und #147–#150 bleiben offene Härtung.
#152 übernimmt deterministische Fault-/Crash-/Recovery-Injektion, #153 Parser-/IPC-/Permissions-
Fuzzing und Sanitizer-Ausbau, #154 reproduzierbare Builds, unabhängigen Audit und Release-Gate.
Freigegebenes #152-A–E finalisiert 1.1.0: 59 Fälle; zwölf neue begrenzte Fälle sind nativ belegt.
1.2.0 ergänzt QA1-FMT-010 (#44, Absender-Signatur in `.pqkf`, Format v3): 60 Fälle; der
CI-Nachweis folgt mit dem nächsten Baseline-Lauf.
1.3.0 ergänzt QA1-FMT-011 (#316/#83, Kern Format v4/Strom): 61 Fälle; CI-Nachweis folgt ebenso.
1.4.0 ergänzt QA1-FMT-012 (#316, Füllung nach PADMÉ): 62 Fälle; CI-Nachweis folgt ebenso.
1.5.0 ergänzt QA1-FMT-013 (#316/#340, anonyme Empfänger, experimentell, teilweise): 63 Fälle.
1.6.0 ergänzt QA1-FMT-014 (#316, verborgener Absender): 64 Fälle.
1.7.0 ergänzt QA1-FMT-015 (#335, Integritätsmatrix der Container); QA1-FMT-003 abgedeckt, QA1-REC-003 teilweise (Kill-Test, Grenze L1 → #338): 65 Fälle.
1.8.0: QA1-FS-008 teilweise (#338, deterministische Race-Tests; Lücken nachgestellt, Behebung in PR 2–4): 65 Fälle.
1.9.0: QA1-FS-008 – Linux behoben (GHSA-9vh5-2vch-2r68, handlebasierte Ausgabe); Windows und Quellen offen: 65 Fälle.
[Ausführungsnachweise](FAULT_RECOVERY_EVIDENCE.md) verknüpfen Quelle/CI; breite Altlücken bleiben offen.

### Dateien, Status und Ausführung

[attack-matrix.json](attack-matrix.json) ist die einzige Fallquelle, anfangs 47 Fälle;
[attack-baseline.json](attack-baseline.json) enthält separat versionierte Ausführungsnachweise.
Vom Repository-Root `python3 scripts/check_attack_matrix.py --summary` für eine DE/EN-Tabelle
aufrufen, ohne `--summary` nur zur Prüfung. Validator-Tests:
`python3 -m unittest discover -s scripts -p 'test_attack_matrix.py' -v`.

| Teststatus | Bedeutung |
|---|---|
| `covered` | Vorhandene automatische Assertions decken den eng beschriebenen Fall auf den genannten Plattformen ab |
| `partial` | Varianten, Voraussetzungen oder Nachweise fehlen teilweise |
| `missing` | Kein dedizierter Test/Nachweis, auch bei nicht angebotener Schutzgarantie |
| `manual` | Kontrollierte manuelle Prüfung nötig; Dokumentation führt sie nicht aus |
| `not-applicable` | Mechanismus/Komponente betrifft diese Plattform bzw. das aktuelle Produkt nicht; Begründung zwingend |

`implementation_state` unterscheidet unabhängig `implemented`, `documented-only`,
`not-implemented`, `not-applicable`; `automation` unterscheidet `automated`, `automatable`,
`manual`, `not-applicable`. Beides belegt keine erfolgreiche Ausführung. In der Baseline stehen
`passed`, `failed`, `skipped`, `not-run`, `unknown`. Dokumentation, Kompilierung und grüne Elternjobs
sind keine bestandenen Sicherheitsassertions. Leere Nachweisverweise bedeuten keine erfasste Ausführung.

### Datenvertrag, Version 1

Beide Dokumente verlangen Integer `schema_version: 1`; unbekannte Felder und doppelte JSON-Schlüssel
scheitern. Matrix: SemVer `matrix_version`, volle `reviewed_source_commit`-SHA, `cases`.
Baseline: eigene SemVer `baseline_version`, passende `matrix_version`, `evidence`.

Die Fallfelder aus der englischen Tabelle gelten identisch: stabile ID `QA1-<Bereich>-NNN`, Kategorie,
Komponentendateien; `scenario`, `expected_behavior`, `boundary`, `preconditions` mit nichtleeren,
gleichwertigen DE/EN-Texten; unabhängige Implementierungs-/Abdeckungs-/Automationszustände;
OS/Architektur-/Featurebedingungen; konkrete Testpfade/Symbole; Workflow-/Job-/Runner-/Gatezuordnung;
P1–P3, Issues, v2-IDs und Nachweisverweise; offene Variante und nächster Nachweis; Stilllegung/Ersatz.
`gap`/`next_evidence` sind nur bei covered null. `retired` erhält alte IDs; Ersatz muss existieren.

Testarten: `rust-integration`, `rust-unit`, `doctest`, `python`, `fuzz`, `manual`.
Test- und CI-Verweise unterscheiden `existing`/`planned`; geplante Verweise belegen weder covered
noch passed. Der Validator prüft Dateipfade und Symbolpräsenz, keinen Sprachparser, kompilierte
Attribute, Aussagekraft von Assertions oder Wahrheit eines CI-Ergebnisses. Kein Import referenzierter
Dateien, kein Ausführen gespeicherter Kommandos und kein Netz. Absolute/Traversal-Pfade und aus dem
Repository führende Symlinks scheitern. Workflowprüfung erkennt die vorhandene eingerückte Jobform;
actionlint und bestehende Workflow-Regeln bleiben zuständig. `required-except-arm64` bezeichnet die
drei bestehenden Pflicht-Runnerchecks plus optionales natives ARM64; keine Regel wird geändert.

Jeder Nachweis nennt ID, Quell-SHA, UTC-Beobachtungszeit, Quelle local/ci, Ergebnis, Plattform,
Runner, Features, beobachtete Umgebung, konkrete Fälle/Testverweise und DE/EN-Grenzen. CI verlangt
positive Run-/Job-/Attempt-IDs und passende URL; lokal sind CI-IDs/URL null. Nicht beobachtete Kernel-,
Seiten- oder Toolchainwerte bleiben unknown. Verweise sind wechselseitig; ein Teilnachweis schließt
fehlende Varianten nicht. Historische Läufe gelten nicht als aktuelle Ausführung.

### Pflege und Reproduktion

IDs nie wiederverwenden. Neue Fälle erhöhen MINOR, Text-/Verweiskorrekturen ohne geänderte Erwartung
PATCH, inkompatibler Vertrag oder geänderte Sicherheitssemantik MAJOR mit Review. Baseline hat eigene
Version und bindet die Matrixversion. Stillgelegte Fälle mit Grund/Ersatz erhalten; Git bewahrt alte
Stände. Versionsanhebung und historische ID-Kontinuität im PR prüfen; ein Offline-Validator kann das
nicht aus einem flachen Checkout erschließen.

Nur tatsächliche Ausführung mit SHA, Plattform/Features, UTC-Beobachtungszeit, Run/Job/Attempt und
Assertion-Scope eintragen. Verlorene Logs als unknown kennzeichnen; Erfolg nicht rekonstruieren.
Bereinigte Auszüge/Hashes bei Bedarf außerhalb Git sichern; keine erzeugten Schlüssel, Archive,
rohen Korpora oder Secret-Logs einchecken. Ein reiner Berichtscommit darf auf den geprüften Commit
folgen: beide Stände nachvollziehen und relevante Code-/Test-/Workflowpfade auf Gleichheit prüfen.

Die Befehle im englischen Abschnitt gelten unverändert; vollständige lokale Checks siehe
[DEVELOPMENT.md](../DEVELOPMENT.md). Neue Tests verwenden bestehende Helfer, Laufzeit-Schlüssel und
kleine synthetische Dateien. Linux-Sandbox-Nachweise benötigen Kernel-/Landlock-Fähigkeiten und
Prüfung bedingter Auslassungen; Helper kapseln Ausgabe teils auch mit `--nocapture`. Keine Schutzmaßnahmen
für Tests abschalten.

### Baseline und Plattformgrenzen

B1: [main-CI 43879233746](https://github.com/SpecterAoD/pqkeep/actions/runs/43879233746),
`4e34468d5dafacdaed994b9e29def2afa53be72a`. Gesichtet: 524 Rust-Tests Ubuntu latest x86_64,
524 natives Ubuntu 22.04 ARM64, 460 Windows x86_64, einschließlich Doctests/Probe-Einstiegen.
Null ignored zählt weder cfg-Ausnahmen noch interne Rücksprünge. Nur sichtbare Tests referenzieren;
keine aktive Landlock-Abwehr oder gescheitertes Locking aus dem grünen Elternjob ableiten.
Windows-Prozesshärtung meldet unsupported; Linux-only ist kein Windows-Nachweis.

B2: [Fuzz-Lauf 43667929295](https://github.com/SpecterAoD/pqkeep/actions/runs/43667929295) auf
`a52353d062db29ae9d56721a65e9d99ffad1499f`, acht grüne Jobs, zwei detaillierte Nachweise
(v2-Header, Stream-Tamper). Relevante Quell-/Fuzz-/Lock-/Konfigurationspfade zwischen B2 und B1
unverändert; dennoch historischer Lauf. Feste Nightly, Seed und begrenzte Zeit/RSS/Eingabelänge
beschreiben die Kampagne, garantieren keine identischen Durchläufe auf anderer Hardware.

`ci.yml:test` prüft Katalog und Python-Tests auf vier nativen Runnern. Default-Rust läuft auf Ubuntu
latest, Ubuntu 22.04, Ubuntu 22.04 ARM64 und Windows latest. No-default-Runtime zusätzlich je einmal
Ubuntu latest und Windows latest; Ubuntu 22.04/ARM64 behalten No-default-Clippy. Kein neuer Workflow
oder Pflichtcheck. Fuzz-Auslöser/Budgets unverändert; Katalogänderung allein startet kein Fuzzing.

Grenzen in jedem Fall: gültiges Replay wird akzeptiert, kein Frischeregister/globaler Versionsboden.
Versionsumschreiben, schwache KDF und Slot-Manipulation werden im konkreten Testscope abgewiesen.
Alte Kopien bleiben nach Empfängerwechsel lesbar. Windows ohne gleichwertige Sandbox/eigene ACL-
Prüfung, WER-Sperre nicht garantiert. Sperren zwingend (siehe LOCKED_SECRETS.md); Zeroize mit Compiler-/OS-Grenzen; Abort ohne Drop. Normales Cleanup
beweist keine SIGKILL-/OOM-/Stromausfall-Recovery. Source-/Publish-/FAT-Rennen dokumentiert.
STREAM-Puffer begrenzt, Gesamtprozess mit Source-/Pfadlisten und Argon2 nicht konstant im Speicher.
ARM64 nur 4-KiB-Seiten belegt; 64 KiB benötigt Sonderprüfung. Windows ARM64 kein aktuelles CI-/Releaseziel.
64-KiB-Header-Fuzzinput erreicht nicht jeden zulässigen Header. Der Katalog führt diese Grenzen offen.

### Rückweg

**Umsetzungsnachweise (16.11.2026):** [CI 43947063245](https://github.com/SpecterAoD/pqkeep/actions/runs/43947063245)
mit zehn grünen Jobs auf Checkout `c817c4464fc668238394231ca97028e3cba42019`, bytegleich zum
signierten Branch `e735edb83559214c85d5de491f267a4a659f93fe` vor diesem Berichtsupdate.
Linux Default je 526 Tests; No-default Ubuntu latest 491; Windows 462/429.
25 Validator-Tests bestanden; Windows überspringt die Unix-Symlink-Probe. Zusätzliche No-default-
Schritte: 96 s Linux, 148 s Windows; Katalogschritte <1 s Linux, 4 s Windows.
Lokal alle Checks bestanden, einschließlich beider Rust-Featuresuiten und 105 Python-Tests ohne
Auslassungen. Praktische Rücknahme der zwei Implementierungscommits im eigenen Arbeitsbaum ergibt
exakt die dokumentierte Basis; fmt/Limits/Smoke sowie erneutes Prüfen/Entschlüsseln bestanden,
erzeugte Schlüssel-/Archivhashes unverändert. Keine Produktivdaten, kein Merge/Deployment.
Baseline 1.0.1 verknüpft konkrete neue Assertions; folgender Berichtscommit ohne Code-/Test-/CI-Änderung.

Isolierten Implementierungs-PR über signierten, geprüften Revert-PR zurücknehmen, Referenzen und CI
prüfen, insbesondere bei späteren abhängigen Änderungen. Keine Schlüssel-/Archivmigration.
Praktische Probe vor Merge: eigener temporärer Arbeitsbaum, nur #151 zurücknehmen, Baum gegen
Basis vergleichen, vorhandene Checks/Smoke-Tests ausführen und erzeugte Schlüssel-/Archivhashes
vor/nach vergleichen. Nutzerarbeit/Nachweise erhalten; kein Force-Push, keine Abschaltung von
Schutzregeln, kein Merge ohne Freigabe.
