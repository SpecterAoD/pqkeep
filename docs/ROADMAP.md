# Fahrplan / Roadmap

Details zu jedem Schritt: [`SPEC.md`](SPEC.md), Abschnitt 7. Jeder Schritt braucht Plan-Freigabe, grüne Tests und die [Checkliste](CHECKLIST.md).

**Stand / status (26.11.2026):** Schritte 0–7 abgeschlossen, Betas [`v0.1.0-beta.1`](https://github.com/SpecterAoD/pqkeep/releases/tag/v0.1.0-beta.1) bis [`v0.1.0-beta.4`](https://github.com/SpecterAoD/pqkeep/releases/tag/v0.1.0-beta.4) veröffentlicht; U0, U1 (mit Absender-Signatur in `.pqkf`, #44), U2 und U4 umgesetzt, U5 begonnen (zufällige Namen #315, Format v4: Kern, Strom #83, Füllung; #316). / Steps 0–7 done, four betas published; U0, U1 (including the sender signature in `.pqkf`, #44), U2 and U4 implemented, U5 started (random names #315, format v4: core, stream #83, padding; #316).

**Aktuelle Planung / current planning:** [Meilensteine M0–M7 / milestones](https://github.com/SpecterAoD/pqkeep/milestones) und [Project-Board](https://github.com/users/SpecterAoD/projects/1). Diese Datei zeigt den bisherigen Weg. / This file shows the way so far.

| Schritt | Inhalt | Ergebnis |
|---|---|---|
| 0 | Projekt-Grundgerüst, Lints, `error.rs`, CI-Rumpf, Zeilenlimit-Check | Leerer Build grün auf Linux und Windows |
| 1 | Core-Krypto: ML-KEM, ML-DSA, AES-256, Argon2id, AES-256-GCM-Container-Verschlüsselung ([CRYPTO.md](CRYPTO.md)) | Roundtrip-, Manipulations-, KAT- und Zeroize-Tests |
| 2 | `security.rs`: Passphrase-Prüfung, Entropie, Generator | Schwach abgelehnt, stark akzeptiert, Generator getestet |
| 2a | `hardening/`: Speichersperre (mlock/VirtualLock), Core-Dump-Sperre, sofortiges Nullen ([MEMORY_HARDENING.md](MEMORY_HARDENING.md)) | Sperr-/Freigabe-Tests, Fehler bei unvollständiger Sperre |
| 2b | Wort-Modell + Wortlisten (EFF, BIP-39, deutsche Diceware-Listen) für die Passphrase-Prüfung ([SECURITY_PASSPHRASE.md](SECURITY_PASSPHRASE.md)) | Zusammengesetzte Wörter abgelehnt, Sätze/Zufall angenommen |
| 3 | `envelope/`: JSON-Container, Metadaten, Parser-Härtung ([FORMAT.md](FORMAT.md)) | Roundtrip, Pfadkonventionen Windows/Linux, Fuzz/Property-Tests |
| 3a | `files/`: Datei- und Ordnerverschlüsselung (Passphrase oder ML-KEM-Empfänger), Streaming-AEAD, Archiv, Pfadsicherheit ([FILE_FORMAT.md](FILE_FORMAT.md)) | Roundtrip, Manipulation, bösartige Archive, keine Teilausgabe |
| 4 | `cli.rs`: Menü, Subcommands, integrierte zweisprachige Hilfe | CLI-Integrationstests, Hilfetests DE/EN |
| 5 | `api.rs`: Axum-REST-API, Härtung | HTTP-Integrationstests inkl. Auth, Limits, DoS-Schutz |
| 5a | Sandboxing Linux: Landlock (Dateipfade), Seccomp-BPF (Systemaufrufe), Profile für CLI und API | Verbotene Zugriffe scheitern, normale Abläufe funktionieren |
| 6 | CI/CD, Release-Workflow mit Signierung, Dokumentation | Grüne CI, Beta-Trockenlauf mit Verifikation |
| 7 | Abschluss-Review, erste signierte Beta | `v0.1.0-beta.1` veröffentlicht und verifiziert |

## In Bearbeitung / In progress

- [ ] [#147](https://github.com/SpecterAoD/pqkeep/issues/147): Secret-Lebensdauer-Audit –
  Inventar, synthetische Kopierproben, Dump-/Prozessgrenzen und priorisierte Nacharbeit.
  / Secret lifetime inventory, copy probes, process/dump boundaries and remediation plan.
  [Plan](security/SECRET_LIFETIME_AUDIT_PLAN.md), [Audit](security/SECRET_LIFETIME_AUDIT.md).
  [Argon2-Descriptor / Argon2 descriptor](security/ARGON_WORKSPACE_OWNER_PLAN.md):
  ursprünglicher Ownerschritt auf Main; vollständige R6-Providerflächen jetzt in
  [Draft334/Abnahmematrix](security/PROVIDER_LIFETIME_VALIDATION.md) umgesetzt,
  finale native/Sicherheits-/Fuzz-/Rückwegabnahme erforderlich.
  / Original owner step on Main; complete R6 implementation awaits final exact-head acceptance.
  Auditphase PR298, geschützte Laufzeitpuffer [PR300](https://github.com/SpecterAoD/pqkeep/pull/300)
  und begrenzte WER-Fähigkeit [PR301](https://github.com/SpecterAoD/pqkeep/pull/301) nach Main gemergt.
  / Audit, protected runtime buffers and partial WER capability merged; authorized remediation continues.
  Gesperrte NFKC-Arbeitsbereiche [PR302](https://github.com/SpecterAoD/pqkeep/pull/302) gemergt;
  vollständiger eigener Provider-Drop in [PR303](https://github.com/SpecterAoD/pqkeep/pull/303).
  / Locked NFKC workspaces and complete owned-state destruction merged.
  [Interne Bewertungsmetadaten / internal assessment metadata](security/ASSESSMENT_METADATA_PLAN.md)
  nach Main gemergt ([PR304](https://github.com/SpecterAoD/pqkeep/pull/304)).
  / Internal assessment metadata merged; Main acceptance tracked separately.
  [Archiv-Framing und interne Einträge / archive framing and entry records](security/ARCHIVE_METADATA_PLAN.md)
  nach Main gemergt ([PR305](https://github.com/SpecterAoD/pqkeep/pull/305)).
  / Archive framing/entry remediation merged; Main acceptance tracked separately.
  [Blake2-Produktionsfeature / production destruction feature](security/BLAKE2_DROP_FEATURE_PLAN.md)
  nach Main gemergt ([PR306](https://github.com/SpecterAoD/pqkeep/pull/306)).
  / Blake2 feature repair merged; Main acceptance tracked separately.
  [Namensdescriptoren und direkte Listen-Slots / name descriptors and direct list slots](security/METADATA_OWNER_PLAN.md)
  nach Main gemergt ([PR307](https://github.com/SpecterAoD/pqkeep/pull/307)).
  / Locked metadata owners merged; Main acceptance tracked separately.
  [SecretBytes-Basisdescriptoren / base byte-owner descriptors](security/BYTE_OWNER_PLAN.md)
  nach Main gemergt ([PR308](https://github.com/SpecterAoD/pqkeep/pull/308)).
  / Base byte-owner guards merged; Main acceptance tracked separately.
  [Typisierte Descriptoren / typed workspace owners](security/TYPED_OWNER_PLAN.md)
  nach Main gemergt ([PR309](https://github.com/SpecterAoD/pqkeep/pull/309)).
  / Typed workspace owners merged; native Main acceptance tracked separately.
  [Feste Sperrbereichsdatensätze / fixed lock-range records](security/LOCK_RANGE_PLAN.md)
  nach Main gemergt ([PR310](https://github.com/SpecterAoD/pqkeep/pull/310)).
  / Fixed range bookkeeping merged; native Main acceptance tracked separately.
  [Geliehene interne Pfadteile / borrowed internal path components](security/PATH_COMPONENT_PLAN.md)
  nach Main gemergt ([PR311](https://github.com/SpecterAoD/pqkeep/pull/311)).
  / Borrowed path components merged; native Main acceptance tracked separately.
  [Stabile typisierte Seeds / stable typed seed owners](security/SEED_OWNER_PLAN.md)
  nach Main gemergt ([PR312](https://github.com/SpecterAoD/pqkeep/pull/312)).
  / Stable typed caller seed views merged; native Main acceptance tracked separately.
  [Direkte gesperrte Terminaleingabe / direct protected terminal input](security/TERMINAL_INPUT_PLAN.md)
  auf Linux/Windows nach Main gemergt ([PR313](https://github.com/SpecterAoD/pqkeep/pull/313));
  separate Main-Abnahme nachverfolgen. / Linux/Windows input merged; Main acceptance separate.
  [Feste Arbeitsbereichsowner / fixed workspace owners](security/FIXED_WORKSPACE_OWNER_PLAN.md)
  für Hash/HKDF/Archiv in Bearbeitung; konkrete native Descriptor-/Payloadprüfung erforderlich.
  / Fixed hash/HKDF/archive owners in progress; actual native descriptor/payload validation required.
  Provider-retained/math scratch,
  other-platform providers, GUI helpers and full process/dump/isolation remain OPEN.
  [Laufzeitplan / runtime plan](security/SECRET_LIFETIME_RUNTIME_PLAN.md).
  Eigentümer hat geprüfte Main-Merges freigegeben; #128/#148/#149/#150 abgleichen, vor Stream83/API98.
  / Verified Main merges authorized; findings close only after actual final validation.

## Abgeschlossene Ergänzungen / Completed follow-ups

- [x] [#186](https://github.com/SpecterAoD/pqkeep/issues/186): Release-Vertrauenskette – vollständige
  Verifikation vor Release-Entwurf, erneute Prüfung an der Schreibgrenze und strikte
  Repository-/Workflow-/Ref-/Commit-Bindung. / Complete verification before drafting,
  revalidation at the write boundary and strict identity/source binding.
  - Mit ausdrücklicher Eigentümerfreigabe signiert gemergt: [PR #296](https://github.com/SpecterAoD/pqkeep/pull/296).
    / Signed main merge with explicit owner approval; [plan and test boundaries](security/RELEASE_CHAIN_DESIGN.md).
  - [Main-CI](https://github.com/SpecterAoD/pqkeep/actions/runs/45083995533),
    [geschützter Trockenlauf / protected dry run](https://github.com/SpecterAoD/pqkeep/actions/runs/45084015723).
    Kein Release/Tag oder Schutzregelwechsel. / No release/tag or protection changes.
  - Historische Reproduzierbarkeit/Preview-Gating, unabhängiges Audit, TUF und SignPath bleiben
    #269/#154/#143/#88. / Separate follow-ups retain their scope.

- [x] [#117](https://github.com/SpecterAoD/pqkeep/issues/117): `pqkeep list` – authentisierte v1/v2-Archivliste ohne Extraktion; begrenzte Metadaten erst nach vollständiger Prüfung, eigenes List-JSON. / Authenticated v1/v2 archive listing without extraction; bounded metadata after full verification, dedicated listing JSON. ([PR #283](https://github.com/SpecterAoD/pqkeep/pull/283), 21.11.2026)
  - Mit Eigentümerfreigabe signiert nach main übernommen; [DE/EN-Anleitung](LIST.md), [Plan/Testzuordnung und Grenzen](security/LIST_DESIGN.md). #116/#86 abgeschlossen, #118 konsolidiert. / Owner-authorized signed main merge; bilingual usage, design, test mapping and limits linked; dependencies complete.
  - [PR-CI](https://github.com/SpecterAoD/pqkeep/actions/runs/44932164489): Linux 628/589, Windows 568/531; [acht Fuzz-Ziele](https://github.com/SpecterAoD/pqkeep/actions/runs/44932178185) bestanden; [main-Abnahme](https://github.com/SpecterAoD/pqkeep/actions/runs/44936806831). / Native full suites and all eight existing fuzz targets passed; main validation linked.
  - Integrität ist keine Absenderidentität; bestehende Formate unverändert. Allgemeine API/Crate-Aufteilung/GUI und breite QA bleiben #98/#99/#63/#153. / Integrity is not sender identity; existing formats unchanged; general API/crate/GUI and broad QA work remain separate.

- [x] [#109](https://github.com/SpecterAoD/pqkeep/issues/109): `pqkeep rekey` – Passphrase-Wechsel mit gleicher Schlüsselidentität/Format/Faktor und exakter Sicherung vor bestätigtem Austausch. / Passphrase changes preserve identity/format/factor, with an exact backup before confirmed replacement. ([PR #282](https://github.com/SpecterAoD/pqkeep/pull/282), 21.11.2026)
  - Mit ausdrücklicher Eigentümerfreigabe signiert gemergt; [DE/EN-Anleitung](REKEY.md), [Entwurf und Grenzen](security/REKEY_DESIGN.md). / Signed merge with explicit owner authorization; bilingual usage, design and limits linked.
  - [PR-CI](https://github.com/SpecterAoD/pqkeep/actions/runs/44885410985): Linux 605/566, Windows 544/507; [acht Fuzz-Ziele](https://github.com/SpecterAoD/pqkeep/actions/runs/44885478805) bestanden. / Native full suites and all eight fuzz targets passed.

- [x] [#152](https://github.com/SpecterAoD/pqkeep/issues/152): QA-2: Deterministic fault injection and crash-recovery tests / Deterministische Fehler-Injektion und Crash-Recovery-Tests. ([PR #279](https://github.com/SpecterAoD/pqkeep/pull/279), 21.11.2026)
  - P2, M2; A–E approved and merged with owner authorization; dependency #151 / PR #251 complete. / A–E freigegeben und mit ausdrücklicher Freigabe gemergt; Abhängigkeit abgeschlossen.
  - Twelve new bounded cases, native Linux/Windows tests and rollback verified; [design](security/FAULT_RECOVERY.md), [evidence](security/FAULT_RECOVERY_EVIDENCE.md), [final CI](https://github.com/SpecterAoD/pqkeep/actions/runs/44823927772). / Zwölf neue begrenzte Fälle, native Tests und Rücksetzung nachgewiesen.
  - Process kills and simulated I/O faults do not prove OS-crash/power-loss durability; broad matrix gaps and #124 remain open; #109 is now completed. / Prozessabbrüche und simulierte I/O-Fehler belegen keine OS-/Stromverlustdauerhaftigkeit; übergreifende Matrixlücken und #124 bleiben offen; #109 ist inzwischen abgeschlossen.
- [x] [#151](https://github.com/SpecterAoD/pqkeep/issues/151): QA-1: Versioned attack test matrix and baseline / Versionierte Angriffstest-Matrix und Baseline. ([PR #251](https://github.com/SpecterAoD/pqkeep/pull/251), 16.11.2026)
  - Status: Completed / Abgeschlossen; Priority / Priorität: P2; Milestone / Meilenstein: M2.
  - 47 versioned DE/EN cases, offline validation and native Linux/Windows CI; evidence and limits: [attack matrix](security/ATTACK_TEST_MATRIX.md), [baseline](security/attack-baseline.json), [verified CI](https://github.com/SpecterAoD/pqkeep/actions/runs/43949469492). / 47 versionierte DE/EN-Fälle, Offline-Validierung und native Linux-/Windows-CI; Nachweise und Grenzen in Matrix und Baseline.
  - Dependencies / Abhängigkeiten: [#97](https://github.com/SpecterAoD/pqkeep/issues/97) completed / abgeschlossen. Follow-up #152 completed / Folgeschritt #152 abgeschlossen ([PR #279](https://github.com/SpecterAoD/pqkeep/pull/279)); [#153](https://github.com/SpecterAoD/pqkeep/issues/153), [#154](https://github.com/SpecterAoD/pqkeep/issues/154) remain open / bleiben offen.
  - Catalogue completed; documented crash/OOM/race, Windows and replay limitations remain. / Katalog abgeschlossen; dokumentierte Crash-/OOM-/Race-, Windows- und Replay-Grenzen bleiben bestehen.
- [x] [#222](https://github.com/SpecterAoD/pqkeep/issues/222): Hilfetests für alle CLI-Unterbefehle auf Deutsch und Englisch, mit und ohne API-Feature; `serve` nur mit API. / Help tests for every CLI subcommand in German and English, with and without the API feature; `serve` only with API. ([PR #243](https://github.com/SpecterAoD/pqkeep/pull/243), 15.11.2026)
- [x] [#224](https://github.com/SpecterAoD/pqkeep/issues/224): Sichere Backup-Monitoring-Beispiele für `pqkeep check --json` mit Bash/jq und PowerShell, DE/EN-Dokumentation und nativen Linux-/Windows-Tests. / Secure backup monitoring examples for `pqkeep check --json` using Bash/jq and PowerShell, bilingual documentation and native Linux/Windows tests. ([PR #245](https://github.com/SpecterAoD/pqkeep/pull/245), 16.11.2026)

## Geplante Updates nach der ersten Beta (Details: SPEC Abschnitt 9)

| Update | Inhalt | Issues |
|---|---|---|
| U0 | Zweiter Faktor als Faktordatei – Format v2 gemeinsam mit U2: [V2_DRAFT.md](V2_DRAFT.md); Core und Kommandozeile (`pqkeep factor`, `--factor-file`) sowie Menü, geführter Ablauf und Kontextmenü umgesetzt; TPM/FIDO2 als Recherche | #39–#41 |
| U1 | Digitale Signaturen mit ML-DSA-87: `sign`/`verify`, Absender-Signatur für `.pqkf` – keine qualifizierte eIDAS-Signatur; U1-1 Format `.pqsig` + Core und U1-2 `sign`/`verify` umgesetzt ([SIGNATURE_FORMAT.md](SIGNATURE_FORMAT.md)); U1-3 Absender-Signatur in `.pqkf` als Format v3 umgesetzt ([V3_SIGNED.md](V3_SIGNED.md)) | #42–#44 |
| U2 | Mehrere Empfänger pro Container (ML-KEM-1024 je Empfänger) – Format v2: [V2_DRAFT.md](V2_DRAFT.md); Core, Kommandozeile (`--to` mehrfach, `--with-passphrase`), Menü und Kontextmenü umgesetzt | #45–#47 |
| U3 | Einrichtungs-Assistent in der Konsole, Notfall-Backup | #48–#50 |
| U4 | Kontextmenü (Rechtsklick) mit Passphrase-Dialog; U4-1 Linux, U4-2 Windows und U4-3 Fenster unter Linux und Windows, U4-4 Mehrfachauswahl sowie U4-5 Thunar umgesetzt ([INTEGRATION.md](INTEGRATION.md)) | #51–#53, #72, #92 |
| U5 | Privatsphäre und Metadaten, optional und konfigurierbar (Standard aus, Stufe `--privacy high`): zufällige äußere Dateinamen, Padding, anonyme Empfänger, verborgener Absender, verschlüsselte Zeitstempel und erweiterte Attribute – Reihenfolge #315 → #316 (mit #83, vor #98) → Archiv-Erweiterung im Backup-Epic | #315, #316, #123 |
| GUI | Optionale moderne grafische Oberfläche, rein in Rust, ohne Web-Technik und Netzwerk; Sicherheit vorab neu bewerten (SPEC-Änderung nötig) | #58–#65 (Meilenstein M3) |
| – | Spiegel-Modus für Ordner | #54 |
| – | Diceware-Generator mit gemeinfreier Wortliste | #55 |
| – | Hybrid-Verfahren (X25519 + ML-KEM) neu bewerten | #56 |
| iOS | iOS-App (ferne Zukunft): Machbarkeit, Architektur, Bedrohungsmodell | #66 (Meilenstein M7) |

## Offene Punkte außerhalb des Codes

- [x] Repository öffentlich schalten (Voraussetzung für SignPath) – 07.11.2026
- [x] Bei der SignPath Foundation beworben – 08.11.2026 vorerst abgelehnt (zu wenig Sichtbarkeit)
- [ ] Später erneut bei SignPath bewerben; bis dahin bleibt das Windows-Programm unsigniert
- [x] MFA bei GitHub aktiv (SignPath bei der Bewerbung)
- [x] Ruleset auf `main` (PR, Pflicht-Checks, signierte Commits) und Schutz der Release-Tags
- [x] Secret Scanning und Push Protection aktiv
- [x] Signing-Key für Git-Tags (SSH)

DE: #147 R8 In Bearbeitung: tatsächlichen Parser-Schutzrecord vor In-place-
Akquisition mit bestehendem SecretState sperren; Main320 vollständig abgenommen.
EN: #147 R8 In progress: prelock parser protection range metadata; full native
acceptance completed on Main320; remaining parser/provider/process gaps OPEN. See
[plan](security/PARSER_PROTECTION_OWNER_PLAN.md).

DE: #147 R8 In Bearbeitung: gesamten konkreten SliceRead-Parser vor Allokation
und privater Bindung sperren; private Fehlerpositionen nicht speichern.
EN: Prelock parser/source/index/depth/scratch descriptor; native/security/fuzz
acceptance required. Other R6/R7/R8 boundaries remain OPEN. See
[parser state plan](security/PARSER_STATE_OWNER_PLAN.md).

DE: #147 R6 abgeschlossen: PR334 auf Mainb813bc6 mit allen neun Zeilen der
[Abnahmematrix](security/PROVIDER_LIFETIME_VALIDATION.md), nativer Linux-/Windows-/
ARM64-Abnahme, Security/Fuzz und geprüftem Rückweg übernommen. R7/R8 separat offen.
EN: R6 completed on Main; current shared-provider changes retain its regression
checks. Issue147 and roadmap stay In progress; no whole-issue closure.

DE: #147 R7/R8 gemeinsam in Bearbeitung in [Draft355](https://github.com/SpecterAoD/pqkeep/pull/355):
[vollständig freigegebener Plan](security/PROCESS_METADATA_COMPLETION_PLAN.md).
Geschützte Pfadindex-Knoten und Absenderidentität veröffentlicht; geschützter
verborgener Signierschlüssel-/Kodier-/Verifikationspfad im selben Draft umgesetzt,
Gesamtabnahme noch offen. Windows-DACL nativ zurückgelesen, privilegierter
SeDebugPrivilege-Bypass tatsächlich nachgewiesen; neuer eigener reduzierter
CI-Threadversuch benötigt separate konkrete Freigabe. Kein Teilmerge.
EN: One joint PR; platform/helper, remaining metadata, native/security/fuzz and
full rollback acceptance remain open. See
[hidden signature scope](security/HIDDEN_SIGNATURE_VALIDATION.md) and
[restricted inspector proposal](security/WINDOWS_RESTRICTED_INSPECTOR_PROPOSAL.md).

DE: Derselbe Draft schützt nun auch Trailer-/Signaturnachricht-Bytes und laufende
STREAM-/Rückhalte-Zähler vor privater Befüllung. Berichte, native Pfade,
Sperrregister und Prozess-/Helper-Gesamtabnahme bleiben offen.
EN: Protected framing and retained stream/holdback counters in the same joint PR;
fallible Rust trailer API, unchanged wire bytes. No whole-row completion claim.
See [scope and migration](security/CONFIDENTIAL_FRAMING_VALIDATION.md).

DE: Im selben Draft folgt das vor Befüllung gesperrte gemeinsame Seitenregister:
Kontroll-/Node-Arenen, fallibles Wachstum, geprüfte Überlappung/Teilsperre und
Verweigerung weiterer Aufnahme nach echtem Release-Fehler oder Poisoning.
EN: Protected shared registry accepted on native Linux/Windows/ARM at5470c188.
Two unnecessary unsafe Send/Sync impls removed;
read-only native Windows observer is test-only. Other R7/R8 rows stay open.
See [registry contract and evidence](security/LOCK_REGISTRY_VALIDATION.md).

DE: Native Pfadkonvertierung an den tatsächlichen Archiv-/Quelldatei-Leseeingängen
vor privater Befüllung gesperrt; Windows-Normalisierung mit gesperrtem Ziel und
std-kompatibler248-Grenze. Quell-/Traversal-/Ziel-/Temppfade insgesamt weiter offen.
EN: First actual native read adapters implemented and locally source-checked in
the same Draft355; native acceptance pending, no M1/M3 closure. See
[native path scope](security/NATIVE_PATH_VALIDATION.md).
