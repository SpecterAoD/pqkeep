# Fahrplan / Roadmap

Details zu jedem Schritt: [`SPEC.md`](SPEC.md), Abschnitt 7. Jeder Schritt braucht Plan-Freigabe, grüne Tests und die [Checkliste](CHECKLIST.md).

**Stand / status (19.11.2026):** Schritte 0–7 abgeschlossen, Betas [`v0.1.0-beta.1`](https://github.com/SpecterAoD/pqkeep/releases/tag/v0.1.0-beta.1) und [`v0.1.0-beta.2`](https://github.com/SpecterAoD/pqkeep/releases/tag/v0.1.0-beta.2) veröffentlicht, `v0.1.0-beta.3` in Vorbereitung; U0, U1 (ohne Absender-Signatur in `.pqkf`), U2 und U4 umgesetzt. / Steps 0–7 done, two betas published, beta.3 in preparation; U0, U1 (except the sender signature in `.pqkf`), U2 and U4 implemented.

**Aktuelle Planung / current planning:** [Meilensteine M0–M7 / milestones](https://github.com/SpecterAoD/pqkeep/milestones) und [Project-Board](https://github.com/users/SpecterAoD/projects/1). Diese Datei zeigt den bisherigen Weg. / This file shows the way so far.

| Schritt | Inhalt | Ergebnis |
|---|---|---|
| 0 | Projekt-Grundgerüst, Lints, `error.rs`, CI-Rumpf, Zeilenlimit-Check | Leerer Build grün auf Linux und Windows |
| 1 | Core-Krypto: ML-KEM, ML-DSA, AES-256, Argon2id, AES-256-GCM-Container-Verschlüsselung ([CRYPTO.md](CRYPTO.md)) | Roundtrip-, Manipulations-, KAT- und Zeroize-Tests |
| 2 | `security.rs`: Passphrase-Prüfung, Entropie, Generator | Schwach abgelehnt, stark akzeptiert, Generator getestet |
| 2a | `hardening/`: Speichersperre (mlock/VirtualLock), Core-Dump-Sperre, sofortiges Nullen ([MEMORY_HARDENING.md](MEMORY_HARDENING.md)) | Sperr-/Freigabe-Tests, Best-effort bei Limit |
| 2b | Wort-Modell + Wortlisten (EFF, BIP-39, deutsche Diceware-Listen) für die Passphrase-Prüfung ([SECURITY_PASSPHRASE.md](SECURITY_PASSPHRASE.md)) | Zusammengesetzte Wörter abgelehnt, Sätze/Zufall angenommen |
| 3 | `envelope/`: JSON-Container, Metadaten, Parser-Härtung ([FORMAT.md](FORMAT.md)) | Roundtrip, Pfadkonventionen Windows/Linux, Fuzz/Property-Tests |
| 3a | `files/`: Datei- und Ordnerverschlüsselung (Passphrase oder ML-KEM-Empfänger), Streaming-AEAD, Archiv, Pfadsicherheit ([FILE_FORMAT.md](FILE_FORMAT.md)) | Roundtrip, Manipulation, bösartige Archive, keine Teilausgabe |
| 4 | `cli.rs`: Menü, Subcommands, integrierte zweisprachige Hilfe | CLI-Integrationstests, Hilfetests DE/EN |
| 5 | `api.rs`: Axum-REST-API, Härtung | HTTP-Integrationstests inkl. Auth, Limits, DoS-Schutz |
| 5a | Sandboxing Linux: Landlock (Dateipfade), Seccomp-BPF (Systemaufrufe), Profile für CLI und API | Verbotene Zugriffe scheitern, normale Abläufe funktionieren |
| 6 | CI/CD, Release-Workflow mit Signierung, Dokumentation | Grüne CI, Beta-Trockenlauf mit Verifikation |
| 7 | Abschluss-Review, erste signierte Beta | `v0.1.0-beta.1` veröffentlicht und verifiziert |

## In Bearbeitung / In progress

- [ ] [#109](https://github.com/SpecterAoD/pqkeep/issues/109): `pqkeep rekey` – Passphrase einer Schlüsseldatei ändern / change a key file's passphrase.
  - P1, M2; SpecterAoD; started / begonnen 21.11.2026. Dependencies #39–#41 completed; #152 supplies fault/crash tests. / Abhängigkeiten abgeschlossen; Fehler-/Crash-Testgrundlage vorhanden.
  - [PR #282](https://github.com/SpecterAoD/pqkeep/pull/282), [DE/EN usage](REKEY.md); owner review/merge pending. / Eigentümerreview/Merge ausstehend.
  - [Security/design plan](security/REKEY_DESIGN.md): preserve key material/ID and v1/v2; explicit output, protected backup before in-place replacement. / Schlüsselmaterial/ID und v1/v2 erhalten; ausdrückliches Ziel, geschützte Sicherung vor Austausch.
  - Owner authorized issue-scoped implementation, signed commits, tests and PR; merge to main excluded. / Issue-bezogene Umsetzung, signierte Commits, Tests und PR freigegeben; Merge nach main ausgenommen.

## Abgeschlossene Ergänzungen / Completed follow-ups

- [x] [#152](https://github.com/SpecterAoD/pqkeep/issues/152): QA-2: Deterministic fault injection and crash-recovery tests / Deterministische Fehler-Injektion und Crash-Recovery-Tests. ([PR #279](https://github.com/SpecterAoD/pqkeep/pull/279), 21.11.2026)
  - P2, M2; A–E approved and merged with owner authorization; dependency #151 / PR #251 complete. / A–E freigegeben und mit ausdrücklicher Freigabe gemergt; Abhängigkeit abgeschlossen.
  - Twelve new bounded cases, native Linux/Windows tests and rollback verified; [design](security/FAULT_RECOVERY.md), [evidence](security/FAULT_RECOVERY_EVIDENCE.md), [final CI](https://github.com/SpecterAoD/pqkeep/actions/runs/44823927772). / Zwölf neue begrenzte Fälle, native Tests und Rücksetzung nachgewiesen.
  - Process kills and simulated I/O faults do not prove OS-crash/power-loss durability; broad matrix gaps and #109/#124 remain open. / Prozessabbrüche und simulierte I/O-Fehler belegen keine OS-/Stromverlustdauerhaftigkeit; übergreifende Matrixlücken und #109/#124 bleiben offen.
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
| U1 | Digitale Signaturen mit ML-DSA-87: `sign`/`verify`, Absender-Signatur für `.pqkf` – keine qualifizierte eIDAS-Signatur; U1-1 Format `.pqsig` + Core und U1-2 `sign`/`verify` umgesetzt ([SIGNATURE_FORMAT.md](SIGNATURE_FORMAT.md)) | #42–#44 |
| U2 | Mehrere Empfänger pro Container (ML-KEM-1024 je Empfänger) – Format v2: [V2_DRAFT.md](V2_DRAFT.md); Core, Kommandozeile (`--to` mehrfach, `--with-passphrase`), Menü und Kontextmenü umgesetzt | #45–#47 |
| U3 | Einrichtungs-Assistent in der Konsole, Notfall-Backup | #48–#50 |
| U4 | Kontextmenü (Rechtsklick) mit Passphrase-Dialog; U4-1 Linux, U4-2 Windows und U4-3 Fenster unter Linux und Windows, U4-4 Mehrfachauswahl sowie U4-5 Thunar umgesetzt ([INTEGRATION.md](INTEGRATION.md)) | #51–#53, #72, #92 |
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
