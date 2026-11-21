# #117 – Vorab-Abstimmung / Pre-implementation coordination

Stand / snapshot: 21.11.2026, main `e66b92556af2835e9a211582d94efd637114f6c8`.
Status: Eigentümerfreigabe vom 21.11.2026 für diesen Plan, Umsetzung, Tests, signierte Commits
und PR ohne erneute Einzelfreigabe; Merge nach main ausdrücklich ausgenommen. /
Owner approved this plan and issue-scoped implementation, tests, signed commits and PR without
repeated approvals; merge to main explicitly excluded.

## Geprüfter Istzustand / Verified current state

- Aktuelle Roadmap, #117 einschließlich aller Kommentare und die unten genannten Issues geprüft.
  / Current roadmap, all #117 comments and the related issues below inspected.
- 166 offene/geschlossene Issues nach direkten #117-Verweisen im Body durchsucht;
  Treffer #118 und #153. Separat relevante Issue-Kommentare gelesen. Das ist keine
  Volltextsuche aller Kommentare aller Issues. / Searched 166 issue bodies for direct #117
  references, finding #118/#153; related comments inspected separately, not every comment globally.
- Aktuell keine offenen PRs; Remote-Branchliste enthält nur main. #117 ist nicht zugewiesen,
  im Board Backlog. Das beweist nicht, dass niemand außerhalb GitHubs arbeitet. /
  No open PRs and only main advertised remotely; #117 unassigned/Backlog. Offline work is unknown.
- #116 und #86 abgeschlossen; #118 ausdrücklich in #117 konsolidiert. /
  #116/#86 completed; #118 explicitly consolidated into #117.
- Vorhanden: `decrypt::open` für v1/v2, `ArchiveReader`, `paths::validate`, `PathSet`,
  `files::check`, CLI-Unlock und Sandbox-Lesepfade. / Existing v1/v2 opening, archive/path checks,
  check operation, CLI unlock and read-access rules can be reused.

## Zuständigkeiten / Ownership boundaries

| Issue | Abgrenzung für #117 / Boundary for #117 |
|---|---|
| #116 / #86 | Vorhandene Headerinspektion und vollständige Prüfung erhalten; dieselben Parser verwenden. / Preserve inspect/check and reuse their parsers. |
| #118 | Bereits konsolidiert; CLI und strukturierter Ergebnisvertrag gehören zu #117, kein zweites Issue/PR. / Already consolidated; CLI/result contract included, no duplicate issue/PR. |
| #98 / #99 / #96 | #96 abgeschlossen. #117 liefert eine reine Bibliotheksoperation plus CLI-Adapter; keine eigene Protokoll-/Trait-Plattform, Capability-Discovery oder Crate-Auslagerung. #98/#99 bleiben offen. / Pure library operation and CLI adapter, no parallel protocol framework or core split. |
| #63 / #102 | Künftige GUI/Client dürfen denselben Core-Aufruf verwenden. Keine GUI, Transportverbindung oder zweite Parser-Implementierung. / Future consumers reuse the core; GUI/transport remain separate. |
| #44 | Containerintegrität beweist keine Absenderidentität. Keine eingebettete Signatur, kein neues Format oder Vertrauensversprechen. / Integrity is not sender identity; no embedded signatures/new format. |
| #83 | Nur vorhandene Datei-/Verzeichniscontainer v1/v2. Keine Pipes, kein neuer Stream-Inhaltstyp, kein Entschlüsseln von Nutzdaten nach stdout. / Existing v1/v2 file/directory containers only; no stream format/payload stdout. |
| #113 / #123–#127 | Archivliste ist kein persistiertes/authentisiertes Backup-Manifest; kein Snapshot, Restore, Pruning oder Retention. / Listing is not a backup manifest; no snapshot/restore/pruning. |
| #119 / #121 | Kein neues Fortschritts-/Cancel-/Resume-Protokoll. Bei Prozessabbruch vor Authentisierung keine Liste. / No parallel progress/cancel/resume protocol; no pre-authentication listing. |
| #147 / #148 / #150 | Bestehende Secret-Typen nutzen; keine globale Speicherhärtung, kein Versprechen vollständiger RAM-Löschung. / Reuse secret types; no broad memory-hardening work or complete erasure claim. |
| #151 / #152 / #153 / #154 | #117 enthält eigene Erfolgs-/Fehler-/Grenz-/Manipulations- und Ausgabe-Gating-Tests; vorhandene Infrastruktur wiederverwenden. #153 erweitert später Corpus/IPC/Berechtigungsmatrix, #154 bleibt Audit-/Release-Gate. Baseline nicht vor Tests auf covered setzen. / Focused feature tests now, broader fuzz/permission work later; no premature baseline claims. |

## Sicherheitsentscheidungen zur Freigabe / Security decisions for approval

1. **JSON-Vertrag:** `docs/JSON.md` und `src/cli/json_out.rs` versprechen für `pqkeep-json/1`
   ausdrücklich keine Archiv-Inhaltspfade. Vorschlag: nur der neue ausdrückliche Befehl
   `list --json` erhält `pqkeep-list/1`, mit bewusst angeforderten Pfaden und Größen;
   gemeinsame Fehlercodes/Formatierung wiederverwenden, keine zweite allgemeine JSON-Infrastruktur.
   Erfolg und frühe Fehler einschließlich Sandbox müssen dasselbe neue Schema liefern.
   Die übrigen Befehle und `pqkeep-json/1` bleiben unverändert. Keine globale API-Stabilitätszusage
   vor #98; der kleine List-Vertrag wird dort zur späteren Aufnahme dokumentiert.
   / Existing JSON forbids archive paths. Propose a command-specific `pqkeep-list/1`, reusing
   formatting/error conventions, including early errors; existing command contracts stay exact.
   Hand off the narrow listing contract to #98 without inventing a general protocol framework.
2. **Keine Veröffentlichung vor vollständiger Prüfung:** ein Quelldatei-Aufruf; Inhalte gestreamt
   prüfen und verwerfen, Metadaten begrenzt im Speicher sammeln; erst nach Checksummen,
   Pfad-/Konfliktprüfung, Archivende und STREAM-Endprüfung zurückgeben/anzeigen. Keine
   Ausgabedatei, kein Temp-Spool und kein öffentlicher Callback mit ungeprüften Namen.
   Authentisierter Erfolg bedeutet Containerintegrität, nicht Absendervertrauen.
   Schreibfehler/BrokenPipe können nach erfolgreicher Prüfung eine Ausgabe verkürzen;
   dafür kein Erfolg/Exit 0 versprechen und keine atomare stdout-Übertragung behaupten.
   / One source per call; stream/discard payload, buffer bounded metadata, release only after
   complete authentication. No temp spool or provisional callback; stdout itself is not atomic.
3. **Ressourcen:** vorhandene Grenzen sind 1.000.000 Einträge, 4096 Pfadbytes, Tiefe64.
   Für die zusätzliche Listensammlung vorgeschlagen: maximal 10.000 Einträge und 16MiB
   aufsummierte UTF-8-Pfadbytes, geprüft vor Sammlung/PathSet-Erweiterung; Überlaufprüfung für
   Zähler/Größen. Überschreitung: Fehler ohne Liste, ohne Disk-Fallback. Das sind List-Grenzen,
   keine Änderung der Format-/check-/decrypt-Limits. Kein konstantes Gesamt-RAM versprechen;
   Containerinhalt bleibt gestreamt, Metadaten/Validierungsstrukturen wachsen begrenzt.
   / Propose listing-only caps of 10,000 entries and 16MiB total path bytes, checked counters,
   no disk fallback. Existing format/check/decrypt limits unchanged; no constant-total-RAM claim.

## Konkreter Umsetzungsrahmen nach Freigabe / Implementation outline after approval

- A: `docs/security/LIST_DESIGN.md`, `docs/JSON.md`, `docs/SPEC.md`/`.en.md` mit Vertrag,
  Threat Model, Grenzen und Test-IDs LIST-001–010; Roadmap-Status und Issue-Zuständigkeit separat.
  / Document contract, threat model, boundaries and stable cases before code.
- B: `src/files/list.rs`, begrenzter gemeinsamer privater Scan (z.B. `src/files/scan.rs`),
  `src/files/check.rs`/`mod.rs`: vorhandene Prüfregeln teilen, kein zweiter Archivparser;
  Verhalten von check durch Regression belegen, decrypt nicht umfassend umbauen.
  / Shared private checked scan, no duplicate parser or broad decrypt rewrite.
- C: `src/cli/list_cmd.rs`/`list_text.rs`, `args.rs`, `mod.rs`, `access.rs`, gegebenenfalls
  `json_out.rs`: neue Ausgabe, vorhandene Entsperrung/Faktoren, nur Leserechte in der Sandbox.
  / New CLI output using existing unlock/factor/sandbox mechanisms.
- D: separate `tests/files_list.rs`, `tests/cli_list.rs`, ggf. zusätzliche Tests interner Grenzen;
  bestehende Help-/JSON-/Sandbox-Tests erweitern. LIST-001 v1/v2; 002 Passphrase/Empfänger/Faktor;
  003 vollständige Authentisierung; 004 Pfade/Duplikate/Konflikte; 005 Ressourcen/Überlauf;
  006 keine Disk-Ausgabe/Quelländerung; 007 neue JSON-/Fehlerverträge; 008 keine Namen vor Fehler;
  009 Linux/Windows-Sandbox; 010 Bestandsregression und isolierter Revert.
  / Separate feature tests and extensions to existing contracts; no new broad fuzzing framework.
- E: README/CHANGELOG/DE-EN-Doku und nachgewiesene Matrixzuordnung. fmt, beide locked
  Clippy-/Volltestvarianten, Limits, cargo-deny, bestehende relevante Python-/Matrixprüfungen,
  native Linux-/Windows-CI und relevante bestehende Fuzz-Ziele. Nicht ausgeführtes offen ausweisen.
  Keine neue Crate geplant. Rückweg: signierter geprüfter Revert, keine Datenkonvertierung.
  / Full existing checks and native CI; no new crate; signed revert without data conversion.

Freigabestatus / approval: **vom Eigentümer erteilt / owner approved**. Keine externe Zustimmung
behauptet. Der zentrale Vorschlag und die Abgrenzung sind in
[#117](https://github.com/SpecterAoD/pqkeep/issues/117#issuecomment-7063008044),
[#98](https://github.com/SpecterAoD/pqkeep/issues/98#issuecomment-7063015533) und
[#153](https://github.com/SpecterAoD/pqkeep/issues/153#issuecomment-7063016144) dokumentiert.
Testnachweise stehen vor Umsetzung aus; keine Baseline vorzeitig auf covered gesetzt. /
Coordination recorded; executable evidence pending implementation, no premature coverage claims.
