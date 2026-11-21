# Rekey design and threat model / Rekey-Entwurf und Bedrohungsmodell (#109)

## Status and authorization / Stand und Freigabe

2026-11-21; base `230ce07cdb94264fe3635181c9292da27e5b1f1d`.
EN: Owner authorized issue-scoped analysis, documented design, implementation, signed commits,
tests, push and a fully validated PR without further individual approvals. Merge to main is
excluded. This is a task-specific authorization; repository/system protections remain enabled.
DE: Eigentümer hat Analyse, dokumentierten Entwurf, Umsetzung, signierte Commits, Tests, Push und
fertig geprüften PR für dieses Issue ohne erneute Einzelfreigaben erlaubt. Merge nach main ist
ausgenommen. Aufgabenbezogene Freigabe; Repository-/Systemschutz bleibt erhalten.

## Verified starting point / Geprüfter Ausgangsstand

- EN: #109 includes consolidated #110/#111: semantics, core, atomic output, CLI and restore tests.
  #39–#41 are closed; #152's scoped faults and acknowledged child crashes are available.
  DE: Semantik, Core, atomare Ausgabe, CLI und Restore-Tests gehören zum zusammengeführten Issue.
  Abhängigkeiten abgeschlossen, Scoped-Fehler und bestätigte Prozessabbrüche vorhanden.
- EN: `KeyFile::build` creates a new timestamp and random AES ID. Calling `create` for rekey
  would violate identity preservation. Existing `unlock` authenticates header/material; protect
  helpers generate fresh salt/nonce and use existing v1/v2 AAD. Factor presence defines key v2.
  DE: `build/create` erzeugt Zeit und AES-ID neu und eignet sich deshalb nicht zum Rekey.
  Entsperren authentifiziert Header/Material; vorhandene Protect-Helfer erzeugen Salt/Nonce.
- EN: Envelope I/O already creates private same-directory temps, syncs files, then publishes by
  hard link or explicit rename. Parent sync is best effort; existing no-overwrite publication
  has a non-atomic unsupported-hardlink fallback. Normal callers must retain their behavior.
  DE: Vorhandene I/O-Helfer nutzen private Temps, Datei-sync und Hardlink/ausdrückliches Rename.
  Eltern-sync ist best effort; bestehender Hardlink-Fallback ist nicht atomar und bleibt für
  bisherige Aufrufer unverändert. Rekey soll diesen Fallback nicht benutzen.

## Decisions / Entscheidungen

1. EN: Add `KeyFile::rekey`: authenticate with old `Passphrase`, require new `StrongPassphrase`,
   preserve algorithm, seed/AES bytes, ID (including AES), creation time, metadata, public key,
   factor and format version. Replace only encrypted protection through existing protect helpers.
   Default KDF parameters stay exact; explicit core upgrades may not reduce any m/t/p component.
   No factor add/remove/rotation, new format, crypto algorithm, dependency or remote endpoint.
   DE: Alten Schutz authentifizieren, neue starke Passphrase verlangen, Identität und Format
   exakt erhalten; nur vorhandene Protect-Helfer einsetzen. KDF bleibt standardmäßig gleich;
   ausdrückliche Core-Anpassungen dürfen keine m/t/p-Komponente senken. Kein Faktor-/Formatwechsel.
2. EN: Add a bounded regular-file snapshot (`RekeyFile`) plus output options. Reject final
   symlinks/non-regular files; Linux opens no-follow/nonblocking and validates the opened file.
   Recheck original encrypted bytes before committing. This is no atomic compare-and-swap or
   process lock: source/target directories must be trusted and have a single writer.
   DE: Begrenzter regulärer Datei-Snapshot mit Ausgabeoptionen, keine finalen Links/Spezialdateien.
   Linux zusätzlich no-follow/nonblocking und Handleprüfung. Vor Commit Originalbytes prüfen;
   kein atomarer CAS/Prozesslock, daher vertrauenswürdige Verzeichnisse und nur ein Schreiber.
3. EN: Require explicit `--out`. Default writes a new file and leaves the source unchanged.
   Existing unrelated outputs are never replaced. In-place requires the same canonical source
   path, `--force` plus confirmation (`--yes` for batch), and `--backup` to a distinct absent path.
   Backup contains exact old encrypted bytes, is never overwritten/deleted by recovery, and is
   committed before replacing the source. Unix hard-linked sources cannot be changed in place.
   DE: Ausdrückliches Ziel, standardmäßig neue Datei bei unveränderter Quelle. Fremde bestehende
   Ziele nie ersetzen. Austausch am selben kanonischen Pfad nur mit --force/Bestätigung und neuer
   separater Sicherung. Diese enthält exakt die alten verschlüsselten Bytes und bleibt erhalten.
   Unter Unix kein In-place-Austausch mehrfach hartverlinkter Quellen.
4. EN: Extend shared atomic helpers with a rekey-only strict no-replace path: unsupported hard
   links fail closed, preserving existing fallback semantics for other callers. Backups/new
   outputs use strict publication; explicitly authorized in-place commit uses existing rename.
   No plaintext temp, secret in filenames/logs/argv/environment, automatic migration or cleanup
   of committed backups. After commit, an error can coexist with a complete new file and backup.
   DE: Nur Rekey nutzt strikt kein Ersetzen ohne Hardlink-Unterstützung; bestehende Aufrufer
   unverändert. Sicherung/neues Ziel strikt, ausdrücklicher Austausch per vorhandenem Rename.
   Keine Klartext-Temps, Secretlogs, automatische Migration oder Entfernung gültiger Sicherungen.
5. EN: CLI: `rekey FILE --out PATH [--backup PATH] [--force --yes] [--factor-file PATH]`
   plus `--passphrase-stdin`, `--min-bits` and existing language/batch options. Interactive input
   hides old/new passphrases and confirms new input. Explicit stdin uses exactly three bounded
   lines: old, new, confirmation. Reject ambiguous global `--passphrase-file` for this new command;
   existing commands retain their behavior. No passphrase arguments/environment or new GUI/API.
   CLI keeps KDF parameters unchanged; core-only explicit upgrades must satisfy no-reduction.
   DE: Verdeckte Terminaleingabe oder drei begrenzte Stdin-Zeilen (alt/neu/Bestätigung), keine
   mehrdeutige globale Passphrase-Datei für diesen neuen Befehl. Bestehende Aufrufe unverändert.
   CLI erhält KDF-Parameter; nur ausdrückliche Core-Upgrades ohne Absenkung.

## Invariants and tests / Invarianten und Tests

Stable issue-local IDs below are acceptance IDs, not renamed attack-matrix IDs. Historical matrix
and execution records stay tied to their revisions. / Stabile Issue-IDs, keine Umbenennung von
Matrix-IDs; historische Nachweise bleiben an ihre Revision gebunden.

| ID | Assertion / Aussage | Planned test / Geplanter Test |
|---|---|---|
| RKEY-001 | Same secret, ID, header, format; fresh salt/nonce / gleiche Identität, frischer Schutz | All 7 algorithms, v1/v2 / alle 7 Algorithmen, v1/v2 |
| RKEY-002 | New credential works; distinct old fails / neu gültig, abweichendes alt ungültig | Core roundtrip, tamper/wrong pass / Core-Roundtrip, Manipulation |
| RKEY-003 | No factor weakening or KDF reduction / kein Faktorabbau, keine KDF-Absenkung | Missing/unused/wrong factor, bounds, upgrade / Faktor-/KDF-Grenzen |
| RKEY-004 | Default preserves source; complete output / Quelle bleibt, Ziel vollständig | New output, existing output rejection / Neuausgabe, Kollisionsfehler |
| RKEY-005 | Confirmed replacement preserves exact valid backup / Austausch mit exakter Sicherung | In-place and backup restore / Austausch und Restore |
| RKEY-006 | Failed authentication/validation writes nothing / Fehler schreibt nichts | Wrong old/new/factor, malformed/truncated files / falsche/beschädigte Eingaben |
| RKEY-007 | File/path safety and limits / Pfad-/Dateisicherheit und Grenzen | Links, directories, size, stale snapshot, Unix hard links / Links, Größen, Änderung |
| RKEY-008 | Commit boundaries preserve old or complete new + backup / Commitgrenzen | Scoped write/sync/publish/remove errors on backup/target / Scoped-I/O-Fehler |
| RKEY-009 | No weak FS fallback for new output/backup / kein unsicherer FS-Fallback | Simulated unsupported hard link / fehlende Hardlink-Unterstützung |
| RKEY-010 | Acknowledged child kill/restart never loses usable key / Abbruch/Neustart | Backup/key commit checkpoints, v1/v2 / Sicherungs-/Schlüssel-Commit |
| RKEY-011 | No secret stdout/stderr/argv/env / keine Secrets in Ausgaben/Argumenten | Bounded stdin, confirmation, batch, error/redaction / Eingabe-/Fehlerfälle |
| RKEY-012 | Existing archive/signature and old backup still usable / Bestand bleibt nutzbar | Recipient archive and signature before/after/restore / Archiv/Signatur/Restore |
| RKEY-013 | Real OS errors preserve inputs / echte OS-Fehler erhalten Eingaben | Native Windows sharing locks; Linux 0600 / Windows-Sperren, Linux-Rechte |
| RKEY-014 | Backward compatibility and rollback / Kompatibilität/Rücknahme | Old CLI/API suites, isolated revert + protected hashes / Regression, Revertprobe |

RKEY-010 keeps the generated test credential constant for some child kill checkpoints to isolate
storage commit behavior; different old/new credentials are checked by core/CLI/fault cases. No
secret-bearing protocol extension is needed. / Teilweise gleiche erzeugte Testpassphrase isoliert
den Speichervorgang; unterschiedliche Passphrasen werden in Core-/CLI-/Fehlertests geprüft.

## Steps, files and validation / Schritte, Dateien und Prüfung

A. This design/roadmap, issue assignment and board status (signed documentation commit).
   / Entwurf, Roadmap, Zuweisung und Status, signierter Dokuschritt vor Produktionsänderungen.
B. `src/envelope/rekey*.rs`, `keyfile_rekey.rs`, `envelope/mod.rs`, small `fsutil.rs`/`io.rs`
   strict-path extension; dedicated core/path/fault tests. / Core, Pfade, strikte I/O und Tests.
C. `src/cli/rekey*.rs`, command/access/dispatch wiring, help catalogue and CLI tests; no menu/GUI.
   / CLI, Sandboxfreigaben, Hilfekatalog und Tests, kein Menü/GUI.
D. Small cfg(test) `Operation::Rekey` wiring in crash driver/recovery, new isolated crash tests;
   native Windows lock and Linux permission tests. / Bestehenden Testtreiber begrenzt erweitern.
E. `docs/REKEY.md`, README, SPEC DE/EN, FORMAT/THREAT_MODEL links, CHANGELOG and this design;
   signed commits, explicit actual test evidence, isolated rollback, PR with `Refs #109`.
   / DE/EN-Doku, echte Nachweise, praktische Rücknahme und PR; kein Merge/Issue-Abschluss.

Each step is reviewed/tested before the next; the owner already authorized these issue-scoped
steps without repeated prompts. / Schritte jeweils prüfen, erneute Freigabeabfragen sind für
diesen Aufgabenrahmen ausdrücklich entfallen. No global rules are changed. / Keine globale Regeländerung.

Required: fmt; locked all-target Clippy default/no-default with -D warnings; full locked Rust
suites both configurations; limits/negative limit tests; cargo deny; matrix validation and unit
tests; existing Python/documentation/policy tests. Native Linux/Windows/ARM64 CI, no passing-skip
claims. Use existing dependency versions and test infrastructure; no new workflow permissions.

## Limits, rollback and completion / Grenzen, Rückweg und Abschluss

EN: Process kills keep a running kernel; no OS-crash/power-loss durability promise. Parent sync
remains best effort. Linux new files use 0600; Windows inherits directory ACLs, with no new DACL,
AV/reparse-race or handle-isolation guarantee. Final-link checks are not a directory-race defense.
No secure deletion and no revocation of already copied old key files; their old credential still
works. Backups retain that old protection and must be stored appropriately. Unsupported-hardlink
filesystems cannot host strict new outputs/backups. No existing real user files are used in tests.
DE: Keine OS-/Stromverlustgarantie, Eltern-sync bleibt best effort. Linux0600, Windows geerbte ACLs;
keine neue DACL-/AV-/Reparse-Race-Garantie. Keine sichere Löschung oder Widerruf alter Kopien;
Sicherungen behalten alten Schutz. Strikte Neuausgabe/Sicherung braucht Hardlinks. Tests isoliert.

Rollback: separate signed revert PR, normal CI and owner merge authorization; no data migration.
Generated v1/v2 keys, factor, recipient archive and signature must remain usable before/after the
change and after isolated revert. Completion requires all actual applicable checks, bilingual
docs/limits and a reviewable PR; leave #109 open/In progress until the owner merges.
DE: Rückweg signierter Revert-PR; praktische Rücksetzprobe mit generierten Schlüsseln/Archiv/
Signatur und gleichen geschützten Hashes. Abschluss der Bearbeitung bis zum geprüften PR;
Issue bleibt offen/In progress, Merge entscheidet Eigentümer.
