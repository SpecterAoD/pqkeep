# R8 borrowed path components / Geliehene Pfadteile

DE: Autorisierter enger Folgeschritt zu #147 auf Main31052d8ef1, dessen native
Main-Abnahme separat läuft. Plan vor Code unter dem bestehenden Eigentümerauftrag
zur eigenständigen Behebung. Kein neuer Provider-/GUI-/Prozessvertrag.
EN: Seven internal validate calls allocate ordinary component-reference vectors;
five discard them and two consume them. Remove these internal tables by reusing
fully validated borrowed iterators, keeping public caller-owned contracts intact.

## Dateien / Files

- src/files/paths.rs: one shared allocation-free validation path returning a
  clonable borrowed iterator; public validate still collects Vec for its callers.
  Share bounded folded-key/conflict logic for public slices and private iterators.
- src/files/scan.rs, decrypt.rs and walk.rs: switch all seven internal calls,
  preserving validation order, listing budgets and failures before filesystem use.
- src/files/output.rs: accept borrowed components directly, with no new joined
  String or component Vec. Existing ordinary output PathBuf lifetime remains OPEN.
- Separate path-component tests plus existing path/list/archive/recovery/Unicode
  tests; SPEC DE/EN, MEMORY_HARDENING, ROADMAP and CHANGELOG scope updates.

## Invarianten / Invariants

DE: Regeln255/4096Bytes und Tiefe64, reservierte Namen, Unicode-/Sigma-Faltung,
Duplikate und Datei-/Ordner-Vorfahrenkonflikte unverändert. Gesamten Pfad prüfen,
bevor Iterator an nachgelagerte Dateierzeugung gelangt; keine lazy validation nach
ersten Seiteneffekten. Öffentliche validate()->Vec und PathSet::insert(&[&str])
behalten ihren Vertrag; keine ungeplante Änderung einzelner Teile-Slice-Semantik.
EN: Existing normalized keys still use mandatory prelocked ConfidentialText and
SecretBytes. No unguarded normalized/joined path scratch is introduced. Iterator/
scalar stack state, caller-owned public Vec results, shared tree topology and
ordinary source/output path copies remain distinct OPEN boundaries.

## Prüfung und Rückweg / Validation and rollback

DE: Private/public validation equivalence at real boundaries and invalid later
components, iterator replay/borrowing, Unicode conflicts and no-state-change on
rejection. Both strict Clippies/features, fmt/limits/provenance; focused file/lock/
owner/unwind tests locally. Exact final-head full Linux/ARM64/Windows CI, existing
archive tamper/recovery tests, security gates and all eight fuzz targets before merge.
EN: Signed commits, complete independently restored/fsck-checked bundle and practical
reverse-patch proof of exact Main310 tree e5c18faf6c6e2fd9611c7dbf0b582a96fb49dbee.
No data migration, host setting, dependency, unsafe, KDF, format, CI or scanner change.
Reviewed revert PR is the recovery path; never an automatic weaker fallback.

DE: Issue147/Roadmap bleiben In progress. R6-Konstruktion/Provider-Scratch und R7
verifizierte Helper/volle Prozesspolicy sowie weitere R8-Daten bleiben offen.
EN: Removing component-reference allocations is not complete path/process/provider
protection. Source/static evidence and actual native execution are tracked separately.
