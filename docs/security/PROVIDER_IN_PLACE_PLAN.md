# R6 provider lifetime completion / Provider-Lebensdauer vollständig schließen

DE: Eigentümerauftrag: R6 aus #147 vollständig bearbeiten. Dieser Plan führt keine
zusätzliche Freigabeschranke ein. Er wird vor Produktionscode signiert. Basis ist
Main #331; die getrennte Record-Borrow-Korrektur #332 bleibt unverändert.
EN: Owner explicitly requests complete R6 remediation. Sign this plan before code;
preserve Main #331 format v4 and the independently reviewed #332 change.

## Contract / Vertrag

DE: Bestehende RustCrypto-Algorithmen und Parametersätze erhalten. Private typisierte
Seeds, expandierte Zustände, Rückgabewerte und tatsächlich erreichbare Arbeitsflächen
einzeln verfolgen. Öffentliche Anfangswerte vor privater Befüllung stabil sperren;
nachträgliche Sperren sind kein rückwirkender Schutz. Wipe vor Unlock und Freigabe,
auch bei Teilinitialisierung/Fehler/Unwind. Keine neuen Kryptoalgorithmen, beliebige
Providerinjektion, schwächeren Parameter, gesenkten Workerzahlen oder Schutz-Ausnahmen.
EN: Preserve algorithms, parameter sets, worker counts and wire bytes. Prelock before
private population; prove wiping before unlock/free on success, failure and unwind.
Do not equate a protected caller buffer with protected provider internals.

## Implementation map / Umsetzungsplan

1. DE: KEM-Entkapselung ohne privaten Rückgabewert: additive borrowed-output-API im
   vorhandenen `vendor/ml-kem-0.3.4`, Root-Adapter und Gegenproben aller Parametersätze.
   EN: Add borrowed-output decapsulation without changing implicit rejection.
2. DE: KEM-/DSA-Konstruktoren, MaybeBox-Payloads und expandierte private Zustände über
   gezielte In-place-Einstiege und feste gesperrte Arbeitsflächen bearbeiten; vereinigte
   Features und externe Consumer berücksichtigen.
   EN: Protect construction and nested private heaps, including unified alloc features.
3. DE: AES-Key-Schedule, GHASH/GCM/CTR und Hash-/XOF-Zwischenzustände an ihren tatsächlichen
   Produktionsaufrufen abgleichen. Keine private Konstruktor-Rückgabe auf normalen Stack.
   EN: Audit and adapt the actual AES/hash/XOF state-construction and scratch paths.
4. DE: Argon2-Initial-/Finalhash, Blockkopien und parallele Worker getrennt prüfen;
   normalisierte Unicode-/Base64-Pfade anhand tatsächlicher Aufrufe klassifizieren.
   EN: Keep parallel-worker coverage separate from caller workspace protection.

DE: Betroffene Dateien: `src/crypto/{kem,dsa,aead,kdf,locked_hash,hkdf_locked}.rs`,
eigene Adapter-/Testmodule, konkret notwendige versionierte Providerquellen, deren
Manifeste/Lockfiles/Herkunftsregister und Sicherheitsdokumentation. Nur nachgewiesen
notwendige Änderungen; kein Umbau unabhängiger GUI-/Prozess-/Metadatenpfade.
EN: Keep changes scoped to actual provider lifetimes, source provenance and regression
evidence. Root `forbid(unsafe_code)` and all CI/scanner gates remain mandatory.

## Acceptance matrix / Abnahmematrix

| Group / Gruppe | Required proof / Nachweis | Initial state / Anfang |
|---|---|---|
| KEM construction | typed seed, expanded DK, constructor transfers | OPEN |
| DSA construction/signing | seed, expanded key, rejection workspaces | OPEN |
| Nested heaps | prepopulation locks, feature unification, external consumer | OPEN |
| KEM encapsulation/decapsulation | caller buffers, provider intermediate/return values | OPEN |
| AES/GCM | schedule, GHASH and CTR workspaces | OPEN |
| Argon2 | initial/final hash, block copies, every private worker | OPEN |
| SHA3/SHAKE/HMAC/HKDF | private state/scratch and finalization transfers | OPEN |
| Unicode/Base64 | actual reachable private buffers, explicit public-only paths | OPEN |
| Failure/platform/source | partial init, wipe/unlock, Linux/Windows, provenance | OPEN |

DE: Ein Teilfix schließt keine Zeile, deren übriger Nachweis fehlt. Keinen bekannten
Providerpuffer als unvermeidliche Compiler-/Registerkopie umklassifizieren. Hardware,
Register-Spills und OS-/Crash-Grenzen präzise benennen; keine pauschale Kopierfreiheit.
EN: Do not close a row based on a partial fix or reclassify known buffers as compiler
limits. An unproven alternative execution stack is not an accepted remediation.

## Tests and rollback / Tests und Rückweg

DE: Gegen unveränderte Provider-APIs und unabhängige KATs prüfen: alle drei KEM-/DSA-
Parametersätze, gültige/manipulierte Chiffrate, v1/v2-Wrapping, v3-Signaturen und v4-Dateien.
Echte Lock-/Wipe-Beobachtung, Verweigerung vor privater Verarbeitung und Unwind prüfen.
fmt, beide strengen Clippy-/Feature-Konfigurationen, Herkunft/Limits, native Linux-/Windows-
und ARM64-Suiten, CodeQL, Dependency-/Secret-Audit und bestehende Fuzz-Ziele ausführen.
EN: Validate actual runtime ownership, compatibility and denied resources, not merely
source patterns. Report pending checks separately; no skipped gate counts as success.

DE: Vollständiges Bundle unabhängig wiederherstellen, Signaturen/Dateibaum prüfen;
Reverse-Patch gegen separaten Index muss den exakten Basisbaum wiederherstellen.
R6 bleibt bis vollständiger Abnahme offen; #147/R7/R8 werden nicht automatisch geschlossen.
EN: Prove exact rollback without touching retained worktrees. Any security rollback,
merge-triggered branch deletion or host-setting change keeps its explicit approval rules.
