# Audit tests and limits / Auditprüfungen und Grenzen (#147)

## Evidence vocabulary / Nachweisarten

| Status / Art | Meaning / Bedeutung |
|---|---|
| Source / Quelle | Concrete pinned source/dataflow inspected; not an extraction proof / konkrete Quellprüfung |
| Fixture / Komponente | Isolated synthetic std/provider reproduction / synthetische Gegenprobe |
| Actual path / Anwendung | Public PQKeep operation with synthetic input / echter Aufruf ohne Nutzerdaten |
| Native CI | Final-commit Linux/Windows execution; exact counts/logs in PR / finale native Ausführung |
| Proposed / Geplant | Test required by future remediation; not executed/implemented here / keine erfundene Abdeckung |
| External / Extern | OS/compiler/provider boundary not established by these tests / Grenze bleibt offen |

DE: Basis ist Main `94b2304`. Produktivpfade bleiben gleich. Auditproben in
[`tests/secret_lifetime_audit.rs`](../../tests/secret_lifetime_audit.rs) werden als eigene
Integrationstestdatei von der vorhandenen nativen CI ausgeführt, mit und ohne API gemäß
bestehender Matrix. Sie erzwingen keine unsicheren Anwendungspfade: std-Fixtures bleiben
auch nach deren Entfernung aus der Anwendung gültig. Der echte Hash-Aufruf berichtet den
Messwert, ohne für immer eine ungesperrte Implementierung zu verlangen.
EN: Synthetic fixtures are not security gates requiring production to stay unsafe. A later
fix can change actual-path measurements; assertions do not forbid that improvement.

## Reproduction / Reproduktion

```text
cargo test --locked --test secret_lifetime_audit -- --nocapture
cargo test --locked --no-default-features --test secret_lifetime_audit -- --nocapture
```

DE: Nur feste synthetische Bytes, keine Passphrase/Schlüssel-/Tokenwerte oder Adressen in
Ausgaben. `/proc/self/smaps` wird nur für noch lebende eigene Allokationen gelesen; nach
Freigabe keine Inhalts- oder Metadateninspektion der Allokation. Ein fehlender Linux-
Messnachweis schlägt fehl. Außerhalb Linux bedeutet `None`: Messverfahren nicht verfügbar,
keine Aussage „ungesperrt“ oder „geschützt“. Die App-Registry ist vom OS-Seitenstatus getrennt.
EN: No real secrets, addresses, foreign-process reads or freed-memory inspection. Non-Linux
None is explicitly unavailable measurement, not a successful Windows lock verification.

| Probe / Gegenprobe | What is actually shown / belegte Aussage |
|---|---|
| Small std reader | 4097-byte request passes through separate internal storage / zusätzliche Kopie |
| Large reader control | 64KiB request can bypass std storage / nicht jeder Read erzeugt dieselbe Kopie |
| Small std writer | capacity−1 bytes remain in live std staging buffer / Retention beobachtbar |
| Empty/large writer controls | No staged bytes for these fixture paths / Negativkontrollen |
| Writer failure | PermissionDenied on flush retains live staged synthetic bytes / Fehlerweg, kein Free-Scan |
| Allocating AEAD spy | aead0.6.1 copies32/65536 bytes before backend encryption; spy then returns Error |
| Direct inout control | The same measuring backend sees caller-owned storage / Gegenvergleich ohne Kopie |
| Actual detached hash | PQKeep digest_reader receives4097 bytes; records buffer registration during Read |

DE: Erste lokale Ausführung auf Linux x86_64/Rust1.99.1: acht Proben bestanden. Gemessen:
std-Reader-/Writer- und AEAD-Kopien `locked=Some(false)`, echter Signatur-Eingabepuffer
`registered=Some(false)`. Der große Reader meldet `private=false`. Acht bestandene
Reproducer bedeuten ausdrücklich nicht, dass A1/A2/A4 behoben sind. Nach Anpassungen und
auf finalem PR-Commit Ergebnisse erneut zuordnen; finale CI/Tests im PR dokumentieren.
EN: Initial local probes reproduce open findings. Native CI and later repetitions must be
reported against their actual commit; no mock/backend probe is a cryptographic KAT.

## Existing coverage to preserve / Vorhandene Abdeckung erhalten

| Concern / Grenze | Existing tests / vorhandene Tests | What remains unproved / nicht bewiesen |
|---|---|---|
| Full lock / Sperrverweigerung | hardening_memlock, hardening_memlock_limit | Other allocations are not covered merely by constructor success |
| Shared pages / Seitenzähler | src/hardening/memlock_tests | Every external allocator/FFI lifecycle |
| Wipe-before-unlock | crypto/secret_buffer_tests, secret_state_tests | Abort/SIGKILL or arbitrary provider construction copies |
| Direct stdin / begrenztes Lesen | cli/secret_input_tests | Rekey's separate std input path A3 |
| Terminal mode / Terminalmodus | scripts/test_terminal_secret.py | Windows WER/widget/driver/kernel memory |
| Linux process flags | hardening_process | Failure enforcement, debugger/dump extraction, deployed Windows policy |
| Authentication/tamper | crypto_aead, crypto_stream, crypto_tamper, files/recovery tests | Entire plaintext allocation inventory |
| Rekey/compatibility | rekey_core/io/compat, cli_rekey, rekey_windows | Three-line memory locking/read-ahead A3 |
| API validation/errors | api_http, api_generate, api_token | Parser/cancel/header/token intermediate lock/wipe A5/A6 |
| No secret echo | cli_factor, cli_keys, cli_json*, API error tests | Every external log hook/intentional output sink |
| Version/atomic output | v1/v2/v3, signed files, rekey, fault/crash tests | OS/power-loss durability or encrypted swap/hibernation |

DE: Dateien unter `tests/` sind Integrationsfälle, unter `src/` explizite `*_tests.rs`.
Alle genannten Fälle sind vorhandene Zuordnungen; ein Name allein ist kein neuer Testlauf.
Vollständige native CI wird für den finalen Audit-PR ausgewertet. Lokale Tests mit Argon2
benötigen ausreichend bereits erlaubtes Memlock-Budget; kein lokales sudo oder Absenken
der KDF-Parameter. Bestehende ausdrücklich freigegebene kurzlebige CI-Prozessbudgets bleiben gleich.
EN: Preserve configured lock budgets and explicit negative zero-budget tests. Distinguish
existing test mapping from actually executed runs; never claim skipped coverage as passed.

## Required remediation tests / Erforderliche Nacharbeitsprüfungen (not implemented / nicht umgesetzt)

| ID | Required case / erforderlicher Fall | Status |
|---|---|---|
| R01 | Actual file input/output/hash: all owned plaintext buffers locked before use, including small/tail chunks | Proposed |
| R02 | No lock resource → sanitized failure before private copy or output; no downgrade | Proposed |
| R03 | AEAD seed/key/chunk copy ownership during backend call; all existing KAT/wire bytes retained | Proposed |
| R04 | Real read/write/flush/sync errors; no public partial output; wipe while still locked | Proposed |
| R05 | Rekey three-line/EOF/CRLF byte boundaries, invalid UTF-8, mismatch and error cleanup | Proposed |
| R06 | Partial JSON parse, unknown fields, invalid algorithm/metadata, request cancellation and queued-task drop | Proposed |
| R07 | Token raw/encoded/format/header ownership, max length, format compatibility, no error echo | Proposed |
| R08 | Provider typed seeds/expanded states/partial construction, denied lock, cleanup and KATs | Proposed |
| R09 | Process-hardening denial and embedder policy; separately validated Windows capabilities | Proposed |
| R10 | Child GUI cancellation/pipe closure/helper lifetime, no secret args/env, fresh child hardening | Proposed |
| R11 | Metadata retention/Debug/Clone/disclosure contract before #98 freeze | Proposed |
| R12 | Abort/OOM/power-loss boundaries; never infer wipe from unwind or change system protection to test | External/proposed |

DE: Bewusst nicht ausgeführt: fremde Speicher-/Swap-/Dump-Extraktion, Deaktivierung von
Schutzmaßnahmen, Windows-Registry-/ACL-/WER-Änderungen, Kernel-/Hibernation-Tests, neue
Ports/Remote-Exposition oder vollständiger externer Provider-Audit. Breite Fuzz-Erweiterung
bleibt #153; neue Kern-/Stream-Verträge bleiben #98/#99/#83.
EN: Unproved boundaries remain open with explicit ownership. Audit success is an inventory
and test/remediation deliverable, not permission to run secrets through known unsafe copies.

DE: Aktueller R6-Gesamtstand: [Provider-Abnahmematrix](PROVIDER_LIFETIME_VALIDATION.md).
Frühere OPEN-/Teilnachweise hier sind historische Zwischenstände.
EN: The current complete matrix supersedes earlier scoped provider status,
without asserting complete R7/R8 or whole-issue147 remediation.
