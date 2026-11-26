# Secret copy inventory / Inventar der Secret-Kopien (#147)

DE: Aktueller enger Ownerschritt auf Main5eb4696: Hash-/HKDF-Ausgabe und PRK ohne
zusätzlichen typisierten Vec direkt in vorab gesperrte SecretBytes; HMAC/Scratch und
Archiv-Framing/Record mit vor Allokation gesperrten inneren SecretWorkspace-Descriptoren.
Native Laufzeitabnahme ist Voraussetzung. Das folgende historische Inventar bleibt
als Ausgangsbefund erhalten; seine A1–A6-Zeilen sind keine Aussage, dass bereits
nachgebesserte Main-Pfade noch dieselben Implementierungen verwenden.
EN: Current scoped fixed-owner remediation uses checked mutable output borrows and
the existing nested workspace owner. Full native validation remains required.
Historical baseline rows below are not a fresh finding against remediated paths;
provider construction/scratch, parser/source/output/tree/shared-registry and
GUI/full-process/compiler boundaries remain OPEN. See
[fixed workspace plan](FIXED_WORKSPACE_OWNER_PLAN.md).

DE: Klasseninventar auf Main `94b2304` mit gezielter Quellprüfung der genannten Pfade,
kein Laufzeit-Heapdump und keine Behauptung, sämtliche Compiler-/Providerkopien erfasst
zu haben. „Gesperrt“ bezeichnet die explizit verwaltete Allokation, nicht jede vorgelagerte
Kopie oder jede Seite eines fremden Providers. A1–A10 sind im [Audit](SECRET_LIFETIME_AUDIT.md)
definiert. Erfolgstests allein schließen die offenen Befunde nicht.
EN: Class inventory and targeted source audit, not heap extraction or complete compiler/
provider-copy enumeration. A locked allocation does not imply locked upstream copies.
Finding IDs refer to the audit; passing functional tests does not close them.

## Current parser protection record / Aktueller Parser-Schutzrecord (#147)

DE: Der persistente ScratchLock-Seitenrecord liegt vor Befüllung im stabil
gesperrten SecretState; vorhandener Payload-Wipe und Unlock bleiben geordnet.
EN: Protect the concrete callback range metadata before in-place acquisition.
The parser-owner remediation below extends this record-only step to persistent
parser/scratch descriptors and SliceRead/index/depth. Shared registry and transit
remain OPEN. Historical baseline rows retain their original meaning; no full
parser closure. [Plan](PARSER_PROTECTION_OWNER_PLAN.md).

## Input and transport / Eingabe und Transport

DE: Aktueller Parserzustandsschritt: gesamten öffentlich leeren SliceRead-Parser
vor Scratch-Reservierung und privater Quellenbindung in SecretState sperren.
EN: New scoped remediation protects persistent parser/source/index/depth and
scratch Vec metadata before population; private positions are not retained.
Actual native/security/fuzz acceptance required. Other source/path/tree/registry
owners, R6/R7 and scalar/compiler transit remain OPEN. Historical rows retain
their baseline meaning. [Plan](PARSER_STATE_OWNER_PLAN.md).

| Class / Klasse | Owner and lifetime / Eigentümer und Lebensdauer | Lock/wipe and failure / Sperre, Wipe, Fehler | Source / Quelle |
|---|---|---|---|
| Ordinary password stdin / normale Passphrase-stdin | Raw duplicated OS handle → bounded bytes → Passphrase | Target locked before read; no std read-ahead; errors drop guard | [secret_input](../../src/cli/secret_input.rs), [io](../../src/cli/io.rs) |
| Confirmed stdin / bestätigte stdin | Two separate bounded locked inputs; compare, convert | Drop both on mismatch; second line not consumed by first read | [io](../../src/cli/io.rs), [secret_input_tests](../../src/cli/secret_input_tests.rs) |
| Rekey stdin | std StdinLock → three Zeroizing<Vec> → Passphrase | Bounded/wiped; no locks; hidden read-ahead and extra byte **A3** | [rekey_input](../../src/cli/rekey_input.rs) |
| Password file / Passphrasendatei | Checked handle → prelocked bounded bytes | Direct reads; normal-error guard; OS ACL/reparse boundaries remain | [unattended](../../src/cli/unattended.rs) |
| Terminal password / Terminalpassphrase | Linux direct read / Windows native record → prelocked UTF-8/state → normalization | Linux/Windows explicit scratch/records in SecretBytes before first read; bounded UTF8/UTF16/repeats; whole-character wipe; continuous confirmation/retry mode, error-only queued-suffix discard and checked restore. Native tests required. Other-platform providers, OS queues, GUI/IME and compiler/scalar copies OPEN | [terminal_secret](../../src/cli/terminal_secret.rs), [input plan](TERMINAL_INPUT_PLAN.md), [native adapter](../../platform/pqkeep-platform/src/console_input.rs) |
| Graphical password / Fensterpassphrase | External helper/widget → OS pipe → child raw input | Parent avoids password bytes/arguments; external widget/.NET/kernel buffers not locked by parent **A8** | [context_dialog](../../src/cli/context_dialog.rs), [dialog](../../src/cli/dialog/mod.rs), [PowerShell](../../src/cli/dialog/powershell.rs) |
| HTTP validate/generate | Hyper body/header → JSON → ordinary String → blocking task/Passphrase | Body limit/auth, but no ingress lock/wipe contract; early-error/cancel paths **A5** | [handlers](../../src/api/handlers.rs), [generate](../../src/api/generate.rs), [server](../../src/api/server.rs) |
| API token generation / Tokenerzeugung | RNG array → Base64 String → final Zeroizing<String> → explicit display | Hash-only persistence; generation/formatting copies not locked, temporary encoding not guarded **A6** | [token](../../src/api/token.rs), [serve](../../src/cli/serve.rs) |
| API bearer token / Bearer-Token | HTTP HeaderValue borrowed by middleware | Length bound and constant-time hash compare; HTTP storage not secret-owned **A5/A6** | [middleware](../../src/api/middleware.rs), [token](../../src/api/token.rs) |
| External API caller / externer Bibliotheksaufrufer | Borrowed &str/&[u8]/String passed into public APIs | Caller owns source copies; destination lock does not retrospectively protect source | [security](../../src/security/mod.rs), [secret](../../src/crypto/secret.rs) |

## Aktueller Argon2-Ownerschritt / Current Argon2 owner step (#147)

DE: Zusätzlich zum bereits gesperrten Blockpayload schützt SecretWorkspace<Block>
jetzt den inneren Vec-Descriptor vor Allokation. Konkreter Drop löscht Blockwerte
und volle frühere Kapazität vor Unlock; Parameter/Parallelität bleiben unverändert.
EN: Nested descriptor and payload locking use the existing owner. Actual lock,
move and denial tests accompany the change. Provider-private Block copies/scratch
remain OPEN. Historical baseline rows below retain their original audit meaning.
[Source](../../src/crypto/kdf.rs), [tests](../../src/crypto/kdf_workspace_tests.rs),
[plan](ARGON_WORKSPACE_OWNER_PLAN.md).

## Secret processing / Verarbeitung

DE: Aktueller enger ML-KEM-Kapselungsschritt: Caller-Entropie sowie K || r und
Ergebnis liegen vor privater Befüllung in SecretBytes. Kein privates SharedKey-
Rückgabetupel auf diesem Pfad; Chiffrat bleibt öffentlich. Historische Tabellenzeile
unten beschreibt den Audit-Ausgangsstand und keine vollständige Provider-Abnahme.
EN: All three parameter sets use borrowed protected encapsulation storage. Native
acceptance required; decapsulation, private constructor/MaybeBox and internal
hash/PKE/compiler copies remain OPEN. [Plan](KEM_ENCAPSULATION_OWNER_PLAN.md).

| Class / Klasse | Owner and lifetime / Eigentümer und Lebensdauer | Lock/wipe and failure / Sperre, Wipe, Fehler | Source / Quelle |
|---|---|---|---|
| SecretBytes | Fixed owned Vec under typed SecretBuffer | Lock before use; incomplete lock rejects; wipe→unlock→free; no Debug/Clone/Display | [secret](../../src/crypto/secret.rs), [secret_buffer](../../src/crypto/secret_buffer.rs) |
| SecretState | Stable Box with public initial/replacement state | Locked destination; destructor in place before unlock; constructor temporaries **A7** | [secret_state](../../src/crypto/secret_state.rs), [tests](../../src/crypto/secret_state_tests.rs) |
| RNG seeds/file keys | OS fills prelocked SecretBytes | No app RNG secret array intermediate; failure drops guard | [rng](../../src/crypto/rng.rs), [encrypt](../../src/files/encrypt.rs) |
| NFKC passphrase | Borrowed source → exact-sized prelocked UTF-8 | Fixed destination and limit; normalization iterator/provider temporaries not fully audited | [security](../../src/security/mod.rs) |
| Strength assessment / Stärkeprüfung | Locked character/byte derivatives → nonsecret enum/count results | Derived buffers locked; errors propagate; returned reasons have no input substring | [locked](../../src/security/locked.rs), [patterns](../../src/security/patterns.rs), [dictionary](../../src/security/dictionary.rs), [policy](../../src/security/policy.rs) |
| Generated password / Generator | Locked RNG pool and candidate → locked Passphrase | Rejected candidates drop; explicit user-requested display crosses sink boundary | [generator](../../src/security/generator.rs), [validate](../../src/cli/validate.rs) |
| Argon2 workspace/output | Caller-owned locked Block array and SecretBytes output | Entire workspace wiped while locked; no smaller KDF on lock failure; provider internals **A7** | [kdf](../../src/crypto/kdf.rs), [typed tests](../../src/crypto/secret_buffer_tests.rs) |
| Factor secret / Faktordatei | Checked direct file read into locked33-byte buffer → locked32-byte Factor | Exact size/type/Unix owner/mode; errors drop; Windows ACL assessment remains #128/#129 | [factor](../../src/crypto/factor.rs) |
| HKDF/HMAC | Locked typed state, scratch, PRK/output → SecretBytes | Public initialization before lock; rekey/finalize in place; wiping retained | [hkdf_locked](../../src/crypto/hkdf_locked.rs), [v2](../../src/crypto/v2.rs), [vendor notes](../../vendor/README.md) |
| AES key schedule | Locked persistent SecretState<Aes256Gcm> | Destination lock/drop verified; by-value construction transit not proven copy-free **A7** | [aead](../../src/crypto/aead.rs) |
| AEAD plaintext on write / beim Schreiben | Locked/caller input → allocating Aead adapter Vec → ciphertext | Hidden private Vec before encryption, including secret wrapping **A2** | [aead](../../src/crypto/aead.rs), [stream](../../src/crypto/stream.rs), pinned aead0.6.1 |
| AEAD plaintext on read / beim Lesen | Ciphertext copied into prelocked SecretBytes, decrypt in place | Guard exists before plaintext; tag failure drops it; provider internals **A7** | [aead](../../src/crypto/aead.rs), [stream](../../src/crypto/stream.rs) |
| ML-KEM seeds/expanded key/shared secret | Locked seed → typed seed/provider DK → shared return → locked output | Seed/shared explicit wipe; provider zeroize enabled; intermediate ownership/locking incomplete **A7** | [kem](../../src/crypto/kem.rs), Cargo features |
| ML-DSA seeds/signing state | Locked seed → typed seed/SigningKey/expanded key → public signature | Seed wipe and provider drop protection; constructor/expanded-state locking incomplete **A7** | [dsa](../../src/crypto/dsa.rs), Cargo features |
| Wrapping/protection/rekey | Locked derived/file/private keys passed by borrow into existing AEAD | Drop derived keys after use; hidden adapter copy **A2**; no JSON seed plaintext | [protect](../../src/crypto/protect.rs), [protect_v2](../../src/crypto/protect_v2.rs), [wrap](../../src/crypto/wrap.rs), [keyfile_rekey](../../src/envelope/keyfile_rekey.rs) |

## Payload, metadata and sinks / Nutzinhalt, Metadaten und Senken

| Class / Klasse | Owner and lifetime / Eigentümer und Lebensdauer | Lock/wipe and failure / Sperre, Wipe, Fehler | Source / Quelle |
|---|---|---|---|
| Plain file source / Klartextquelle | File → std BufReader → ArchiveWriter locked chunk | Hidden reader allocation on small/tail reads **A1**; source-file mutation detection retained | [encrypt](../../src/files/encrypt.rs), [archive](../../src/files/archive.rs) |
| Archive/STREAM explicit buffers | Locked chunk and EncryptWriter buffer / DecryptReader plaintext | Fixed prelock; consumed encryption buffer wiped; allocating seal **A2** outside it | [archive](../../src/files/archive.rs), [stream_io](../../src/crypto/stream_io.rs) |
| Decrypted output / entschlüsselte Ausgabe | Locked chunk → std BufWriter → private temporary file | std staging **A1**; no final publish before full checks/signature; normal cleanup, not crash wipe | [decrypt](../../src/files/decrypt.rs), [output](../../src/files/output.rs) |
| Detached hash input / abgesetzter Hash | File/reader → normal64KiB Vec → SHA3 state | Payload Vec not locked/explicitly wiped **A4**; hash state/provider copies **A7** | [sign/hash](../../src/sign/hash.rs) |
| Archive paths/list / Archivpfade | Decrypted name → String/path sets → cloned bounded Listing → explicit output | Auth before listing; confidential metadata lacks lock/wipe contract **A9** | [archive](../../src/files/archive.rs), [paths](../../src/files/paths.rs), [list](../../src/files/list.rs) |
| Content checksum state / Inhaltsprüfsumme | Plaintext absorb into SHA3 archive/sign state | Not a locked SecretState; examine provider block/stack lifetime **A7**; digest disclosure classification distinct | [archive](../../src/files/archive.rs), [sign/hash](../../src/sign/hash.rs) |
| Ciphertext buffers / Chiffratpuffer | Encrypted input/output, v3 hashing, signatures | No plaintext/key lock requirement merely because Vec/BufReader/BufWriter is used | [decrypt](../../src/files/decrypt.rs), [signed_io](../../src/files/signed_io.rs), [format_v2](../../src/files/format_v2.rs) |
| Protected key JSON / geschütztes Schlüssel-JSON | KeyFile/rekey original/serde/base64/atomic file | Serialized seed is ciphertext, metadata/public keys are public fields; no blanket secret classification | [keyfile](../../src/envelope/keyfile.rs), [parse](../../src/envelope/parse.rs), [io](../../src/envelope/io.rs), [rekey](../../src/envelope/rekey.rs) |
| Salt/nonce/AAD/fingerprints | Public values in arrays/Vec/metadata/headers | Public serialization allowed; AES key ID random, not hash of private key | [keyfile](../../src/envelope/keyfile.rs), [format](../../src/files/format.rs), [format_v2](../../src/files/format_v2.rs) |
| API response JSON | Assessment metadata or encrypted key/public file | No passphrase/seed text in response schema; safe response does not sanitize earlier buffers **A5** | [handlers](../../src/api/handlers.rs), [generate](../../src/api/generate.rs) |
| Error/log output / Fehlerprotokoll | Fixed Error enums, Io(ErrorKind), public assessment reasons | Reviewed paths sanitize values; no claim about arbitrary callers/provider panic hooks | [error](../../src/error.rs), [json_out](../../src/cli/json_out.rs), [handlers](../../src/api/handlers.rs) |
| Child arguments/environment | Command args contain operation/paths, pipe carries password | No secret-argument convention; GUI process owns widget copies **A8**; caller/export sinks external | [context_dialog](../../src/cli/context_dialog.rs), [dialog](../../src/cli/dialog/mod.rs), [pqkeepw](../../src/bin/pqkeepw.rs) |

## Lifecycle and unresolved coverage / Lebenszyklus und offene Abdeckung

DE: Normale Fehler, Drop und Unwinding sind von Abort/SIGKILL/OOM und Systemabsturz zu
trennen. Stabile gesperrte Allokationen können beim normalen Drop gelöscht werden;
ein abgebrochener Prozess führt keine solchen Destruktoren aus. Zurückbleibende private
Temporärdateien und OS-/Terminal-/HTTP-/GUI-Puffer sind dadurch nicht nachträglich gelöscht.
EN: Normal error/drop/unwind evidence does not prove cleanup after abort/kill/OOM/crash,
nor does it erase external buffers or private temporary plaintext left on disk.

DE: Referenzschritte des weiteren Audits: Quellen-/Senkeninventar bei neuen CLI/API-/Provider-
Pfaden aktualisieren; konkret benötigte Secret-Konstruktion vor Lesen/Ableiten sperren;
Fehler vor Ownership-Übernahme und Netzwerk-/Task-Abbruch explizit kartieren. Keinen
Puffer allein wegen `Zeroizing`, `SecretState` oder eines generischen Vec-Typs klassifizieren.
EN: Refresh ownership on every new path, lock before input/derivation, map pre-ownership
and cancellation failures, and inspect contents/dataflow instead of relying on type names.

DE: Nicht bestätigt: tatsächliche Speicher-/Dump-Extraktion, vollständige Compilerkopien,
Windows-WER/ACL-/Debugger-Abwehr, geschützte externe GUI-/Netzwerkpuffer, Hibernation oder
unabhängiger Provider-Audit. Diese offenen Punkte bleiben bei #128/#149/#150 beziehungsweise
der eingegrenzten Provider-/Ingress-Nacharbeit, nicht als erledigte Haken in #147.
EN: No extraction/whole-compiler/Windows external-policy/provider-completeness claim.
Unproved platform and provider coverage remains explicitly assigned follow-up work.
