# R6 provider lifetime acceptance / R6-Providerabnahme

DE: Aktueller Gesamtabgleich zu [R6](SECRET_LIFETIME_REMEDIATION.md) aus #147,
nach [vor Code signiertem Plan](PROVIDER_IN_PLACE_PLAN.md). Er ersetzt die offenen
Zwischenstände früherer Teilnachweise, nicht deren Historie. Implementierung aller
neun Matrixzeilen vollständig; endgültige Abnahme benötigt den exakten signierten
PR-Head mit vollständiger nativer/Sicherheits-/Fuzz-CI und geprüftem Rückweg.
EN: Do not merge a partial row or close all147. GitHub records final acceptance
against the exact resulting head, not against an earlier passing checkpoint.

| Matrix row / Zeile | Actual private path / Tatsächlicher Privatpfad | Evidence / Nachweis |
|---|---|---|
| KEM construction | Root KeyState; typed seed borrow; outer state plus three payloads prelocked before seed; borrowed keygen/hash/sampling/NTT output | kem_key_state_tests/order_tests/denial_tests; all512/768/1024 ACVP keygen and ordinary-provider comparisons |
| DSA construction/signing | Root KeyState plus two prelocked payloads; inline keygen/hedged sign/verification; every rejected candidate stays locked | [DSA](DSA_WORKSPACE_VALIDATION.md);44/65/87 ACVP/keygen/sigver, fresh RNG targets, partial RNG/error/unwind |
| Nested heaps | public initialization only before locks; actual stable private payload ranges guarded separately; explicit key wipe before payload unlock/Box free | KEM ordering witness, actual DSA payload/lock tests; external consumer path/feature resolution |
| KEM encapsulation/decapsulation | borrowed entropy/G/result; complete PKE/implicit-rejection candidate/recomputed ciphertext storage; no private SharedKey tuple | kem_operation_workspace_tests; all three params, valid/tampered/length failures, Wycheproof implicit rejection |
| AES/GCM | inline protected AES schedule/fixslice/native-width batch, GHASH/POLYVAL products, CTR keystream/mask/tag; locked Stream AAD | [AES](AES_OPERATION_WORKSPACE_VALIDATION.md);72 independent vectors, disjoint buffers, init/wipe/error/unwind/denial |
| Argon2 | fixed operation/initial/final/long-hash scratch; prelocked block matrix and one inline worker per configured lane; original parallel scheduler | [Argon2](ARGON_OPERATION_WORKSPACE_VALIDATION.md); RFC9106,76 C vectors,512 BLAKE2b cases, every lane4*t, AVX2 and portable native execution |
| SHA3/SHAKE/HMAC/HKDF | prelocked state/output, inline permutation lanes; borrowed XOF reader and HMAC/PRK/expand; direct scalar sponge byte access | [hash](HASH_WORKSPACE_VALIDATION.md); independent hashlib/OpenSSL and v1/v2 domain/wrap KATs; original Keccak rounds |
| Unicode/Base64 | NFKC callback/static-table/scalar primitives with locked decomposition/sort/output; token remainder in seven prelocked bytes | normalize_tests: every Unicode scalar, Unicode18 five-column conformance; [Base64](BASE64_WORKSPACE_VALIDATION.md):304 Python cases |
| Failure/platform/source | actual owners stable/locked before input; complete destruction/capacity/padding wipe before unlock/free; no resource fallback | isolated bounded error/unwind/denial children; native Linux/Windows/ARM64; provenance/strict lint/MSRV/online audit/full-history scan/eight fuzz targets |

## Reachability and classification / Erreichbarkeit und Klassifikation

DE: Root benutzt für private Operationen ausschließlich die konkreten geschützten
Einstiege, keine beliebige Providerinjektion. Gewöhnliche Konstruktoren/Operationen
bleiben als öffentliche Kompatibilitäts-/Referenz-APIs im Provider; sie sind kein
Fallback. Private PKE-/NTT-/Hash-/BLAKE2-/AEAD-Zwischenarrays sind bekannte Flächen
und liegen in diesen Workspaces, statt als Compilergrenze umbenannt zu werden.
EN: Source hashes/invariants preserve original round bodies, constants, reference
indexing, lazy hashing, hedged nonce/rejection rules, CT comparison/selection and
parallel segment barriers. Versions/parameters/worker counts/wire bytes unchanged
by R6; independently merged Main dependency updates are retained and reviewed.

DE: Archivprüfsummen, Dateiinhalts-/Tokenhashes, v4-Schlüsselbindung und neuer
verborgener Absender verwenden LockedHash mit geschütztem Provider. Gewöhnliche
Digest-Aufrufe hashen sichtbare Header, öffentliche Schlüssel/Fingerprints oder
Integrationsdateien. Der v3-HashingWriter/Tail hasht Chiffrat. Hashen vertraulicher
Nachrichten zur DSA-Prüfung benutzt ebenfalls geschützte Verifikationsflächen.
EN: getrandom fills borrowed locked destinations for seeds/keys/hedged randomness;
rng::array is used for public salts, nonces and random public identifiers.

DE: Base64-Aufrufe und gleichversionige Registry-Transitive sind in dessen Nachweis
einzeln klassifiziert. NFC-Iteratoren in envelope/metadata bearbeiten ausdrücklich
unverschlüsselte Schlüssel-Metadaten, keine Passphrase. Die API schützt weder
fremde Caller-Strings rückwirkend noch macht sie personenbezogene Daten unkritisch.
NFKC für Passphrasen nutzt die callbackbasierten Unicode-Primitiven mit gesperrten
Arbeitsflächen; skalare Zeichen und öffentliche Tabellen sind keine privaten Arrays.
DE: UTF-8-Char-Schreiben und ASCII-Validierung auch gegen die exakten offiziellen
Rust1.88-MSRV-Blobs geprüft: [Char-Primitiven](https://github.com/rust-lang/rust/blob/1.88.0/library/core/src/char/methods.rs),
[UTF-8-Validierung](https://github.com/rust-lang/rust/blob/1.88.0/library/core/src/str/validations.rs).
EN: Both the minimum supported Rust source and installed stable source use scalar
stores/native-word ASCII reads on these reached paths, not private scratch arrays.
EN: Public signature/digest outputs are intentional disclosure boundaries. Hidden
sender identity/signature retention and confidential length/metadata policy belong
to R8; protected internal hashing/signing does not settle that separate output policy.
External ingress/source/sink ownership and GUI/process policy remain separately mapped.

## Native, resource and performance evidence / Native-, Ressourcen- und Laufzeitnachweise

DE: Zwischenstände: DSA26117f6 alle23 Checks; AES2b44f3e alle23; Argon2e5868d6
alle23. Vollständige native Logs gehasht: Argon Ubuntu22/ARM je903Tests,
Ubuntu-latest1732 und Windows1568 über jeweilige Konfigurationen, null Fehler;
echte AVX2-Flags Linux/Windows=true und ARM=false. Spätere Main-/Base64-/Dokument-
Änderungen benötigen eigene finale Abnahme. Kein übersprungener Test zählt als Beleg.
EN: Token Base64 local10/10,304 independent cases and ordinary API compatibility;
four strict Linux/Windows-cross lint configurations. Cross checks are not native ABI tests.

DE: Regression #325: beide unveränderten CLI-Profile standard256MiB/t3 und
hardened1GiB/t4 müssen bei8MiB-Sperrbudget im eigenen begrenzten Linux-Kind mit
MemoryLock-Hinweis/Exit1 ohne Ziel-/Restdateien abbrechen. Keine Parameterabsenkung,
Rechteerhöhung oder Systemänderung. Nullbudget-Unit-Kinder prüfen zusätzlich die
privaten Provider-Einstiege; Erfolgstests laufen mit ausreichendem Testprozessbudget.
EN: The low-budget test must actually enforce the limit; a privileged/skipped run
is not evidence. Existing native suites keep their original concurrency and gates.

DE: Rechenbenchmarks mit öffentlichen synthetischen Daten: SHA3/SHAKE protected/
reference etwa1.076–1.189; AES/GCM3.442/2.999/3.099 für32/1024/65536Byte; Argon2
0.951/0.928/0.961 bei64MiB-p1/64MiB-p4/256MiB-p4,t3. Je fünf verschränkte Messungen,
Sperr-/Allokationskosten ausgenommen. Portabler geschützter AES-Pfad kostet sichtbar
Leistung; keine ARM-/End-to-end-Zusage oder allgemeine Beschleunigungsbehauptung.
EN: See checkpoint validation documents for hardware, formulas, boundaries and raw evidence.

## Unsafe and remaining boundaries / Unsafe und verbleibende Grenzen

DE: Root behält forbid(unsafe_code). Keine zusätzliche eigene Unsafe-Grenze in
R6; drei Sponge-Casts und ein Base64-Cast entfallen. Zwei bestehende Argon2-AVX2-
Grenzen erhalten geliehene Ausgaben bei gleicher Laufzeit-Erkennung, target_feature-
Schranke,64Byte-Ausrichtung und disjunkten Rust-Leihen. Übernommene Scheduler-,
Allocator-,ARM-/Windows-/Std-/Zeroize-Interna sind ausdrücklich nicht unsafe-frei.
Main352s Zeroize1.9.2-Bulk-/Assemblerbarrieren und portabler volatiler Rückweg
sind gegen beide gepinnten Archive geprüft; keine geänderte Root-Schutzregel.
EN: Necessary FFI/intrinsic unsafe requires its original safety invariants. Passing
tests/source review is not a formal soundness proof. PR332's separate reduction
of unnecessary Windows record unsafe is retained; rejected stack switching is absent.

DE: Keine Garantie über jeden skalaren Registerwert, Compiler-Spill, CPU-Cache,
Swap-/Hibernate-/Crash-/Debugger-/Hostzugriff. Diese Grenzen sind keine Erlaubnis
für bekannte private Array-/Vektorkopien. Normaler Drop/Unwind ist kein Abort-/
SIGKILL-/OOM-Wipe-Beweis. Ein unabhängiges externes Krypto-/Compiler-Audit wird
nicht behauptet. R7 und R8 bleiben offen; #147 insgesamt bleibt In progress.
EN: Complete R6 means this concrete source-level provider-lifetime matrix, not a
promise to eradicate all machine/register copies or repair unrelated OS/metadata policy.

## Final acceptance and rollback / Endabnahme und Rückweg

DE: Vor Merge müssen finaler Head/Signaturen/exakter integrierter Main-Baum,
alle Pflichtchecks samt vier nativen Vollprotokollen und acht Fuzz-Zielen, aktuelle
Audit-/Scan-Ergebnisse sowie vollständiges Bundle mit unabhängiger Wiederherstellung
geprüft sein. Reverse-Patch in separatem Index muss exakt den vorigen Main-Baum
ergeben. Kein Release, keine Datenmigration, kein automatischer Sicherheitsrevert.
EN: Evidence is retained in analysis/issue-147-provider-in-place-20261126T171500Z;
source-bound checkpoint documents and GitHub checks remain reviewable in the PR.
Automatic remote branch deletion still requires exact scoped owner approval;
local worktrees/branches, bundle and all earlier evidence are retained.

DE: Zusätzliche lokale Gesamtabnahme: r6-matrix-local-v2.json alle sieben Kommandos
erfolgreich, beide Feature-Konfigurationen des tatsächlichen8MiB-CLI-Tests mit
erzwungener Limitprüfung (kein Skip), jeweils standard und hardened. Beide strengen
Test-Clippies, fmt/Limits/Diff grün. Memlock des Elternprozesses vor/nachher identisch.
EN: This adds resource-profile coverage without changing production code, crypto
parameters or CI gates. Final native checks and independent rollback remain required.
