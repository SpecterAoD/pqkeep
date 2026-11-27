# Pinned provider patches / Gepinnte Provider-Anpassungen

DE: Ausgangspunkt sind exakt die bereits verwendeten Cargo-Versionen. Die SHA-256-Werte
aller unveränderten Ausgangsdateien stehen in `upstream-sha256.json`; vollständige Original-
Lizenztexte bleiben erhalten. Keine Algorithmen, Konstanten oder Formatbytes wurden geändert.
Die Änderungen sind Teil des Sicherheitsreviews und werden nicht als unveränderte Upstream-
Artefakte ausgegeben. SBOM/Cargo-Metadaten kennzeichnen diese Pakete als lokale Pfadquellen.

EN: These are the exact previously used Cargo versions. Original source hashes and complete
license texts are retained. These reviewed local path packages are explicitly modified providers,
not pristine upstream artifacts. Algorithms, constants and file-format bytes are unchanged.

| Package | Upstream | Narrow patch / begrenzte Änderung |
|---|---|---|
| hmac 0.13.0 | RustCrypto/MACs, MIT OR Apache-2.0 | In-place rekey/finalize using caller-provided scratch; zeroize opad on Drop and keyed state on explicit wipe. Existing API preserved. |
| hkdf 0.13.0 | RustCrypto/KDFs, MIT OR Apache-2.0 | Allocation-free first HKDF block over caller-owned HMAC/PRK/output. Same extract/expand steps; no hidden PRK or cloned keyed state. Existing API preserved. |
| region 4.0.1 | darfink/region-rs, MIT | Safe current-process Windows working-set capacity request before VirtualLock. No token, account, privilege or machine-policy changes; errors are propagated. Existing lock API preserved. |
| ml-kem 0.3.4 | RustCrypto/KEMs, Apache-2.0 OR MIT | Borrowed keygen and complete PKE operation workspaces, prelockable payloads, direct codecs/transforms and protected hash/XOF state; preserve legacy APIs and algorithms. |
| module-lattice 0.2.4 | RustCrypto/KEMs, Apache-2.0 OR MIT | Borrowed codec destinations; shared original packing loops with scalar little-endian accesses instead of private conversion arrays. |
| ml-dsa 0.1.2 | RustCrypto/signatures, Apache-2.0 OR MIT | Borrowed keygen/sign/verification workspaces; fixed private payloads prelocked by Root; existing arithmetic and hedged randomness preserved. |
| sha3 0.12.0 / shake 0.1.0 | RustCrypto/hashes / sponges, MIT OR Apache-2.0 | Opt-in inline permutation scratch; borrowed XOF reader finalization and explicit wipe. |
| keccak 0.2.2 | RustCrypto/sponges, MIT OR Apache-2.0 | Existing portable permutation with borrowed five-lane scratch. Ordinary backend dispatch preserved. |
| sponge-cursor 0.1.0 | RustCrypto/sponges, MIT OR Apache-2.0 | Captured permutation closure; direct scalar byte accesses replace private arrays and three inherited pointer casts. |
| aes 0.9.2 | RustCrypto/block-ciphers, MIT OR Apache-2.0 | Borrowed AES-256 fixsliced key schedule, rounds and native-width batch scratch; ordinary hardware dispatch preserved. |
| aes-gcm 0.11.1 | RustCrypto/AEADs, MIT OR Apache-2.0 | Fixed protected AES-256/GCM workspace, original CTR32BE counters and authenticate-before-decrypt contract. |
| ghash 0.6.0 / polyval 0.7.3 | RustCrypto/universal-hashes, MIT OR Apache-2.0 | Borrowed portable multiplication/reduction, GHASH reverse/mulX and fixed private intermediate storage. |
| argon2 0.6.0 | RustCrypto/password-hashes, MIT OR Apache-2.0 | Borrowed complete operation storage and one prelocked worker per lane; original parallel scheduler and AVX2 dispatch retained. |
| blake2 0.11.0 | RustCrypto/hashes, MIT OR Apache-2.0 | Inline compression/message scratch, borrowed vector operations and lazy buffered output; ordinary APIs preserved. |
| base64ct 1.8.3 | RustCrypto/formats, MIT OR Apache-2.0 | Borrowed remainder scratch for private token encoding; shared original alphabet/padding, safe UTF-8 view, ordinary APIs preserved. |

DE: Der Token-Einstieg leiht exakt sieben vorab gesperrte SecretBytes an Base64.
Quelldaten und Ausgabe sind ebenfalls gesperrt. Löschen erfolgt vor Unlock/Free,
auch bei Fehler/Unwind; Sperrfehler verweigern ohne gewöhnlichen Encoder-Fallback.
Die gewöhnlichen Base64-APIs bleiben für öffentliche Hüllfelder/Skripte erhalten.
EN: Complete production modules/licenses come from the checksum-verified1.8.3 archive.
The inherited decode/string unsafe remains outside the protected token path; one
inherited encode UTF-8 cast is removed. No newly authored unsafe. Registry copies
of the same version still serve unchanged transitive password-hash/DER APIs; Root
never uses those APIs for private seed/token encoding. No global patch assumption.

DE: Root aktiviert protected-workspace für private SHA3-/SHAKE-Verarbeitung. Hash und
Reader enthalten ihre fünf Scratch-Lanes inline und werden vor privater Befüllung
gesperrt. Der vorhandene portable Backend wird geteilt; die zusätzliche private
ARM-Intrinsics-Arbeitsfläche wird dadurch vermieden. Dies kann ARM-Beschleunigung
kosten; kein neuer Algorithmus oder neue Assembly. Ohne das opt-in bleibt die
Upstream-Backend-Auswahl erhalten. Alle Produktionsmodule/Lizenzen bleiben erhalten;
nur Dev-/Test-/Bench-Targets fehlen in diesen vier Subsets.
EN: Borrowed finalization never returns a private reader in the protected Root path.
Explicit Zeroize and Drop cover state, cursor and scratch. Preserve all rates,
padding and output bytes; independent hashlib/OpenSSL vectors cover block boundaries
and split calls. Package versions remain identical in Root/Fuzz/external consumers.


DE: Die beiden neuen Subsets enthalten sämtliche Produktionsmodule und vollständige
Original-Lizenzen. Nur Dev-/Test-/Bench-Targets sowie acht reine Inline-Testmodul-
Suffixe von ML-DSA fehlen. Ausgewählte Originaldateien bleiben einzeln gehasht;
jede Abweichung steht im Patchregister. Root und Fuzz behalten alle Paketversionen.
EN: Both production subsets preserve all production modules and original licenses.
Only development targets/dependencies and eight pure ML-DSA test suffixes are omitted.
Versioned dependency paths apply to external consumers, with no root-only patch.

DE: ByteEncode/ByteDecode delegieren an geliehene Ausgabe-Schleifen. 12-Bit-Reduktion
und öffentliche Geometriegrenze bleiben erhalten. Der KEM-CBD-Sampler dekodiert
direkt ins Ziel und berechnet dort dieselben Koeffizienten; kein zweites lokales
Dekodierpolynom. Legacy-Rückgaben und private Sampling-/XOF-Zustände bleiben offen.
EN: Independent bit tests cover all used KEM/DSA widths in prelocked stable storage.
This removes conversion arrays and one CBD intermediate, not all provider scratch.

DE: ML-KEM stammt aus dem gegen das Basis-Cargo.lock geprüften Originalarchiv.
Produktionsquellen/README/Lizenzen vollständig erhalten; nur Test-/Benchmarktargets,
Dev-Abhängigkeiten und reine Inline-Testmodul-Suffixe aus dem Produktionssubset
weggelassen und exakt im Patchregister erfasst. Keine Parameter-/Versionsänderung.
EN: Preserve complete production code and original licenses, with per-file original
hashes. The new output path does not imply protected private constructors, separate
MaybeBox storage, decapsulation or internal hash/PKE/compiler copies. Root and fuzz
select the same path provider. Refresh the existing Blake2 root dependency reference
in the stale fuzz lockfile; no selected package version changes.

DE: Der R6-Arbeitsbranch ergänzt `DecapsulateInto`: Ausgabe direkt in geliehene,
vom Caller vorab gesperrte 32 Byte. Die bestehende Berechnung der Kandidaten wird
geteilt; die neue Ausgabe verwendet konstante bedingte Zuweisung von ctutils.
Alte APIs/Parameter bleiben erhalten. Private Kandidaten, PKE-/Hash-Arbeitsflächen
und Konstruktoren sind damit ausdrücklich noch nicht geschützt.
EN: Borrowed-output decapsulation removes the returned private SharedKey array.
Existing APIs share the original candidate computation, with ctutils conditional
assignment for the borrowed destination. Internal candidates, scratch and private
construction remain open; differential output tests alone do not close R6.

DE: `EncapsulateWithHash` leiht zusätzlich den vorab gesperrten SHA3-512-Zustand des
Callers. `FixedOutputReset` vermeidet dessen konsumierende private Wertübertragung;
Reset vor und nach Absorb verhindert Altzustand. Die alte API bleibt verfügbar.
EN: The additional encapsulation entry borrows caller-prelocked SHA3-512 state and
uses FixedOutputReset, preserving the old API. The protected hash feature below
also borrows permutation scratch; remaining private PKE storage stays open.

DE: `SeedKeyInPlace` erzeugt nur öffentlichen Anfangszustand, besucht genau drei feste
private Speicherbereiche und befüllt deren bestehende Payloads aus geliehenem Seed.
Root muss Zustand und Payloads vorher sperren und vor Guard-/Boxfreigabe explizit
zeroisieren. `Zeroize` und Drop verwenden dieselbe bisherige Payload-Löschung.
EN: Public initial state plus fixed private-storage visitation enables host prelocks
before seed population. Explicit Zeroize and Drop share the original wiping body;
private boxes are never replaced during initialization. Root PKE keygen writes
expanded state through borrowed NTT output, sharing the original transform loops.
The operation workspace extension below also covers private encryption/decryption
and candidate storage; native acceptance remains required.

DE: KeyGenerationWorkspace ergänzt feste Inline-Flächen für Samplingvektor,
Fehler-NTT, Produktpolynom, noch private öffentliche-Schlüssel-Zwischensummen,
PRF-/G-Ausgabe und SHA3-512-Zustand. Root sperrt die gesamte stabile Arbeitsfläche
vor dem Seed-Einstieg. Die alten APIs teilen dieselben Sampling-/NTT-/Produkt-
Schleifen; nur vollständig fertiggestellte öffentliche Werte werden zurückgegeben.
EN: Key generation borrows prelocked fixed storage, with no nested workspace heaps.
Root refuses failed workspace locks before private initialization. ML-KEM/zeroize
now forwards SHA3/SHAKE zeroization explicitly, including standalone consumers.
Keygen also borrows prelocked SHAKE hash/reader state and inline Keccak scratch in
the protected mode below. Operation scratch is now borrowed as described next.

DE: Das aktuelle Format braucht genau 32 HKDF-Bytes = einen SHA3-256-Block. Der neue
HKDF-Einstieg ist ausdrücklich darauf begrenzt, kein neuer allgemeiner KDF-Baukasten.
HMAC-Zustand und Scratch/PRK/Ausgabe liegen in typisierten gesperrten SecretBuffer-Instanzen.
Provider-Hashzustände verwenden aktiviertes SHA3-zeroize. Die Herkunft ist die Cargo-Registry
der Versionsnummern aus dem Ausgangs-Lockfile; dessen Checksummen bleiben im Git-Verlauf.

EN: Current formats need exactly one 32-byte SHA3-256 HKDF block. The added entry point is
limited to that operation. HMAC state, scratch, PRK and output use locked typed SecretBuffer
storage. SHA3 zeroize is enabled. Source originates from the versions in the baseline lockfile.

DE: Tests vergleichen gegen die unveränderte Upstream-API an HMAC-Blockgrenzen und gegen
bestehende unabhängige v2-KATs. Vollständige Linux-/Windows-Regressionsprüfungen und das
Lizenzinventar sind vor Merge erforderlich. Kein Test darf eine fehlgeschlagene Sperre umgehen.
EN: Test against unchanged upstream APIs at HMAC boundaries and existing independent v2 KATs;
require full Linux/Windows regressions and license inventory before merge. Never bypass failed locks.

Windows references / Quellen:
- https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock
- https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-setprocessworkingsetsize

DE: Direkte versionierte Pfadabhängigkeiten gelten auch für externe Consumer und den
separaten Fuzz-Workspace; kein nur im Root wirksames Cargo-Patch. Das Projekt bleibt
`publish = false`. Vor einer Crates.io-Veröffentlichung (#71) müssen diese Provider
über einen gesondert geprüften Veröffentlichungsweg verfügbar sein.
EN: Direct versioned path dependencies also apply to external consumers and the separate
fuzz workspace. Publishing remains disabled; #71 requires a reviewed provider publication path.

DE: Für den unveränderten Sonar-Duplikationsgrenzwert wurden die byteidentischen
BSD-Protection-Flag-Abbildungen samt identischen Tests einmalig in `bsd_protection.rs`
zusammengeführt. Beide OS-Module inkludieren exakt denselben bisherigen Code; keine neue
FFI, keine geänderte Abbildung, kein Linux-/Windows-Laufzeitpfad. Die Gleichheit beider
ursprünglichen Kopien wurde vor der Extraktion geprüft. Native BSD-Abnahme wird nicht behauptet.
EN: Consolidate byte-identical BSD protection mappings/tests into a shared include, preserving
code and the unchanged duplication threshold. No new FFI, mapping or Linux/Windows behavior;
verify both original copies identical before extraction. No native BSD test claim.


#147 protected ingress / geschützter Eingang:
- DE: Additive SliceRead-Vorbereitung: Host sperrt öffentlichen leeren Parser vor
  Scratch-Reservierung; erst nach vollem Payload-Schutz wird Quelle direkt gebunden.
  EN: In-place one-shot protected parser binding; no scratch Vec escape, unchanged
  ordinary algorithms and diagnostics. Private positions discarded before retention.
  DE/EN: SliceRead and iterative IgnoredAny scratch are bounded by input length,
  not recursion128. Extended numeric modes and disabled recursion limits are refused.
- Hyper1.12.0: opt-in host-owned protected read/split/trailer buffers; retain existing
  HTTP parser and framing, sanitized trailer errors, no payload Debug. Replace the old
  unsafe benchmark length reset with explicit initialized synthetic fixture reset.
- serde_json1.0.154: opt-in caller-locked bounded SliceRead scratch with a wipe-before-
  release callback. No parser/escape/algorithm replacement. Extended numeric modes are
  rejected by this entry point; the ordinary upstream API stays available for public data.
- Axum0.8.9 and hyper-util0.1.21: dependency-path bridges only, ensuring external consumers
  and the fuzz workspace also select these exact providers, not a root-only Cargo patch.

DE: Originalarchive gegen Ausgangs-Cargo.lock-Prüfsummen verifiziert. Original-Lizenztexte
MIT (Hyper/hyper-util/Axum), MIT OR Apache-2.0 (serde_json) bleiben unverändert erhalten.
Alle Originaldateien in upstream-sha256.json, jede konkrete Abweichung/Zusatzdatei in
patches-sha256.json. Protokoll-/Speicherprüfungen und native CI vor Abnahme erforderlich;
keine Root-only-Ausnahme, Scanner-Unterdrückung oder neue Privilegien.
EN: Preserve original licenses and per-file provenance; actual native validation remains
required. Package versions and parsing algorithms are unchanged. These are modified local
providers and remain subject to the separate publication-route issue71, not crates.io releases.
# Minimal Axum source subset / minimale Axum-Quellen

DE: Der Main-basierte Folgeimport zu PR299 enthält nur den HTTP-/JSON-Adapter;
`extract/ws.rs` und das unbenötigte ws-Feature wurden nicht aufgenommen. PQKeep
hatte und hat keinen WebSocket-Endpunkt. Die übrigen ausgewählten Originaldateien
bleiben gegen das gepinnte Upstream-Archiv gehasht, die Manifest-/Exportanpassungen
im Patchregister erfasst. Keine Scanner-/Sonar-Ausnahmen und kein Hashersatz im
WebSocket-Protokoll. Dieser Adapter bietet bewusst nicht alle optionalen Axum-Features.
EN: The protected adapter imports a documented source subset. WebSockets are not
part of PQKeep's existing HTTP/JSON contract; requesting the absent ws feature
fails at Cargo resolution. Retain licenses and exact provenance for included files.
The full original import remains preserved in PR299 and a verified protected bundle;
see docs/security/SOURCE_MINIMIZATION_PLAN.md. No history rewriting or hidden omission.

DE: Der synchrone geschützte serde_json-Eingang redigiert nun auch Fehler, bevor ein
Display-Wert in einen normalen Fehler-String formatiert werden könnte. Threadgebundener
RAII-Scope wird bei Erfolg/Fehler/Unwind wiederhergestellt; normale Parseraufrufe behalten
ihre bisherigen Fehlermeldungen. Kein beweglicher/async gespeicherter Schutz-Scope.
EN: Protected parsing prevents pre-sanitization error-message copies; formatter probes
and ordinary-error restoration tests exercise the actual provider error constructor.

## Private KEM operation storage / Private KEM-Operationsflächen

DE: EncapsulateWithWorkspace/DecapsulateWithWorkspace teilen ursprüngliche PKE-
Arithmetik mit geliehenen Zielen. Feste vollständige Workspaces müssen vor privater
Verarbeitung gesperrt sein; generierte Feldlisten koppeln Default und vollständiges
Zeroize/Drop. Private Inverse-NTT-/Skalarprodukt-/Packing-Zwischenwerte werden nicht
als Arrays zurückgegeben. Disjunkte Chiffratteilsichten verwenden geprüfte sichere
hybrid-array-APIs der unveränderten ausgewählten Version. Ungültige öffentliche
Vektorgeometrie führt vor Ausgabe-Schreibzugriffen zum Fehler, ohne neuen Panic-Fallback.
EN: Recomputed decapsulation ciphertext is confidential and stays in the locked
workspace. Only actual intended encapsulation ciphertext leaves by value. Root
selects the strict workspace traits, propagates failures and never falls back to
the ordinary provider APIs. Constant-time candidate selection and implicit rejection
are preserved. Three parameter sets, tampering, sentinel/stability/lock/cleanup
and independent KAT proofs remain required, including final native CI acceptance.

## Private DSA storage / Private DSA-Flächen

DE: Root sperrt SigningKey, Seed-/Expanded-Key-Payloads und vollständige Inline-
Workspaces vor privater Befüllung. Geliehene NTT-, Sampler-, Packing-, Hash-/Reader-
Einstiege verwenden bestehende Konstanten und Koeffizientenoperationen. Beide
Ablehnungsprüfungen und die vollständige ursprüngliche Noncesequenz bleiben erhalten;
erst akzeptierte Signaturen dürfen gewöhnliche öffentliche Allokationen verwenden.
EN: Secret-derived rejection candidates and hints stay in the prelocked workspace.
Public rho-derived matrix caches contain no private products. Root uses fresh OS
hedged randomness directly in locked storage; no deterministic or unprotected fallback.
Verification also protects confidential message/context hashes, mu and recomputed
challenges, using constant-time comparison. Explicit key wiping precedes payload
unlock/free. Ordinary provider APIs remain compatibility/reference paths and are
not used by the protected Root DSA operations. Native acceptance remains required.

## Private AES/GCM storage / Private AES/GCM-Flächen

DE: Die vier AES/GCM-Subsets enthalten alle Produktionsmodule und Original-Lizenzen.
Nur Dev-/Test-/Bench-Targets sowie drei reine POLYVAL-Inline-Test-Suffixe fehlen.
Neue geschützte Typen sind additiv: Root sperrt den vollständigen öffentlichen
Anfangszustand vor Key-Schedule, GHASH-Schlüssel und Operationen. Private Produkte,
Bit-Slicing-Scratch, Tagmaske, Keystream und AAD-Padding bleiben inline. Stream-AAD
liegt in SecretBytes. Öffentliche Zähler und fertige Tags dürfen das Objekt verlassen.
EN: The protected path uses the existing portable constant-time arithmetic, preserving
native batch widths and CTR32BE. Ordinary APIs retain hardware dispatch. Existing
upstream native unsafe code remains in the production subsets; the new protected
path introduces no unsafe code. This is not an unsafe-free dependency claim.

DE: protected-workspace von aes-gcm benötigt std für den Inline-Mutex. Das neue
Objekt erhält Send/Sync und Unwind-Eigenschaften; belegter/vergifteter Zustand wird
verweigert. Vergiftete Daten werden ausschließlich zum Löschen zugänglich. Die
gewöhnliche API bleibt ohne dieses Feature no_std-fähig. Byteweises Zeroize benötigt
keine implizite hybrid-array-Feature-Vereinheitlichung durch Root.
EN: Explicit wipe and Drop cover all private fields before host unlock/free.
Standalone consumers exercise both documented cpubits width overrides; this does
not replace native ABI tests. Public-data x86 measurements show roughly 3.0–3.4x
the hardware-accelerated registry provider's compute time, excluding owner locking.
Native acceptance and the remaining Argon2/R6 matrix are still required.

## Private Argon2 storage / Private Argon2-Flächen

DE: Beide Subsets enthalten alle Produktionsmodule und Original-Lizenzen; nur
Dev-/Test-/Bench-Targets und zwei reine Argon2-Inline-Test-Suffixe fehlen. Root
sperrt Blockspeicher, vollständigen Operationszustand und sämtliche Lane-Worker
vor privater Verarbeitung. AD wird direkt geliehen, nicht mehr privat in Params
kopiert. BLAKE2b Initial-/Final-/long-Hash, Erst-/Schlussblöcke und R/Ergebnis sind
feste Inline-Flächen. Private Byte-/Vektorkonvertierungen geben keine Arrays zurück.
EN: Shared original arithmetic uses borrowed scalar/vector destinations. Compression
message words, four working vectors and the gathered message vector are inline.
Little-endian word framing writes directly into the prelocked lazy buffer. Default
state/constructors contain public IV/zero values; ordinary APIs remain compatible.

DE: Der originale Segment-Scheduler und seine Bounds-/Alias-Prüfungen bleiben
byteidentisch. Exklusive Worker-Slice-Leihe und eigener Inline-Mutex je Lane
bewahren die bisherige Parallelität; keine globale Serialisierung oder kleinere
Parameter. Belegung/Gift werden verweigert, Giftzustand nur gelöscht. Fortschritt
und tatsächliche AVX2-Auswahl können ohne private Inhalte validiert werden.
EN: Two existing AVX2 unsafe sites accept borrowed R/output instead of returning
a private Block. The same feature detection and target-feature boundary remain;
no additional unsafe boundary. New protected modules and Root add no unsafe code.
Inherited allocator/segment unsafe remains for existing APIs. This is not a formal
soundness proof or an unsafe-free dependency claim. Native acceptance is required.

DE: Aktueller R6-Gesamtstand: [Provider-Abnahmematrix](../docs/security/PROVIDER_LIFETIME_VALIDATION.md).
Frühere OPEN-/Teilnachweise hier sind historische Zwischenstände.
EN: The current complete matrix supersedes earlier scoped provider status,
without asserting complete R7/R8 or whole-issue147 remediation.
