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
| ml-kem 0.3.4 | RustCrypto/KEMs, Apache-2.0 OR MIT | Additive encapsulation into borrowed entropy/G-output storage; public ciphertext return only. Existing G/PKE/legacy APIs unchanged. |

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
uses FixedOutputReset, preserving the old API. Keccak/PKE internal scratch remains
open; a protected top-level hash state is not proof of protected permutation scratch.

DE: `SeedKeyInPlace` erzeugt nur öffentlichen Anfangszustand, besucht genau drei feste
private Speicherbereiche und befüllt deren bestehende Payloads aus geliehenem Seed.
Root muss Zustand und Payloads vorher sperren und vor Guard-/Boxfreigabe explizit
zeroisieren. `Zeroize` und Drop verwenden dieselbe bisherige Payload-Löschung.
EN: Public initial state plus fixed private-storage visitation enables host prelocks
before seed population. Explicit Zeroize and Drop share the original wiping body;
private boxes are never replaced during initialization. Root PKE keygen writes
expanded state through borrowed NTT output, sharing the original transform loops.
Sampling/hash/PKE intermediates remain OPEN; this is not copy-free private construction.

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
