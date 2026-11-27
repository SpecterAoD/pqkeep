# Argon2 lifetime checkpoint / Argon2-Lebensdauer-Zwischenstand

DE: Umsetzung nach vor Code signiertem Plan2b44f3e im R6-Draft334. Parameter,
Argon2id1.3, Versionen0.6.0/0.11.0, Dateiformate und konfigurierte Lanes bleiben gleich.
EN: This checkpoint does not close R6 before final native/source/matrix acceptance.

| Private surface / Fläche | Protected path / Geschützter Pfad |
|---|---|
| Initial hash, first-block bytes, final block/XOR and final bytes | Fixed OperationWorkspace, prelocked by Root |
| BLAKE2b state, lazy pending block, full output, message words, working/gathered vectors | Inline protected core; borrowed scalar/vector operations and finalization |
| Long-hash chaining output | Fixed64byte inline buffer; borrowed next-hash input/output |
| Length/word framing | Direct scalar little-endian writes into locked pending storage |
| Every lane's address/input/zero/R/result blocks | One fixed inline WorkerWorkspace per configured lane |
| Main Argon2 block matrix | Existing prelocked SecretWorkspace<Block> |
| Associated data | Borrowed WorkspaceInputs; no private ParamsBuilder/AssociatedData copy |
| Errors/unwind/cleanup | Explicit zeroization/destruction before host unlock/free |

DE: Root wählt ausschließlich den neuen Workspace-Einstieg. Alle drei Speicher-
bereiche sind vor privatem Eingang gesperrt; keine kleinere Ableitung bei Fehlern.
Der strikte Einstieg verlangt leere Params-AD und leiht AD separat. Dieselbe
32Byte-Grenze bleibt erhalten. Gelöschte/finalisierte BLAKE2-Zustände verweigern
weitere Updates/Finalisierung. Ungültige Ausgabegeometrie schreibt keine Ausgabe.
EN: Public IV/default constructors precede locks; private data is populated only
afterward. Ordinary APIs remain compatibility/reference paths, not a Root fallback.
DE: Der neue Worker-Einstieg benötigt std für den Inline-Mutex; gewöhnliche APIs
ohne protected-workspace behalten ihren bisherigen no_std-Vertrag.
EN: Root already requires std; no existing platform contract is withdrawn.

DE: Originale Block-Permutationsmakros und Row-/Column-Schleifen erhalten.
BLAKE2-Konstanten, Rundensequenz, skalare Wrapping-/XOR-/Rotationsformeln und
Little-Endian-Framing erhalten; keine neue Kryptoimplementierung. Private8Byte-
Load-Konvertierung und zurückgegebene private Vektoren entfallen. Getter/Setter
arbeiten auf einzelnen nativen Wörtern beziehungsweise geliehenen festen Zielen.
EN: Original lazy final-block semantics and BLAKE2b-long chaining/truncation remain.
Known private arrays/vectors are workspace fields, not renamed compiler limits.

DE: Der ursprüngliche parallele Segment-Scheduler inklusive Bounds-/Alias-Prüfungen
ist byteidentisch. Worker-Slice wird exklusiv geliehen; pro Lane ein Inline-Mutex,
keine globale Serialisierung. Originale Slice-Barrieren und sämtliche Lanes bleiben
erhalten. Fehler werden nach den Barrieren vor Finalausgabe weitergegeben. Belegung/
Gift verweigert; Giftzustand ausschließlich für Wipe zugänglich.
EN: All lanes report exactly4*t completed segments in independent-vector tests.
Progress/backend diagnostics expose public metadata only, never inputs or addresses.
DE/EN: Ordinary and protected paths share reference indexing and initial-hash framing;
length conversions are checked before private absorb. No new lint suppression.

DE: Zwei bestehende AVX2-Unsafe-Stellen erhalten geliehene R-/Ausgabeparameter statt
privater Block-Rückgabe. Gleiche Feature-Erkennung und target_feature-Grenze, keine
zusätzliche Unsafe-Grenze. Rust-Leihen sichern disjunkte mutierbare Arbeitsflächen,
Block-Ausrichtung64 bleibt bestehen. Neue geschützte Module und Root ohne Unsafe.
EN: Inherited segment/allocator unsafe remains; this is no unsafe-free dependency
or formal soundness claim. Native logs must show actual AVX2/fallback selection
alongside the independent vectors, including native Windows/Linux/ARM64 acceptance.

DE: Unabhängige Nachweise: RFC9106/5.3 mit Secret/AD und Negativkontrollen;
76 Vektoren der vorhandenen System-C-Referenz, deren ABI ebenfalls den RFC-Vektor
reproduziert;512 hashlib-BLAKE2b-Fälle für alle Digestgrößen und Lazy-Blockgrenzen,
sieben Wortframing-Grenzen. C-Vektoren decken1/2/4/8/16Lanes,1/2/3Pässe, minimale/
gerundete Speichergeometrie, wiederholte Adressblöcke und Ausgaben bis1024Byte ab.
EN: Ordinary API compatibility separately covers all76 C cases,512 BLAKE2b and
eight BLAKE2s cases, both without and with unified protected features. Existing
64MiB C-reference KATs and v2 secret/domain/wrapping vectors remain required.

DE: Tatsächliche Owner und alle Worker sind stabil/gesperrt. Ungültige Geometrie,
kurzer Salt und überlange AD schreiben keine Ausgabe. Isolierte begrenzte Kinder
prüfen Wipe unter Sperre bei Fehler/Unwind und Sperrverweigerung ohne Fallback;
nur das eigene Linux-Kind senkt sein Budget auf null. Eltern-/Hostrechte unverändert.
EN: Scalar/register/compiler spills and OS/crash boundaries remain explicit limits;
R7/R8 are separate. No installation, privilege, CI protection or worker-count change.

DE/EN: Evidence in analysis/issue-147-provider-in-place-20261126T171500Z:
argon-production-import-provenance.json, argon-lock-and-fuzz-resolution-proof.json,
argon-source-invariants-v2.json, argon-compat-results-v3.json, argon-local-v5.json/logs,
generate_argon_c_vectors.py and the independently generated KAT fixtures. Final
source, performance, native/security/fuzz and complete R6 matrix/rollback acceptance
remain required. Private Base64 token remainder storage remains OPEN; no partial merge.

DE: Final lokal11/11 Kommandos erfolgreich; je9 KDF-/Hash-Elterntests mit/ohne API,
zwei ausdrücklich von Eltern ausgeführte ignorierte Kind-Einstiege. Beide Linux-/
Windows-Cross-Clippies, Herkunft/Limits/staged-Diff und64MiB-/v2-KATs erfolgreich.
Alle geprüften Dateien blieben während dieses Laufs unverändert. Direkte zusätzliche
Provider-Clippies prüfen die tatsächlichen Produktionsquellen als isolierte Workspace-
Mitglieder bei denselben Root-Features; beide erfolgreich. Keine realen Manifest-/
CI-Lintregeln geändert. Unverändert übernommener, von Clippy1.99 entfernter Lintname
from_iter_instead_of_collect erzeugt eine bekannte Manifestwarnung.
EN: Validation-only manifests omit the unavailable optional kdf dependency, which
is disabled in Root and in this lint configuration; actual production sources and
lint settings remain unchanged. Evidence: provider-clippy-harness-proof.json,
provider-clippy-v4-results.json/logs. No active production feature is skipped.

DE: Frischer externer Consumer bestätigt20 eindeutige Pfadprovider, geschützte
Features/Zeroize und unveränderte parallele Argon2-Auswahl. Root-/Fuzz-Lockfiles
entfernen nur Registry-Herkunft derselben zwei Versionen. Offline cargo-deny
erfolgreich mit Cache und bestehender syn2/3-Warnung; Online-CI-Audit bleibt Pflicht.
EN: Public synthetic x86 computation benchmark, original registry versions,
five interleaved trials after warmup: protected/reference0.951 at64MiB/p1,
0.928 at64MiB/p4 and0.961 at256MiB/p4, alwayst=3. Both arenas and outputs locked
before timing; allocation/lock/drop excluded. These are measurements with normal
timing variation, not a general speedup or ARM/end-to-end claim. Evidence:
argon-public-benchmark-v2.json/log; actual local AVX2 dispatch is false.

DE/EN: Native Linux/Windows/ARM64 with actual AVX2/fallback flags, MSRV,
online security/history/fuzz acceptance and final complete R6 matrix/rollback
remain pending for the signed resulting head. AES2b44f3e is already separately
accepted; this does not accept later Argon2 or Base64 code.

DE: Signierter Argon2-Checkpoint e5868d62e7d5efc85ae4463c029605a907b3d0c4
besteht alle23 Checks, einschließlich MSRV, Online-Audit, vollständigem Historien-
Scan und acht Fuzz-Zielen. Vier vollständige native Logs gesichert/gehasht:
Ubuntu22/ARM je903Tests, Ubuntu-latest1732, Windows1568 über jeweilige Feature-/
Plattformkonfigurationen, null Fehler. KDF-/Hash-Eltern und tatsächliche Laufzeit-
Backendflag nachgewiesen: Linux/Windows AVX2=true; ARM64=false (portabel).
EN: Evidence argone586-checks.json/native-summary.json and four complete logs.
This accepts this exact Argon checkpoint, not subsequent Main352/Base64 changes.
