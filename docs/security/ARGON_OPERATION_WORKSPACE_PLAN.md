# Argon2 complete operation storage / Vollständige Argon2-Operationsflächen

DE: Nächster Teil des ausdrücklich beauftragten vollständigen R6-Abschlusses.
Vor Argon2-/BLAKE2-Produktionsänderungen signieren. Basis: Draft334 mit KEM/DSA/
SHA3-Workspaces und gesondert geprüfter AES/GCM-Umsetzung, Main339/341 erhalten.
EN: Existing locked Argon2 memory blocks alone do not protect provider-private
initial/final hashes, temporary blocks or worker scratch. Close these separately.

DE: Exakt ausgewählte Quellen argon2 0.6.0 und blake2 0.11.0 gegen ursprüngliche
Cargo.lock-Archivchecksummen prüfen. Vollständige Produktionsmodule/Lizenzen und
Herkunfts-/Patchregister behalten. Versionierte Pfade müssen auch Fuzz und externe
Consumer erreichen. Keine Paketversions-, Algorithmus-, Parameter- oder Formatänderung.
EN: Keep Argon2id1.3, current m/t/p bounds, secrets/associated-data framing,
BLAKE2b output lengths, full configured lane count and Rayon parallel execution.

DE: Additive geliehene Provider-API mit vollständigem festen Operationszustand:
Initialhash, Erstblock-Bytes, Schlussblock/XOR, Schlussblock-Bytes, BLAKE2b-long-
Zwischenausgaben sowie Hash-/Buffer-/Kompressionsscratch. Öffentlicher Anfangszustand
vor privatem Eingang stabil sperren. Keine privaten Digest-/Block-Rückgabewerte
oder Hash-Clone-/Default-Zustände erst nach privater Befüllung übernehmen.
EN: Reuse the original BLAKE2 round ordering/constants and Argon2 permutations.
Add borrowed compression/output paths to the existing kernels; preserve ordinary
compatibility APIs. Audit structured vector operations and byte conversions too;
do not relabel known private arrays as unavoidable compiler/register spills.

DE: Pro konfigurierter Lane eine eigene vorab gesperrte feste Arbeitsfläche für
Adress-/Input-/Nullblock, Kompressions-R/Z und Ergebnis. Die bisherige Parallel-
Segmentverarbeitung mit disjunkten mutablen Worker-Leihen verbinden. Gleiche
Slice-Barrieren und Lane-Geometrie, kein globaler Mutex und keine Serialisierung.
EN: Preserve existing bounds/alias checks of SegmentView. Reuse the existing
audited native boundaries rather than introducing additional unsafe boundaries.
Where signatures must accept borrowed scratch, review the unchanged safety
conditions explicitly. Preserve existing AVX2 selection and target-feature checks.

DE: Bevorzugt den unveränderten vorhandenen Segment-Scheduler verwenden. Eine
eigene Inline-Mutex-Leihe je Lane kann deren vorab gesperrten Worker exklusiv
zugänglich machen, ohne die Lanes untereinander zu sperren. Höchstens ein Aufruf
je Lane/Slice ist durch den vorhandenen Scheduler gewährleistet; try_lock statt
Warten, Belegung/Gift als Fehler. Kein privater Worker wird in einen Guard kopiert.
EN: Per-lane borrowing preserves parallelism and avoids additional SegmentView
unsafe construction. Propagate any worker access error after the slice barrier;
do not report success or derive output from a partially processed memory matrix.

DE: Root kdf.rs sperrt vollständigen Operationszustand und alle Worker vor Übergabe
von Passwort/Secret/AD. Auch ParamsBuilder/AssociatedData-Kopien und sonstige
tatsächliche vertrauliche Root-BLAKE2-Aufrufe verfolgen. Öffentliche Konfiguration
von privaten Daten trennen, vorhandene SecretState/SecretWorkspace nutzen.
EN: Lock failures propagate before private work, without fallback or lower costs.
Explicit Zeroize/Drop and host allocation wiping precede unlock/free on success,
partial initialization, errors and unwind. Root forbid(unsafe_code) remains intact.

DE: Dateien: Root kdf.rs und eng notwendige eigene Adapter-/Tests; zwei versionierte
Provider einschließlich Manifeste/Lockfiles/Herkunft; Sicherheitsdokumentation.
Keine GUI-/Prozess-/Host-/CI-Schutzänderung. R7/R8 bleiben gesondert offen.
EN: No installation, privileges, global allocator or stack-switching prototype.

DE: Abnahme: RFC9106 mit Secret/AD, bestehende unabhängige C-/Python-KATs und v2-
Container; Gegenproben zur unveränderten Provider-API mit mehreren Lane-/Pass-/
Speichergeometrien und langen/kurzen Hashausgaben. Tatsächliche Worker-Sperren,
stabile Ziele, vollständige parallele Lane-Abdeckung, Wipe unter Sperre sowie
Ressourcenverweigerung/Fehler/Unwind prüfen. Leistungsabweichungen messen/benennen.
EN: Require both feature configurations and strict Clippies, provenance/limits,
native Linux/Windows/ARM64, MSRV, audit/security/full-history scan and all eight fuzz
targets. Width/cross checks do not replace native execution. Complete remaining
Unicode/Base64/private-call matrix and independent exact restore/rollback before
final R6 merge. No partial merge or premature R6/issue147 closure.
