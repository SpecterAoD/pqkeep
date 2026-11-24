# R8 byte-owner metadata / Byte-Owner-Metadaten

DE: Basis Main307 b973967, Baum55af2079. Isolierte Linux-Probe auf Main306
bestätigt ungesperrte untersuchte Seiten eines lebenden zurückgegebenen SecretBytes-
Datensatzes bei positiv gesperrten Nutzdaten. Der bisher inline gespeicherte Vec-
Descriptor enthält variable Längen/Kapazitäten. Keine Beobachtung innerhalb des
Konstruktors, keine Windows- oder pauschale Schlüsselinhalt-Leckaussage.
EN: Protect managed byte-owner metadata with the existing stable SecretState,
without changing public fallible APIs or claiming all compiler/register copies.

DE: SecretBytes.inner wird SecretState<SecretBuffer<u8>>. Öffentlichen leeren
Bytepuffer im festen Owner sperren, bevor private Geometrie eingetragen wird.
Nur für den konkreten bestehenden Bytepuffer ZeroizeOnDrop markieren: dessen
u8-Drop löscht bereits Nutzdaten/volle Kapazität; keinen pauschalen Marker für
beliebige T oder fremde Provider erfinden. SecretState zerstört den Puffer an Ort
und Stelle und löscht danach seinen gesamten früheren Descriptorbereich vor Unlock.
EN: Reuse reviewed destruction, shared page accounting and allocation wiping.
No new allocator, unsafe code, dependency, crypto, host or process-policy change.

DE: Private Bytepuffer-Helfer initialisieren nur leere unallokierte Ziele direkt
im gesperrten Descriptor: fallibel reservieren, volle Kapazität sperren, erst dann
öffentliche Nullwerte initialisieren. Bei Fehler bereinigen und leeres gültiges
Ziel wiederherstellen; kein privates Wachstum/Reallokation. from_slice kopiert erst
danach. new(Vec) bleibt bewusste Caller-Ownership-Grenze ohne Payloadkopie; auch
bei vorzeitigem Owner-Sperrfehler Caller-Puffer vollständig löschen. Übernahme
sperrt Caller-Payload vor Commit und wahrt Wipe→Unlock→Free bei Fehlern.
EN: Preserve len/expose/mutable borrow/truncate/explicit Zeroize and empty text
behavior. Empty byte values also require the metadata guard. No unlocked fallback.
Fixed public outer guard geometry differs from the old private inline descriptor.

DE: Dateien: crypto/secret.rs und secret_buffer.rs, getrennte Byteowner-/Fehlertests;
gemeinsamen Registry-/Linux-VmFlags-Testprüfer auf crate-Testebene wiederverwenden,
ohne Duplikate/Gateausnahmen. Alte Datei als Test-Reexport erhalten. Namensowner-
Tests zusätzlich auf tatsächlichen inneren Byte-Descriptor richten. SPEC DE/EN,
Roadmap, Changelog und Memory-Hardening-Doku mit präzisem Teilumfang aktualisieren.
EN: Tests: prefill descriptor locking, stable address through moves, payload locks,
no-copy caller adoption, truncate/zeroize/empty values, overflow/no-growth refusal,
isolated child denial before metadata allocation and after prepared descriptor
for payload allocation/adoption. Reuse shared wipe/unwind tests; do not read freed
or raw padding memory. Preserve all existing API/CLI/vector contracts.

DE: Beide Features, fmt, beide strengen Clippies, Limits/Herkunft, native Linux/
Windows/ARM64, acht Fuzz-Ziele; vollständiges Bundle, unabhängige Wiederherstellung
und praktischer Rückweg vor Abnahme. Plan vor Code signieren. Main307 separat prüfen.
EN: Issue147/roadmap stay In progress. Other variable typed-workspace metadata,
components/source/output/tree data, provider construction/scratch and protected
password helpers/full process policy remain OPEN. Caller source/OS bookkeeping
boundaries remain explicit; no complete R6/R7/R8 closure or installation/deployment.
