# Parser state ownership / Parserzustands-Ownership (#147)

DE: Nach PR320 ist der Scratch-Sperrrecord geschützt, der persistente Parser
mit Scratch-Vec-Descriptor, SliceRead-Quelle/Index und Rekursionstiefe dagegen
noch nicht. Dieser Schritt schützt diesen konkreten Zustand vor privater Bindung.
EN: Protect the concrete persistent parser before binding private input. Existing
payload protection and the independently locked range record remain required.

## Umsetzung / Implementation

- DE: Einen ausschließlich öffentlich leeren konkreten SliceRead-Parser in
  SecretState sperren. Erst danach den eingebetteten Scratch-Vec reservieren,
  dessen volle Kapazität mit dem bestehenden ScratchLock schützen und zuletzt
  Quelle/Index direkt im gesperrten Parser binden. Keine private Konstruktion mit
  anschließendem Verschieben, kein frei zugänglicher mutabler Scratch-Vec.
  EN: Prelock public-empty parser metadata; reserve and protect scratch in place,
  then bind source in place. The root wrapper never exposes an unlocked parser.
- DE: Additive std-Provider-Schnittstellen für Vorbereitung und synchrones,
  einmaliges Deserialisieren. Aktive/wiederverwendete Zustände, ungeeignete
  Kapazität, Overflow, deaktivierte Rekursionsgrenze und erweiterte Zahlenmodi
  ablehnen. Inputlänge+128 bleibt konservativ: kopierter SliceRead-Scratch und
  der iterative IgnoredAny-Frame-Stack sind jeweils durch Eingabelänge begrenzt.
  EN: Preserve normal serde behavior and recursion128. Do not incorrectly bound
  iterative ignored containers by recursion128. No parser algorithm replacement.
- DE: Der bestehende synchrone private Fehlerscope verhindert zusätzlich die
  persistente Speicherung von Zeile/Spalte und spätere Positionsnachtragung;
  öffentliche Fehlerpositionen und Klassifikation bleiben unverändert.
  EN: Discard private positions before allocation, preserve ordinary diagnostics.
- DE: Konkreter lokaler Wrapper: einziger eigener privater Payload ist der durch
  den Provider-Destructor vollständig gewischte Scratch. SecretState zerstört
  diesen an Ort und Stelle und löscht danach die gesamte Parserallokation vor
  Unlock. Borrowed Input bleibt beim separat gesperrten Caller. Kein generischer
  ZeroizeOnDrop-Marker und keine neue unsafe-Grenze.
  EN: Review the concrete destruction contract; no marker as a substitute for
  actual wiping, no foreign/generic ownership guarantee.

## Dateien und Prüfungen / Files and validation

DE/EN: src/api/locked_json.rs, new locked_parser.rs and separate tests; vendor
serde_json de.rs/read.rs/error.rs plus new protected_slice.rs; exact vendor patch
hashes and README; DE/EN SPEC, memory inventory, roadmap, changelog.

DE: Tatsächliche Sperre des gesamten Parsers vor Allokation/Bindung und stabile
Adresse nach Bewegungen; echte private Besucher; vollständiger Wipe bei Erfolg,
Fehler und Unwind; begrenzte isolierte Metadaten-/Payload-Sperrverweigerung vor
Besucheraufruf. Öffentliche synthetische Differentialfälle einschließlich UTF-8,
Escapes, tiefem IgnoredAny, Rekursionslimit, abgeschnittenen und nachgestellten
Daten. Private Positionsfehler zuerst rot, dann grün; normale Diagnosen bleiben.
EN: Require fmt, strict clippy with/without API on Linux/Windows targets,
native Linux/Windows/ARM64 CI, all eight fuzz targets, security/provenance checks.
No reduced KDF/workers/lock budgets, skipped failure paths or scanner exclusions.

## Grenzen und Rückweg / Limits and rollback

DE: R6-Providerinternas, R7-Helper/GUI/Prozessschutz, übrige Pfad-/Baum-/Registry-
Owner sowie Scalar-/Compiler-/Register-/Stacktransit bleiben offen. Fehlerkategorie
und Rückgabeobjekte beliebiger externer Serde-Besucher sind keine neuen Secret-
Owner-Garantien. Keine Installation, Hostpolicy, Abhängigkeit oder Formatänderung.
EN: No full147 closure or release. Keep signed plan before code; full bundle,
independent restore and exact reverse patch before merge. Retain local work.
The specific new remote branch needs separate deletion approval before GitHub's
automatic deletion on the already authorized merge. No settings changes.
