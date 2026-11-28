# Confidential name folding / Vertrauliche Namensfaltung

DE: R7/R8-Teil von Draft355. Mehrfachauswahl verwendet für Top-Level-Namen
denselben bereits geschützten PathSet wie der Archivleser. Die gewöhnliche
BTreeSet mit privaten to_lowercase-Strings entfällt. Sperrfehler werden als
MemoryLock weitergegeben; kein gewöhnlicher Ersatzindex. Namenskonflikte
behalten das bisherige Feld duplicate.
EN: Source records and archive bytes retain their original Unicode spelling.
Only conflict keys are folded. The existing archive-reader rule conservatively
merges both sigma aliases, without adding Unicode normalization or new folding.

DE: Bisher konnte die Auswahl beispielsweise ΟΣ und οσ akzeptieren, obwohl der
Archivleser diese Kombination zurückweist: str::to_lowercase verwendet beim
ersten Namen kontextuelles finales Sigma. Die gemeinsame Konfliktregel weist
solche nicht rundlauffähigen Kombinationen jetzt bereits beim Schreiben ab.
EN: Ordinary distinct names keep their ordering and bytes. This is an intentional
stricter rejection of combinations already incompatible with the archive reader,
not a wire-format change or a new case-insensitive filesystem assumption.

## Runtime storage / Laufzeitspeicher

DE: char::to_lowercase besitzt ein kleines Expansionsarray. Statt dieses mit
privaten Namen zu befüllen, erzeugt build.rs eine öffentliche Tabelle durch
vollständige Enumeration aller Unicode-Skalare. Gleiche Rust-Standardbibliothek
und bestehende Sigma-Regel liefern die Referenz. Generierte numerische Schlüssel
und UTF8-Bytes vermeiden versehentliche Quelltextnormalisierung.
EN: Runtime lookup returns only immutable public table slices. Mapped bytes are
copied directly into the existing prelocked key; identity scalars encode directly
there. No private expansion array, String, lowercase collection or extra crate.
Necessary scalar/register transit is not a whole-stack-wiping claim.

DE: build.rs ist ausdrücklich im Cargo-Paket enthalten. Generierte Daten liegen
in OUT_DIR; die Erzeugung ist deterministisch für dieselbe Rust-Unicode-Version.
Compiler-/Unicode-Updates ändern die Referenz wie zuvor die Standardbibliothek.
Keine Buildzeit-Eingabe enthält Laufzeitnamen oder andere Geheimnisse.
EN: No new unsafe block, dependency version or sandbox/host-policy change.

## Acceptance and remaining scope / Abnahme und offene Flächen

DE: Exhaustiver Test vergleicht jeden Unicode-Skalar mit der bisherigen
char-Faltung einschließlich Sigma-Zusammenführung; Größen, tatsächliche Bytes,
unveränderter Zielrest und sortierte Tabellenschlüssel werden geprüft. Echte
Mehrfachauswahl prüft Sigma-/ASCII-/Expansionskonflikte und unveränderte
unterschiedliche Namen. Bestehende Pfadindex-Sperr-/Verweigerungsfälle bleiben.
DE: Lokaler Checkpoint unicode-names-v1:879 unveränderte Rust-/Manifest-Hashes,
13 erfolgreiche Befehle, vier strenge Linux-/Windows-GNU-Lints, je88 Datei-
gruppen mit/ohne API und57 Integrationen. Cargo-Paketliste enthält build.rs.
EN: Native acceptance of this component is pending. Native traversal, skip/output/report records and verified
process/helper/host contracts remain open; no complete M1/M2 or R7/R8 claim.
