# Locked NFKC workspace / Gesperrter NFKC-Arbeitsbereich (#147 R6)

DE: Quellabgleich unicode-normalization0.1.26: Decompositions/Recompositions benutzen
TinyVec, dessen Heap-Spill private Zeichen enthält. Decompositions::sort_pending nutzt
zusätzlich den allokierenden stabilen Standardsort. Die spätere gesperrte UTF-8-Ausgabe
schützt diese vorangehenden Arbeitsbereiche nicht. Kein vollständiger R6-Abschluss.
EN: Existing input limits and NFKC bytes are security contracts: changing normalization
would change derived keys. Preserve the pinned provider and its Unicode18.0.0 tables.

DE: Konkreter Adapter vor Code: vorhandene öffentliche char::decompose_compatible,
canonical_combining_class und compose verwenden, keine neuen Tabellen/Abhängigkeiten.
Zerlegte Zeichen, Sortier-Scratch und256 Klassenzähler vor privater Befüllung über den
bestehenden SecretBuffer sperren. Stabile Klassensortierung je Startersegment als
begrenzter Counting-Sort ohne allokierende Standardsort-Helfer; kanonisch in-place
rekombinieren. UTF-8-Ziel exakt bestimmen und vor Schreiben sperren. Alle Bereiche
vor Unlock vollständig löschen; keine wachsenden privaten Vecs/TinyVecs/Strings.
EN: Reuse provider decomposition/composition primitives and UAX15 rules; protect owned
multi-character workspaces. Scalar arguments, compiler/register and OS boundaries are
not claimed eliminated. Bounds and failure behavior remain explicit and unchanged.

DE: Dateien: neue security/normalize.rs und separate normalize_tests.rs, kleiner
Passphrase::new-Adapter, gezielter Lock-Denial-Test und DE/EN SPEC/Changelog. Keine
Krypto-, Format-, Host-/System- oder GUI-Änderung. Eigener Folgebranch abhängig von300.
EN: Require differential tests against the pinned original normalizer for every valid
Unicode scalar in bounded batches, deterministic mixed/combining sequences, Hangul,
compatibility expansions, equal-class stability and long combining runs; input limits,
actual workspace locks and error cleanup. Retain existing passphrase/KDF/KAT/native
Linux/Windows/ARM64/security checks. No byte-compatibility claim from examples alone.

Sources / Quellen:
- [Unicode UAX15](https://www.unicode.org/reports/tr15/)
- [Pinned character primitives](https://docs.rs/unicode-normalization/0.1.26/unicode_normalization/char/index.html)
- Local pinned provider source: decompose.rs, recompose.rs, normalize.rs, tables.rs.

DE/EN: Rollback: reviewed code revert, no migration or persisted data change. Full R6
still needs provider constructor/expanded-state and algorithm workspace verification.
