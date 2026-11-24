# R8 typed workspace owners / Typisierte Arbeitsbereich-Owner

DE: Basis Main308 5cbf7fd, Baum38162e80. Quellabgleich bestätigt: SecretBytes
schützt nun seinen inneren Byte-Descriptor, aber SecretBuffer<char/usize/bool>,
WordSpan, ListEntry und Windows-u16-Arbeitsbereiche haben weiterhin bewegliche
Vec-/Lock-Descriptoren mit privater Länge/Kapazität. Bereits gesperrte Nutzdaten
allein schließen diese Grenze nicht. Kein neuer Laufzeit-Leaknachweis behauptet.
EN: Scope is application-owned typed buffer descriptors, not every scalar,
iterator, compiler/register copy, tree/source/output path, provider or helper.

DE: Bestehenden SecretState und SecretBuffer wiederverwenden. Ein interner
SecretWorkspace hält den konkreten Buffer stabil in SecretState. Öffentlichen
leeren Buffer zuerst sperren; erst darin Kapazität fallibel reservieren, gesamte
Nutzdatenkapazität sperren und öffentliche Defaults bzw. vertrauliche Werte
schreiben. Keine private Reallokation oder ungesperrter Fallback. Byte-Owner-API
und Verhalten aus308 bleiben erhalten, gemeinsame Reserve-/Übernahmeprimitive
ohne zusätzliche ungesperrte temporäre Descriptoren verwenden.
EN: No blanket generic ZeroizeOnDrop marker. Review concrete primitive char,
usize, bool, u16 and application WordSpan/ListEntry destruction; implement only
their concrete SecretBuffer markers at the owning module. Existing buffer Drop
wipes elements/spare capacity while locked; SecretState destroys that buffer in
place and wipes its former allocation including padding before unlock/free.

DE: Feste Arbeitsbereiche verwenden erst nach Sperre initialisierte öffentliche
Defaults; variable WordSpan-/Listenarenen reservieren im vorbereiteten Owner und
wachsen ausschließlich innerhalb der gesperrten Kapazität. Caller-Vec-Übernahme
für ConfidentialEntries bleibt explizite Grenze ohne Payloadkopie. Quelle auch
bei frühem Ownerfehler vollständig löschen; übergroße öffentliche Listen weiter
mit list_limit ablehnen. Leere Default-Listen bleiben ohne private Geometrie;
nach prepare muss auch ihr tatsächlicher variabler Descriptor gesperrt sein.
EN: Preserve public signatures, iteration/equality/redacted Debug, budgets,
normalization/Unicode/dictionary behavior, output encoding and fail-closed errors.
Private output counters, source paths and tree topology remain separate findings.

DE: Dateien: neuer crypto/secret_workspace.rs, bestehende Bufferprimitive,
Security-Zeichen/Normalisierung/Entropie/Dictionary/Masken/Windows-Ausgabepuffer
sowie ConfidentialEntries; getrennte Tests und präzise SPEC DE/EN, Roadmap,
Changelog/Memory-Hardening-Doku. Keine neuen Abhängigkeiten, kein unsafe, keine
Krypto-/KDF-, CI-, Scanner-, Plattform-/Hostpolicy- oder GUI-Vertragsänderung.
EN: Tests inspect actual descriptor before population and after owner moves,
payload locks, empty/default values, capacity refusal and explicit wiping.
Exercise concrete primitive/application types, list transfer/rollback, existing
drop/unwind tests, and isolated Linux child lock denial before metadata and after
prepared metadata for payload allocation/adoption. No addresses/secrets in failed
assertions, no freed/uninitialized/padding reads, no inferred Windows OS mapping.

DE: Plan vor Code signieren. fmt, beide strengen Clippies/Features, vorhandene
Unicode-/Assessment-/Datei-/Ausgabe-/Byteowner-Verträge, Limits/Herkunft sowie native
Linux/Windows/ARM64 und alle acht Fuzz-Ziele prüfen. Vollständiges Bundle unabhängig
wiederherstellen und praktischen Rückweg zum exakten Main308-Baum prüfen.
EN: Main308 acceptance is independent and still running. Issue147/roadmap stay
In progress. R6 provider construction/scratch, R7 verified helpers/full process
policy and remaining R8 scalar/path/source/output/tree boundaries remain OPEN.
No release/deployment or deletion permission for this new branch is implied.
