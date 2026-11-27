# KEM operation workspaces / KEM-Operationsarbeitsflächen

DE: Folgeschritt des vollständig beauftragten R6-Abschlusses, vor Code signiert.
KEM-Keygen-Flächen sind implementiert; ihre native Abnahme läuft. Nun tatsächliche
Kapselungs-/Entkapselungs-PKE-Pfade ohne private Rückgabearrays umstellen.
EN: Preserve all three parameter sets, original arithmetic/constant-time selection,
implicit rejection and existing public PQKeep APIs. No alternate crypto provider.

DE: Insbesondere ist das bei Entkapselung neu berechnete Vergleichs-Chiffrat
vertraulich: Es ist keine veröffentlichte Kapselungsausgabe. Kandidaten-Nachricht,
G-/J-Ausgaben, r, Vergleichs-Chiffrat, Sampling-/NTT-/Produkt-/Inverse-NTT-/
Kompressionsflächen und Hash/Reader/Scratch vor privater Befüllung vollständig
sperren. Empfangene Chiffrate, öffentlicher Schlüssel und aus rho abgeleitete
Matrizen sind getrennte öffentliche Eingaben.
EN: Treat recomputed candidate ciphertext as private. Never justify its ordinary
array return merely because ciphertext transmitted by encapsulation is public.

DE: Dateien: vorhandener ML-KEM-Provider, gemeinsamer Gitter-Codec für geliehene
Vektorausgabe, eigene Workspace-/Operationsmodule, Root-KEM-Adapter und getrennte
Tests. Öffentliche leere Inline-Workspaces in SecretState; keine inneren Heaps.
Inverse NTT und Skalarprodukt teilen die vorhandenen Schleifen mit geliehenen
Zielen. Ciphertext-Teilsichten sicher aus disjunkten mutablen Bereichen gewinnen.
EN: Fixed typed prelocked storage, shared original transforms/products/packing,
safe disjoint output borrows. Reject invalid geometry before output writes; do not
add unwrap/expect, private fallback, unsafe, changed constants or worker reductions.

DE: Root nutzt ausschließlich die neuen geschützten Workspace-Einstiege. Vor
privater Verarbeitung alle nötigen Owner/Sperren vorbereiten; Fehler propagieren.
Legacy-Upstream-APIs für unabhängige Gegenproben erhalten, nicht als Root-Fallback.
EN: All active payloads remain locked until zeroization and release, including
partial initialization, denied resources and unwind. Debug output stays redacted.

DE: Tests: gültige/manipulierte/zu kurze/zu lange Chiffrate aller Parametersätze,
unabhängige KATs/Wycheproof, Gegenvergleich zu Legacy-Ausgaben, tatsächliche
Owner-/Workspace-Sperren, stabile Ziele, Konstantzeit-Quellabgleich und Cleanup.
Beide Featurekonfigurationen/strenge Clippies/fmt/Herkunft/Limits sowie native
Linux-/Windows-/ARM64-, Security- und Fuzz-Abnahme bleiben notwendig.
EN: No R6 closure from a local partial fix. Retain DSA/AES/Argon2 and remaining
matrix rows as OPEN until proven; exact complete bundle/reverse rollback before
merge, with no implied branch deletion or host-policy permission.
