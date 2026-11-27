# Confidential path nodes / Vertrauliche Pfadknoten

DE: Teilbehebung M2 des vor Code signierten und ausdrücklich freigegebenen
[gemeinsamen R7/R8-Plans](PROCESS_METADATA_COMPLETION_PLAN.md), Basis Mainb813bc6.
Kein vollständiger R7-/R8-Abschluss und kein Teilmerge. Stand: lokal entwickelt,
native CI/Windows/ARM64 und abschließender Gesamtvergleich stehen noch aus.
EN: Earlier protected path strings did not protect ordinary BTree node records.
This patch protects actual index node storage, not just their payload names.

## Ownership and indexing / Ownership und Index

DE: Vorher zwei Standard-BTreeSets: private Vergleichstexte gesperrt, Knoten mit
Owner-/Kindreferenzen ungeschützt. Jetzt ein intern balancierter AVL-Index mit
SecretState für Root/Belegung und SecretWorkspace für sämtliche Knoten. Nur
öffentliche Defaults vor der Sperre; Name/Dateiart/Links/Höhe danach setzen.
Kein frei zugänglicher Standard-BTree-Allocator, der die bisherigen Knoten vor
deren privater Befüllung sperren könnte. Kein neuer Kryptoalgorithmus/unsafe.
EN: Node indices give borrowed in-place rotations; no private node arrays returned
or moved as aggregate values. Balanced lookup retains logarithmic search depth;
no quadratic full scan for late file ancestors. No performance-parity claim.

DE: Wachstum von16 Plätzen, Verdopplung begrenzt durch bestehendes MAX_ENTRIES.
Neues vollständiges Array vor privater Befüllung sperren. Schlüssel ausschließlich
fallibel in geschützte Ziele duplizieren; Recordfelder im gesperrten Slot setzen.
Erst nach vollständigem Erfolg den alten Owner ersetzen. Fehler zerstören nur
die teilweise neue Fläche; alter Baum/Root/Belegung bleiben gültig. Knoten löschen
verschachtelte Owner, anschließend löscht der vorhandene SecretBuffer auch die
gesamte frühere Kapazität/Padding vor Unlock/Free.
EN: Existing Unicode folding, sigma aliases, case conflicts, path/depth limits,
later directory parents and file-prefix conflicts are unchanged. Public PathSet
signatures remain unchanged; tests inspect the new single index without weakening
their original conflict/state/owner assertions.

## Executed local evidence / Ausgeführte lokale Nachweise

- DE: Aktueller API-Stand:4 Elternprüfungen grün, ein ausdrücklich durch den
  Elternprozess ausgeführter ignorierter Kindeinstieg. Auf-/absteigende und
  permutierte257-Einträge-Folgen gegen unabhängigen BTreeMap-Referenzindex;
  jede Zwischenstufe mit AVL-Höhen-/Ordnungsprüfung, sämtliche Lookups und
  zusätzliche lower-bound/Präfix-Gegenproben.
- EN: Actual State/node first/last addresses and nested key owners remain locked.
  Explicit node field wipe observed while node allocation remains protected.
- DE: Isoliertes eigenes Kind: echter Unwind, exakte Sperrfreigabe, vorab gesperrte
  Quellen und danach wirkliches RLIMIT_MEMLOCK.current=0. Tatsächlicher Indexaufruf
  muss MemoryLock liefern, nicht skippen. Vorhandene Einträge/Belegung unverändert;
  Sperren nach Drop exakt zurück auf Baseline, Elternlimit unverändert.
- EN: All14 existing path/component groups pass. Earlier no-API checkpoint passes
  all54 file-module tests; later denial addition still requires final no-API/native
  acceptance. Do not count an earlier compiled checkpoint as current source proof.
- DE: Strenges Linux-All-targets-Clippy mit/ohne API erfolgreich; nach Ergänzung
  des echten Denial-/Unwind-Falls API-Clippy erneut erfolgreich. Root-/Plattform-
  Formatierung und bisheriger Limit-/Diffcheck grün; Gesamtchecks vor Commit erneut.

DE: Geschützte Vollprotokolle/Quellhashes unter
`analysis/issue-147-r7-r8-20261127T182246Z`: joint-local-v1/v2/v3,
implementation-plan-approval.json. Frühere Compile-/Test-Lintfehler erhalten:
alte interne Zwei-Baum-Testzugriffe und direkter Timeout-panic wurden korrigiert,
keine Suppression einer Produktionsregel. Der versehentliche All-workspace-
Formatter-Diff ist gesichert; alle21 betroffenen Vendor-Dateien bytegenau auf
den unveränderten Basisstand zurückgesetzt.
EN: No provider/algorithm/format/KDF/worker/gate changes. Registry, source/output
path ownership, report/progress/hidden-sender and process/helper rows remain open.
