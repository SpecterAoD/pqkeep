# Protected lock registry / Geschützte Sperrbuchhaltung

DE: M6-Baustein des ausdrücklich freigegebenen gemeinsamen R7/R8-Plans in
Draft355. Lokale Implementierung; vollständige native Abnahme dieses Bausteins
und übrige Planzeilen bleiben erforderlich. Kein R7/R8-Gesamtabschluss.
EN: Shared bookkeeping component, not a claim of full process/metadata protection.

## Ownership and lifetime / Eigentum und Lebensdauer

DE: Die gewöhnlichen BTreeMap-Knoten mit Seitenadressen, Referenzzählern und
Sperr-Guards entfallen. Ein seitendisjunkter statischer Kontrollbereich enthält
Mutex, Hash-Wurzeln und Arenadescriptoren. Der Kontrollbereich wird direkt mit
region gesperrt, bevor private Records befüllt werden; keine rekursive Nutzung
von SecretState/SecretBytes zum Bootstrap des eigenen Registers.
EN: Target alignment is64KiB on ELF and8KiB on Windows/COFF. Actual page size must
divide that alignment; unsupported geometry
fails closed. Control and arena allocations cannot share OS pages with separately
managed data allocations. Statistics alone do not allocate or bootstrap locks.

DE: Fallibles Arenawachstum: neue Nodes ausschließlich öffentlich leer anlegen,
gesamte neue Allocation sperren, dann skalare Felder zwischen geliehenen Nodes
übertragen und Guard-Eigentum feldweise tauschen. Keine private Guard-Gesamtkopie
in gewöhnliche Container. Alte Felder und gesamtes Allocation-Padding vor Unlock
löschen. Kein fixer Gesamtseiten-Cap; arithmetische/allokative/native Fehler
verweigern weitere Aufnahme ohne Verlust bestehender Datensperren.
EN: Overlap reference counts and the successful contiguous prefix retain their
previous semantics. Removed page records are wiped before native data unlock.
Free nodes may be reused while the arena remains locked. After the final owner,
wipe/free the entire arena and release the control lock; no permanent bootstrap
allocation remains locked. Tests require the exact kernel VmLck baseline again.

DE: Ein vergifteter Mutex erlaubt nur Bereinigung bestehenden Eigentums, keine
neuen Secret-Sperren. Ein beschädigter Registerzustand wird nicht stillschweigend
als gesund übernommen. Noch lebende Guards werden bei Invariantenfehlern nicht
pauschal freigegeben. Native Release-Fehler sperren weitere Aufnahme und werden
als fehlgeschlagene Sperrverwaltung gezählt.
EN: Existing `LockStats.locked_pages` continues to count pages owned by secret
ranges, preserving API semantics. Locked bookkeeping is additional memory, included
in internal native capacity planning. Arena capacity may remain until the last
owner; data records are cleared on each release. Budget failure has no ordinary
memory fallback and never raises host limits or privileges.

## Safe code and narrow FFI / Sicherer Code und enge FFI

DE: Root bleibt forbid(unsafe_code). region::LockGuard hält numerische OS-Adressen
statt Rust-Raw-Pointern; beide bisherigen unsafe Send/Sync-Implementierungen
entfallen. Die Adresse wird niemals in Rust dereferenziert. Öffentlich leere
Guards lassen sich direkt in geschütztem Speicher befüllen, eigenes Eigentum
fallibel freigeben und feldweise tauschen. Release löscht die tatsächlichen
gespeicherten Wörter volatil vor dem nativen Unlock. Es entsteht keine sichere
API zum beliebigen Unlock fremder Spannen; das bestehende unsafe unlock bleibt
eine getrennte unbenutzte Fremd-Caller-Grenze.
EN: Reuse the already locked zeroize1.9.2 dependency, MSRV1.85, Apache-2.0/MIT.
No package version/source upgrade or installation. Update exact region patch
inventory only, without modifying upstream provenance or validation rules.

DE: Ein einzelner neuer notwendiger FFI-Block ist ausschließlich Teil der nativen
Windows-Testfixture, nicht des normalen Produktionsfeatures. K32QueryWorkingSetEx
liest Seiteneigenschaften ausschließlich des eigenen Prozesses. Der Caller legt
den vollständigen öffentlich leeren Query-Record in SecretState ab, bevor eine
Adresse eingeht. repr(C), zwei initialisierte ABI-Wörter, statisch gleiche Größe/
Ausrichtung wie der SDK-Typ, exklusiv lebende Ausgabe über genau dessen Größe;
keine Pointeraufbewahrung, kein Rust-Dereferenzieren, kein Lesen von Seiteninhalten.
EN: Both Valid and Locked must be set; the locked bit has no meaning if Valid is
clear. The test fixture checks actually locked and unlocked owned pages,
including guard transfers, and queries each registry/control page. No policy,
token, account, host, Registry or process rights mutation by this observer.

Sources / Quellen:
- [QueryWorkingSetEx](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-queryworkingsetex)
- [Valid/Locked bit layout](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-psapi_working_set_ex_block)

## Required evidence / Erforderliche Belege

DE: Bestehende Überlappungs-, Sättigungs-, Prefix-, Konkurrenz-, Unwind- und
Double-Zeroize-Fälle erhalten. Neue begrenzte eigene Kinder prüfen tatsächliches
Wachstum/Wiederverwendung, reale geschützte Node-/Kontrollseiten und Poison-
Verweigerung. Der echte Linux-Teilsperrtest berücksichtigt die zusätzliche
Buchhaltung anhand tatsächlicher Kernelwerte: weiterhin erster Zielseite Erfolg,
zweiter Seite Verweigerung, unabhängiger Owner unverändert und exakter vollständiger
Kernel-Rücklauf. Elternlimit unverändert; keine Nullbudget-/Prefix-Abschwächung.
EN: Full source-bound lint/tests on both feature configurations and native Linux,
ARM64/Windows, plus strict provenance/audit/fuzz, remain mandatory. Defining a test
or successful cross-compilation alone does not claim native execution. Caller-
owned buffers, allocator/OS internals and transient compiler/register scalar copies
remain explicit limits; known ordinary application records are not renamed as
compiler limits. Other native path/report/helper/host rows remain open.

DE: Zusätzlicher echter Release-Fehlerfall: Nur die eigene öffentliche Testabbildung
vor dem Guard freigeben. Der anschließende native Unlock muss fehlschlagen; weitere
Secret-Aufnahme wird verweigert, ein unabhängiger lebender Owner bleibt tatsächlich
gesperrt. Danach alle übrigen eigenen Sperren bereinigen und Kernel-Baseline prüfen.
EN: Bounded child only, no private test contents or foreign mappings; no mocked
release success. The error counter increases and no live owner's lock is sacrificed.

DE: Lokaler Quellenstand v1: 865 Rust-/Manifestdateien über alle14 Befehle
bytegleich. Vier strenge All-Target-Clippy-Konfigurationen (Linux/Windows-GNU,
mit/ohne API), direktes region-Clippy, 280 Bibliothekstests mit API, 250 ohne und31
Integrationsfälle erfolgreich; Format/Limits/Herkunft/Angriffsmatrix/Diff grün.
EN: Explicitly ignored child entry points run through their actual parents;
separately known ignored #338 race gaps stay documented and are not counted as
executed successes. Source-delta proof for the later additional release-error
test confirms unchanged production code; two bilingual comment-only updates.
Native exact-head acceptance of the complete new registry component remains pending.

DE: Native Windows-Codegenerierung am ersten Register-Head brach in rustc/LLVM
mit illegaler Instruktion ab. Minimaler COFF-Objekttest reproduziert denselben
WinCOFFObjectWriter-Abbruch für16/64KiB, während8KiB funktioniert. Kontroll- und
Node-Ausrichtung daher auf Windows auf die tatsächlich kodierbaren8KiB setzen;
Linux/ARM64 behalten64KiB. Die tatsächliche OS-Seitengröße wird weiterhin strikt
geprüft, keine ungesperrte/geometrisch unsichere Ausnahme.
EN: Cross-Clippy checks metadata, not this object-emission boundary. Actual COFF
object emission and native MSVC test/release builds are required in addition.
The local full GNU library attempt stopped on missing x86_64-w64-mingw32-dlltool
in getrandom before the root crate; it is not claimed as a successful build.
Use existing native CI for full builds; no tool installation or gate reduction.
Original failed CI logs and all reproduction results are retained, not relabeled.
[LLVM COFF writer alignment contract](https://llvm.org/doxygen/WinCOFFObjectWriter_8cpp_source.html).

DE: Letzter lokaler v2-Stand nach dem zusätzlichen echten Release-Fehlerfall:
alle zwölf Prüfungen erfolgreich, erneut865 Quellen vor/nach dem Lauf identisch.
Vier strenge Clippy-Konfigurationen, je16 Härtungsgruppen mit/ohne API samt den
tatsächlich aufgerufenen begrenzten Kindern; Format/Limits/Herkunft/Matrix/Diff grün.
EN: `registry-release-test-source-delta-proof.json` binds unchanged production code
to the broad v1 suites; only the new test/parent invocation and two comment-only
files differ. `protected-registry-v2.json` binds the final focused checks to exact
source hashes. No new unapproved token/thread experiment was executed or published.

DE: COFF-Fix v3: erneut zwölf Befehle erfolgreich bei vor/nachher865 identischen
Quellhashes, vier strenge Linux/Windows-Cross-Lints und je16 Härtungsgruppen mit
beiden Featurekonfigurationen. ELF-Ausrichtung und Funktionskörper bleiben erhalten;
die Windows-Ausrichtung erfüllt nun den reproduzierten Objektformat-Vertrag.
EN: Final native MSVC code generation and page observations still required;
successful metadata checks are not substituted for those native jobs.
