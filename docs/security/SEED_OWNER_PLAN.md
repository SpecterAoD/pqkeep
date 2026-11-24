# Stable typed seed owners / Stabile typisierte Seed-Owner

DE: Beauftragter nächster enger #147-R6/R8-Schritt auf signiertem Main311262c087; dessen native Main-Abnahme läuft separat.
Bisherige Caller-Seed-Payloads sind bereits vor privater Kopie gesperrt; keinen
neuen ungesperrten Seed-Befund daraus ableiten. Zusätzliche innere Vec-Descriptoren
entfernen, indem feste typisierte Seed-Arrays im vorhandenen stabil gesperrten
SecretState<Zeroizing<T>> liegen. Keine Änderung der Kryptoalgorithmen oder Provider.
EN: Use only existing pinned types. Construct public defaults, validate the exact
length before locking, lock stable state, then borrow-copy source bytes in place.
Review only actual fixed ML-DSA32/ML-KEM64 array call sites; no blanket provider
protection, new ZeroizeOnDrop marker, private by-value seed or exported clone.

## Files / Dateien

- src/crypto/seed_state.rs: internal shared prepare/parse for actual typed fixed
  arrays using existing Zeroizing destructor guarantee and SecretState full former
  allocation wipe-before-unlock path. Reject allocation/lock failure without fallback.
- src/crypto/mod.rs, dsa.rs and kem.rs: wire only existing typed seed construction;
  preserve length errors, provider call graph, random hedged signing, output bytes
  and explicit early wiping after derivation. Provider-owned returns remain OPEN.
- Separate seed_state_tests.rs and Linux isolated denial tests; adapt existing KEM
  typed-seed regression to stable state. No unsafe or public API/format changes.
- DE/EN SPEC, MEMORY_HARDENING, ROADMAP and CHANGELOG update with exact open limits.

## Validation / Prüfung

DE: Tatsächliche 32/64-Byte-Arrays vor privater Befüllung gesperrt beobachten;
Rückgabe/Bewegungen behalten dieselbe Adresse. Grenzlängen und Callerbytes erhalten;
explizites Zeroize behält stabilen gesperrten Zustand. Ein eigener isolierter
Linux-Kindprozess reduziert Memlock auf0 und prüft alle tatsächlichen Seedtypen:
gültige Länge scheitert strikt mit MemoryLock, falsche Länge bleibt InvalidInput.
Keine Erhöhung von Limits/Rechten und kein lokales sudo. Bestehende Owner-/Unwind-
Tests, KEM/DSA-Tests und unabhängige KAT-/Format-/Signaturtests bleiben bestehen.
EN: Both strict clippies/features, focused low-memory tests locally and complete
native Linux/ARM64/Windows CI plus all eight existing fuzz targets on final head.
Verify pinned archive checksums/source/features, all security/review gates and
signed commits. Complete independently restored/fsck-checked bundle and practical
reverse patch to exact accepted Main311 tree before merge; local work retained.

DE: R6 Providerkonstruktion, beibehaltene Provider-Seeds/expandierte Zustände,
SHAKE-/Kompressions-/Shared-secret-Scratch und R7 Helper/volle Prozesspolicy sowie
übrige R8-Pfad-/Baum-/Skalar-/Registrydaten bleiben offen. Keine vollständige
Stack-/Register-/Compilerkopien- oder Prozessschutzgarantie.
EN: #147/roadmap stay In progress. No dependency, KDF, provider source, CI/scanner,
ACL/Registry/rights/host-policy change or deployment. Recovery is a separately
reviewed signed revert PR, never an automatically weaker security fallback.

## Signed refinement before final implementation / Signierte Präzisierung

DE: Die gepinnte hybrid-array-API bietet TryFrom<&[u8]> für &Array<u8,N>.
Damit feste Seeds direkt aus dem bereits stabilen gesperrten SecretBytes-Owner
ausleihen; kein zusätzlicher typisierter Owner und keine private Arraykopie.
Plan-State/Zeroizing-Prototypen bleiben historische Zwischennachweise, nicht der
finale Produktionsweg. Erst exakte erwartete Länge prüfen, dann SecretBytes vor
privater Kopie sperren. Typisierte Sicht nur geliehen; fehlerhafte Sicht verweigern.
EN: Use existing stable byte-owner descriptor/payload protection and destruction.
The internal view is constrained to Array<u8,N>, uses the pinned checked borrowed
conversion and cannot outlive its SecretBytes owner. Preserve early wiping and
all provider calls/bytes. No new owner abstraction, unsafe or dependency.

DE/EN: Same scoped files/tests/rollback and OPEN provider/helper/process boundaries.
Add actual pointer-identity/owner-lock checks for borrowed views and reject wrong
view sizes; the isolated denial child checks actual byte-owner construction.
Signed refinement precedes replacement of the uncommitted prototypes.
