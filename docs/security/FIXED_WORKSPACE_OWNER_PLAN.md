# Feste Arbeitsbereichsowner / Fixed workspace owners

DE: Folge zu #147 auf Main `5eb4696` (PR313); dessen separate Main-Abnahme läuft.
Der selbstständige Umsetzungsauftrag umfasst diesen eng begrenzten Schritt.
Plan vor Code; Issue/Roadmap bleiben In Bearbeitung.
EN: Scoped #147 follow-up on Main `5eb4696`; its independent Main acceptance is
running. The user's autonomous implementation instruction covers this step.
Plan precedes code; issue/roadmap remain In progress.

## Befund und Umsetzung / Finding and implementation

- DE: `locked_hash.rs` und `hkdf_locked.rs` halten typisierte Ausgaben in zusätzlichen
  Vec-Ownern und kopieren sie nach privater Befüllung nach SecretBytes. Hashausgabe,
  HKDF-PRK und -Ergebnis stattdessen direkt in exakt großen SecretBytes finalisieren;
  eine gemeinsame längengeprüfte mutable Output-Leihsicht bindet die Lebensdauer
  an den bestehenden gesperrten Owner. Kein privater Arraywert und kein unwrap.
  EN: Finalize hash output, HKDF PRK and result directly into exact-sized SecretBytes
  through one checked mutable Output borrow, removing additional typed Vec owners
  and private output copies. No private array value or unwrap.
- DE: HKDF-HMAC/Zwischenpuffer und Archiv-Framing/EntryRecord verwenden den bestehenden
  SecretWorkspace, dessen innerer SecretBuffer-Descriptor vor Allokation/Befüllung
  in SecretState gesperrt ist. Nur konkrete geprüfte ZeroizeOnDrop-Marker für diese
  tatsächlichen Payloadtypen; kein generischer schwächerer Marker. HMAC wird nur mit
  öffentlichem leerem Schlüssel vorinitialisiert, privat erst nach allen Sperren.
  EN: Reuse existing SecretWorkspace for HMAC/scratch and archive framing/records.
  Lock nested descriptors before allocation/population; add only concrete reviewed
  wiping-drop markers. Public empty-key HMAC initialization precedes locking;
  private rekey happens only after every required allocation has been locked.
- DE: Abschlussabgleich: Auch den öffentlichen HMAC-Startwert ohne vorgeschaltetes
  `vec!` übernehmen. Zuerst SecretWorkspace::with_capacity(1) fallibel anlegen und
  sperren, dann den öffentlichen leeren HMAC mit push_preallocated einsetzen.
  Damit gilt „Descriptor vor Allokation“ auch für diesen Konstruktor; öffentliche
  Initialisierung darf nach dem Sperren erfolgen. Keine Änderung privater Ableitung.
  EN: Final review refinement: use fallible SecretWorkspace::with_capacity(1)
  before constructing/pushing the public empty-key HMAC. Remove the preceding
  public vec! allocation; descriptor-before-allocation now also covers this path.
  Public initialization may occur after locking; private derivation is unchanged.
- DE: Ein bloßer Wechsel nach SecretState<Zeroizing<T>> wäre unzureichend: dessen
  beweglicher innerer Vec-Descriptor bliebe außerhalb der neuen Schutzbehauptung.
  EN: A type swap to SecretState<Zeroizing<T>> alone does not establish nested
  descriptor protection and is explicitly excluded from this implementation.

## Dateien und Nachweise / Files and evidence

DE/EN: `src/crypto/locked_hash.rs`, `hkdf_locked.rs`, their separate test files,
`src/files/archive_metadata.rs` and separate tests; DE/EN SPEC, memory inventory,
roadmap and changelog. No new crate, vendor, lockfile, KDF, wire format, public API,
unsafe code, CI/scanner relaxation or host policy change.

DE: Reale Tests prüfen identische Owneradressen, exakte Längenablehnung ohne Schreiben,
lebende innere Descriptor-/Payloadsperren vor privater Verarbeitung und nach Moves,
HMAC-Scratchlöschung und vollständige Datensatzlöschung. Bestehende unabhängige
SHA3/HMAC/HKDF-Vektoren, Wrapping-/Archivkompatibilität, Drop-/Unwind-/Denialverträge
weiter ausführen. Zusätzlicher begrenzter eigener Linux-Kindprozess senkt nur sein
eigenes Memlock-Limit auf null und muss tatsächliche Konstruktorfehler nachweisen.
EN: Test actual addresses/checked borrowing, wrong lengths before writes, live nested
descriptor/payload locks before private processing and after moves, scratch wiping
and record destruction. Retain independent vectors, wrapping/archive compatibility
and existing drop/unwind/denial contracts; bounded private Linux child proves actual
constructor denial with only its own memlock limit reduced to zero.

DE/EN: Required checks: fmt, strict Linux/Windows Clippy with/without API, focused
runtime tests in both feature configurations, limits/provenance, full native CI,
eight fuzz targets and PR security/review audit. Complete independently restored
bundle and practical reverse patch before merge; exact-head and Main acceptance.

## Grenzen und Rückweg / Limits and rollback

DE: Provider-interne Konstruktion/Scratch, Parser-/Pfad-/Baumdaten, gemeinsame Registry,
Compiler-/Stack-/Registerkopien und GUI-/vollständige Prozessgrenzen bleiben offen.
Die Änderung ist keine vollständige R6/R7/R8-Erfüllung. Vor Merge lokalen/PR-Stand
behalten; nach Merge separat geprüfter signierter Revert-PR. Keine Installation,
Bereitstellung, Rechte-/ACL-/Registryänderung oder nicht freigegebene Löschung.
EN: Provider internals, parser/path/tree/shared-registry/compiler/stack/register and
GUI/full-process boundaries remain OPEN. This is not complete R6/R7/R8 closure.
Preserve local/PR state before merge; separately reviewed signed revert after merge.
No installation, deployment, rights/ACL/Registry changes or unapproved deletion.
