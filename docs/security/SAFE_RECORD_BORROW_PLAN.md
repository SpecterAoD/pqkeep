# Safe console record borrows / sichere Konsolen-Record-Sichten

DE: Beauftragter einzelner Patch/PR zu #147 auf Main9193647. Vier vermeidbare
produktive unsafe-Stellen reduzieren; notwendige native Grenzen nicht verstecken.
EN: One scoped patch/PR reduces four avoidable production unsafe sites, retaining
checked Win32 FFI and locked caller storage. This does not close R6 or #147.

## Files and invariants / Dateien und Invarianten

- `console_input_record.rs`: align_offset plus checked mutable subslices and a
  safe raw-pointer cast select a complete aligned record. Retain exclusive
  backing-storage lifetime and write-only volatile full-allocation padding wipe.
- `console_input.rs`: native read requires an exclusive mutable Record borrow;
  only success plus count1 yields a lifetime-bound initialized shared record view.
  Check EventType before borrowing the key union variant. Ordinary scalar fields
  use safe borrowed access; Unicode union access remains explicitly justified.
  No whole private native record is moved/copied into ordinary stack storage.
- Separate platform tests cover every starting alignment, exact/insufficient
  capacity, sentinel boundaries, cleanup/unwind and event-discriminant handling.
  Keep actual native Windows input/mode/cancellation tests and all full CI gates.
- Update DE/EN SPEC, memory documentation and changelog for this narrow boundary.
  No dependency, lockfile, algorithm, format, process policy or CI-policy changes.

## Validation and rollback / Prüfung und Rückweg

DE: Formatierung, strenges Plattform-Clippy lokal/nach Windows cross, Plattformtests,
Limits und Vendor-Herkunft prüfen. Native Windows-CI ist für neue Record-Tests und
echte Eingabe mit/ohne API erforderlich; Cross-Check ist kein Laufzeitnachweis.
Root-forbid bleibt unverändert. Fehler vor privater Verarbeitung zurückgeben;
Record vor erneutem Bytezugriff löschen. Keine lokalen Memlock-/Rechteänderungen.
EN: Preserve native Linux/Windows/ARM64 and existing compatibility/security tests.
Validate the exact reviewed head; retain source, signatures and full bundle.
Practical reverse patch must restore the exact base tree before handover.
No data migration. This request creates a PR only; no Main merge or branch deletion.
