# R8 fixed lock-range records / Feste Sperrbereichsdatensätze

DE: Autorisierter enger Folgeschritt zu #147 nach PR309 auf Main747767f.
Der Eigentümer verlangt eigenständige Behebung der Laufzeitlücken und geprüfte
Main-Merges. Dieser Plan geht dem Code voraus; Main309-Abnahme läuft separat.
EN: Scoped application-owned bookkeeping repair, not full provider, stack,
registry or process protection. No new dependencies, unsafe, privilege,
host-policy, KDF, format, scanner or workflow changes.

## Befund / Finding

DE: LockedRange hält jede erworbene Seitenadresse zusätzlich in gewöhnlichem
Vec-Speicher. Die bestehenden Sperrschleifen erwerben stets einen zusammenhängenden
Präfix und stoppen am ersten Fehler. Eine feste Bereichsdarstellung beseitigt diese
zusätzliche Allokation, ohne die gemeinsame Registry umzubauen oder rekursive
Sperren für ihre eigenen Daten zu erzeugen.
EN: The existing shared page/refcount/LockGuard BTreeMap remains OPEN. Temporary
range handles, scalar/stack/compiler copies and OS records are not claimed protected.

## Dateien und Vertrag / Files and contract

- src/hardening/memlock.rs: checked page-span rounding and capacity arithmetic;
  fixed successful-prefix record instead of Vec; exact completion identity;
  checked existing-page refcounts; preserve partial cleanup and first-error exit.
- src/hardening/memlock_tests.rs and a separate Linux child-test file: real page
  ownership, empty/unaligned/boundary/overflow geometry, shared and concurrent
  references, deterministic refcount saturation and actual OS partial denial.
- docs/SPEC.md, docs/SPEC.en.md, docs/MEMORY_HARDENING.md, docs/ROADMAP.md,
  CHANGELOG.md: DE/EN scope and explicit remaining boundaries.

DE: Ein End-/Rundungs-/Budget-/Referenzzählerüberlauf verweigert die vollständige
Sperre; bestehende Secret-Konstruktoren liefern weiter MemoryLock vor privater
Nutzung. Keine stille Fortsetzung. Drop gibt genau den erfolgreichen Präfix frei.
Eigene feste Record-Felder nach Freigabe zeroisieren; dies ist keine Zusage über
Compilerkopien. SecretBuffer/SecretState-Drop-Verträge in diesem Schritt erhalten.
EN: Preserve public LockStats/is_locked and shared-page last-owner semantics,
including Windows working-set preparation. No new runtime bypass or test-only
production hooks. No allocation is added for private range geometry.

## Prüfung und Rückweg / Validation and rollback

DE: Beide strengen Clippy-/Featurekonfigurationen, fmt, Limits, fokussierte
Sperr-/Owner-/Unwind-/Wipe-/Denial-Tests und öffentlicher Freigabevertrag lokal.
Vollständige native Linux-x86/ARM64-/Windows-CI, Audit/CodeQL/Secret-Scan (Sonar seit 25.11.2026 entfernt)
und alle acht bestehenden Fuzz-Ziele am finalen Head vor Merge erforderlich.
Linux-Denial nur im eigenen kurzlebigen Prozess mit reduziertem Limit;
keine lokalen Rechteerweiterungen und keine schwächeren Sicherheitsparameter.
EN: Use public synthetic allocations only; no secret/address logging, freed-memory
or padding reads. Require signed commits, a complete independently restored bundle
and practical reverse-patch proof of the exact Main309 tree. Restore through a
separate revert PR; no existing key/archive/host data is modified. Main309 native
acceptance is tracked separately. Issue147/roadmap remain In progress.
