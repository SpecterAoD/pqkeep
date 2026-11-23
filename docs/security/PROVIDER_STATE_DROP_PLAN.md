# Complete owned provider-state destruction / Vollständiger eigener Provider-Drop

DE: #147 R6: SecretState ersetzt beim Drop das private T durch einen öffentlichen
Konstruktorwert. Das führt den Provider-Destruktor gesperrt aus, garantiert aber
keinen vollständigen Wipe früherer Belegungs-/Paddingbytes. Der öffentliche
Konstruktor wird außerdem im Drop erneut ausgeführt. Keine vollständige Behebung
privater Provider-Konstruktoren, interner Allokationen oder Arbeitsbereiche behaupten.
EN: Destroy the owned provider state in place while locked, then wipe its entire
former allocation before unlocking. Do not invoke a replacement constructor during
destruction or claim that private provider internals are thereby protected.

DE: Konkrete Dateien: crypto/secret_state.rs, getrennte secret_state_tests.rs,
kleine Anpassungen in aead.rs und locked_hash.rs, SPEC DE/EN und Changelog.
Box<T> durch festen Ein-Element-Vec<T> ersetzen; nur öffentliche Initialwerte
vor dem Sperren, dieselbe stabile Adresse während privater Verwendung. Gesamte
Kapazität sperren. Drop: Vec::clear führt T::drop an Ort und Stelle aus; danach
spare_capacity_mut().zeroize löscht alle früheren Owner-/Padding-/Kapazitätsbytes,
während die Sperre und Allokation noch bestehen. Erst dann entsperren und freigeben.
EN: Reuse the existing zeroize MaybeUninit-slice wiping primitive and memlock registry.
No new unsafe, dependency, allocator hook, crypto implementation or machine policy.
Retain mandatory lock failure; never initialize private state on an unlocked path.

DE: Nachweise: normale Zerstörung und Unwind führen den Destruktor genau einmal an
der ursprünglichen gesperrten Adresse aus, einschließlich eigener Ressourcen;
Stabilität und mehrseitige Belegung, Lock-Denial im bestehenden Kindprozess.
Bestehende Hash-/HKDF-/AEAD-/Stream-KATs und native Linux/Windows/ARM64-CI behalten.
Speicher nach Freigabe oder uninitialisierte Bytes niemals zur Testbeobachtung lesen.
EN: Verify ordering through live destructor probes, not freed-memory inspection.
Run fmt, strict Clippy with/without API, focused tests and full native CI. Require
reviewed source/provenance checks and a practical reverse-diff rollback before merge.

DE/EN: Abhängig von PR302 und dessen Main-Abgleich / depends on PR302 and its Main
integration. Rollback: separate reviewed code revert, no data migration or release.
Issue147 and roadmap remain In progress; provider internals/password helpers open.
