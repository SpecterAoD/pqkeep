# AES/GCM lifetime checkpoint / AES/GCM-Lebensdauer-Zwischenstand

DE: Umsetzung nach signiertem Plan26117f6 im R6-Draft334. Kein vollständiger
R6-Abschluss und noch keine native Abnahme dieses AES-Patches. Basis enthält
Main339/PADMÉ und Main341/ANON. Parameter/Versionen/Formatbytes bleiben gleich.
EN: The protected Root entry points now borrow fixed provider storage throughout
AES-256 scheduling, encryption, GHASH/POLYVAL and GCM authentication/decryption.

| Private surface / Fläche | Protected lifetime / Geschützte Lebensdauer |
|---|---|
| AES round keys, bit-slicing scratch, state and native block batches | Inline ProtectedAes256, locked before initialization |
| GHASH H, accumulator, input, wide multiplication/decomposition arrays | Inline ProtectedGHash/ProtectedPolyval and native-width workspace |
| Keystream, tag mask, partial AAD block, expected tag | Inline GCM Operations under the same prelocked owner |
| Stream AAD | Stable SecretBytes owner, including confidential library AAD |
| Caller plaintext/output | Existing locked buffers; invalid tag checked before output writes |
| Cleanup | Explicit Zeroize and Drop before SecretState unlock/free |

DE: Ursprüngliche Fixslicing-S-Box, MixColumns und Hilfsfunktionen byteidentisch.
Key-Schedule-/Rundenschleifen, POLYVAL32/64-Zerlegung, Multiplikation und Reduktion
gegen Originalarchive abgeglichen; ausschließlich geliehene Speicherziele und
skalare Bytezugriffe ersetzen private Array-Rückgaben. Bestehende CTR32BE-Flavour,
Längengrenzen und konstante Tagprüfung erhalten. Keine neu verfasste Unsafe-Stelle.
EN: Original native unsafe backend modules remain for ordinary APIs; this is not
an unsafe-free dependency claim. Root keeps forbid(unsafe_code). The protected
path uses the existing portable constant-time implementation and native batch width.

DE: 72 unabhängige cryptography41.0.7-Vektoren decken leere Eingaben, Teilblöcke,
Block-/Batchgrenzen und AAD-Padding ab. Zusätzlich frische Schlüssel, disjunkte
Puffer, unveränderte Ausgabe-Sentinels bei falschem Tag, reale Sperren/stabile
Owner und isolierte Error-/Unwind-/Memlock-Verweigerungskinder. Diese Kind-Einstiege
sind im normalen Harness ignoriert und werden explizit von begrenzten Eltern ausgeführt.
EN: A standalone consumer passes all72 cases with both documented cpubits32/64
overrides, without Root feature unification. Ordinary APIs separately pass all72
cases with normal hardware dispatch and forced portable32/64 backends. Width
overrides on a64-bit host do not prove a native32-bit ABI or ARM execution.

DE: Der neue geschützte GCM-Typ benötigt std für einen Inline-Mutex; Send/Sync und
beide Unwind-Traits bleiben nachweislich erhalten. Belegter/vergifteter Zustand
wird verweigert; Giftzustand nur zum Wipe zugänglich. Gewöhnliche APIs behalten
ihren no_std-Vertrag ohne protected-workspace. Kein gesenkter Worker-/Threadwert.
EN: Byte-slice wiping avoids relying on hybrid-array zeroize feature unification.
DE: Der öffentliche Anfangszustand und explizit gelöschte Zustände verweigern
Ver-/Entschlüsselung vor Ausgabe-Schreibzugriffen; nur erfolgreiche Initialisierung
aktiviert Operationen. Eigener Sentinel-Test für beide Richtungen/Zustände.
EN: Explicit zeroization also clears initialization; wiped state cannot silently
process data with erased round keys.

DE: Öffentlicher synthetischer x86-Laufzeitvergleich mit exakt denselben Registry-
Versionen am finalen Prüfstand: Median protected/reference3.442 bei32Byte,2.999 bei1024Byte und3.099
bei65536Byte, jeweils fünf Messungen. Hardwarebeschleunigung entfällt im geschützten
Pfad. Allokation/Sperren außerhalb der Schleife; kein End-to-end- oder ARM-Benchmark.
EN: Reinitialization timing also excludes allocation/locking/drop. These measurements
show a substantial compute cost; no acceleration/performance parity is claimed.

DE/EN: Evidence: aes-production-import-provenance.json,
aes-lock-and-fuzz-resolution-proof.json, aes-source-review-v3.json,
aes-math-invariants-v2.json, aes-width-results-v2.json,
aes-ordinary-results.json, aes-public-benchmark-v2.json and local-v11.json/logs in
analysis/issue-147-provider-in-place-20261126T171500Z. Native Linux/Windows/ARM64,
MSRV, audit/security/fuzz and complete R6 matrix/rollback acceptance remain required.
Argon2 initial/final hashes and all parallel workers remain OPEN. No partial R6 merge.

DE: Final lokal12/12 Prüfungen erfolgreich: fmt/Herkunft/Limits/staged-Diff,
beide Linux-/Windows-Cross-Clippies, beide fokussierten AES-Konfigurationen,
Stream-AAD und öffentliche AEAD-/Stream-/Fehler-/v2-KATs. Vorgängerstand zusätzlich
gegen DSA/KEM und sämtliche sechs Datei-/CLI-Suiten für v4/PADMÉ/ANON/Stream geprüft.
EN: The final initialization guard is covered in both focused configurations;
full native CI of the signed implementation remains pending. Offline cargo-deny
passes with cached advisories and the existing syn2/3 warning. Initial Python
module invocation failed on its import path; direct script invocation passes2tests.
No source or gate was relaxed to correct that command.

DE: Native Abnahme am signierten Head2b44f3e: alle23 Checks erfolgreich. Vier
vollständige native Protokolle geprüft/gehasht: Ubuntu22/ARM je888Tests/113Gruppen,
Ubuntu-latest1702/224 und Windows1540/226 über die jeweiligen Konfigurationen;
null Fehler. Neue AES-Eltern einschließlich Initial-/Wipe-Verweigerung und beide
Stream-AAD-/Autotrait-Tests tatsächlich enthalten. MSRV, Online-Audit/CodeQL,
vollständiger Historien-Secret-Scan und acht Fuzz-Ziele erfolgreich.
EN: Evidence: aes2b44-checks.json and aes2b44-native-summary.json/logs. This accepts
the AES checkpoint, not subsequent Argon2/Base64 code or the complete R6 matrix.
