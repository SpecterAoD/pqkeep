# Base64 lifetime checkpoint / Base64-Lebensdauer-Zwischenstand

DE: Umsetzung nach vor Code signiertem Plan2b44f3e; exakt vorhandenes base64ct1.8.3.
Alle Produktionsmodule und Original-Lizenzen aus dem gegen Cargo.lock geprüften
Archiv erhalten. Keine zusätzliche Bibliothek, Version oder eigene Kodierung.
EN: Additive borrowed-scratch API shares original alphabet, length and padding
logic. Ordinary encode/string/decode APIs remain compatibility/public-data paths.

DE: Tatsächlicher privater Aufruf ist die Token-Erzeugung mit32OS-Zufallsbytes.
Quelle und Ausgabe sind SecretBytes, der Restblock jetzt ebenfalls: sieben Bytes,
aufgeteilt in exklusiv geliehene3-/4Byte-Sichten. Sperren vor privater Befüllung;
Wipe vor Unlock/Free bei Erfolg, Fehler und Unwind. Keine gewöhnliche Encoder-
Rückfalloption bei Ressourcenfehlern. Strenge Root-Schnittstelle bleibt erhalten.
EN: Reusing scratch clears stale remainder bytes before filling it. A destination
that is too short is refused before either scratch or output writes. Returned text
borrows the locked destination; safe UTF-8 validation replaces one inherited unsafe
cast. No newly authored unsafe. Ordinary decode/string unsafe is explicitly retained
upstream code outside the protected token path, not a claim of unsafe-free dependencies.

DE: Der Original-3Byte-/6Bit-Alphabetkern arbeitet mit skalaren nativen Wörtern und
öffentlichen konstanten Alphabettabellen; keine privaten Array-Rückgaben. Installierte
Rust-UTF-8-Prüfung liest ASCII über native Wörter beziehungsweise einzelne Bytes,
ohne bekannte private Arbeitsarrays. Register-/Compilerkopien bleiben eine Grenze;
dies ist kein formaler Soundness- oder Compilerbeweis.
EN: Inherited bulk-zeroization/assembly boundaries in Main352's zeroize1.9.2 were
reviewed against both pinned archives. No Root unsafe or local host-policy change.
Whole-object destruction and full-capacity/padding wiping still precede unlocking.

DE: Private Providerverarbeitung: nur `api/token` benutzt den strikten Encoder.
`envelope/{parse,public}` kodieren öffentliche Schlüssel, Salt, Nonce und bereits
verschlüsselte Seeds; `sign/format` die ausdrücklich veröffentlichte Signatur.
Die jeweiligen Decoder liefern dieselben öffentlichen Hüllfelder. PowerShell
kodiert das statische Skript, nicht die über Pipe übertragenen Passwörter. Der
Fehler-Fixture-Test ist kein Produktionsaufruf. Keine privaten Seeds als Base64-JSON.
EN: A registry copy of1.8.3 remains in ordinary transitive password-hash/DER APIs;
Root's direct private call resolves to the versioned path, also for an external
consumer and fuzz. Do not infer a global dependency override from this path edge.

DE: Unabhängige Python-Referenzen:76Längen × zwei Alphabete × Padding an/aus =304
Fälle, einschließlich0/1/2/3/31/32/33 und Blockgrenzen bis4097Byte. Reale stabile
gesperrte Owner/Scratch, Wiederverwendung mit Sentinels, zu kurze Ziele und frischer
OS-Zufall geprüft. Begrenzte isolierte Kinder prüfen Wipe unter Sperre bei Fehler/
Unwind und Sperrverweigerung vor Token-Dateiausgabe. Nur eigenes Linux-Kind senkt
sein Budget; kein sudo und keine Änderung des Elternprozesses.
EN: Full native/security/fuzz acceptance remains required for the resulting head.
R6 stays open until the complete provider matrix and exact rollback are accepted;
R7/process/GUI and R8/confidential metadata remain separate, with no whole147 closure.

DE/EN: Evidence in analysis/issue-147-provider-in-place-20261126T171500Z:
base64-production-import-provenance.json, base64-lock-resolution-proof.json,
external-consumer-base64-resolution.json, main352-zeroize-source-review.json,
base64-provider-v1.json/logs and final local/native source-bound acceptance.

DE: Final lokal10/10 Kommandos erfolgreich (base64-local-v3.json): fmt, Herkunft,
Limits, staged-Diff, fünf fokussierte Eltern, vier strenge Linux-/Windows-Cross-
Clippies mit/ohne API und bestehende Token-Integrationstests. Beide ignorierten
Kind-Einstiege werden tatsächlich durch Eltern ausgeführt. Alle geprüften Dateien
blieben unverändert. Gewöhnliche APIs bestehen die304 unabhängigen öffentlichen
Referenzfälle; zusätzlicher direkter Clippy prüft tatsächliche Providerquellen.
EN: Fresh external consumer resolves21 path providers and proves Root's private
Base64 edge. Existing lockfile versions/checksums/dependency names are preserved;
only the same-version path package and source disambiguation are added. Offline
cargo-deny passes: existing syn duplicate and documented same-version Base64 source
duplicate warnings; no policy exception or suppression. Final online CI is required.
