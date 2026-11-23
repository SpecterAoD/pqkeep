# R6 Blake2 drop feature / Blake2-Drop-Feature

DE: Der tatsächliche gepinnte Produktionsgraph mit und ohne API enthält blake2
0.11.0 ohne zeroize. Argon2s zeroize aktiviert nur dep:zeroize; Blake2s eigener
Core-Drop löscht h/t aber nur unter blake2/zeroize. Gepinnte Originalarchive und
Backendquellen wurden bytegleich und gegen Cargo.lock geprüft. Noch keine Behebung.
EN: This is a concrete missing destruction feature, not proof of locked provider
construction, compression arrays, outputs or Rayon workspaces. R6 remains open.

DE: Enger beauftragter Schritt: Cargo.toml ergänzt blake2 als normale Produktions-
abhängigkeit mit bestehender Version0.11.0, default-features=false, features=zeroize.
Cargo.lock erhält nur die Root-Kante; Paketmenge, Versionen, Quellen und Checksummen
bleiben gleich. Keine reinen Dev-Features, die nur Testbuilds schützen. Kein Vendor-
Fork nur zur Weiterleitung eines Features, keine neue Kryptografie oder Installation.
EN: Reuse the already pinned crate and existing production graph. No CTR/Cipher
feature changes: actual dataflow does not justify claiming those as private fixes.

DE: Separate Tests sichern ZeroizeOnDrop für Blake2b512 und Blake2bVarCore als
Typvertrag. Beide normalen Produktionsgraphen gegen Ausgangsstand prüfen, bestehende
Argon2-/AEAD-/Container-/Interop-Vektoren und native Linux-/Windows-/ARM64-Prüfungen
beibehalten. fmt, beide strengen Clippy-Konfigurationen, Limits, cargo-deny, Herkunft/
Secret-Scan und acht automatische Fuzz-Ziele vor Abnahme. SPEC DE/EN, CHANGELOG und
Roadmap mit präziser Teilgrenze aktualisieren, vollständiges Bundle und praktischen
Rückweg prüfen. Plan vor Code signieren, gesonderter begrenzter PR.
EN: Preserve KDF parameters, parallelism, arithmetic, wire/derivation bytes and root
unsafe prohibition. Feature activation does not replace SecretBytes/SecretBuffer,
prelock ordinary provider workspaces or justify a full R6/R7/R8 closure. No host,
Registry, rights or process-policy changes. Issue147/roadmap stay In progress.

## Korrigierter Typabgleich vor Abnahme / Corrected type review before acceptance

DE: Die erste lokale Übersetzung widerlegt die geplante Annahme, Blake2b512
implementiere selbst ZeroizeOnDrop. Der feste buffer_fixed!-Wrapper besitzt Core
und Buffer, stellt dieses Merkmal aber nicht bereit. Keine erfundene Implementierung
oder Ausnahme hinzufügen: die tatsächlich verwendeten Bestandteile Blake2bVarCore
und LazyBuffer<U128> separat auf ZeroizeOnDrop prüfen. Der aktivierte Core-Drop
löscht h/t; der Buffer hat unter dem bereits aktiven Blockbuffer-Feature seinen
eigenen Drop. Automatische Felddestruktion und Quellabgleich getrennt dokumentieren.
EN: Preserve the failed compile log. Test actual component contracts and both
production graphs; never claim a marker or complete workspace lock guarantee for
the fixed wrapper. This correction changes the inaccurate proposed test assumption,
not the requirement for private core destruction or mandatory locked root owners.
