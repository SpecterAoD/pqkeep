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
