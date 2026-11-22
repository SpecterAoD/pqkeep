DE: Freigegebener Umfang: Audit A01–A03 und app-eigene STREAM-Klartextpuffer. Fail-closed SecretBytes, typisierter gesperrter Argon2-Puffer, minimale RustCrypto-API-Patches für caller-owned HKDF/HMAC-Zustand und Zwischenwerte, begrenztes Secret-stdin/-file, sichere Freigabe. Keine neue Krypto-Konstruktion, Format-/Ableitungsbytes unverändert. Keine RLIMIT-/Working-Set-/sudo-Änderungen am Nutzerrechner. Bei unzureichender Speichersperre Fehler statt ungesicherter Verarbeitung. Tests: KAT/Kompatibilität, Limit-/I/O-/Drop-/Fehlerpfade, volle Linux-/Windows-/ARM64-CI, fmt/clippy/limits/deny, praktischer Revert. Rückweg: geprüfter Revert ohne Datenmigration; bis dahin main unverändert. Sicherheitsbedingt können bisher best-effort-funktionierende Aufrufe künftig sicher fehlschlagen. Nutzer autorisiert ausdrücklich Arbeit bis Merge nach main; keine erneute Einzelfreigabe.
EN: Owner-approved audited lifetime hardening through main merge: fallible fail-closed locked secrets, typed locked Argon2 storage, narrow upstream-derived in-place HKDF/HMAC interfaces, bounded secret input and locked application plaintext buffers. Preserve algorithms, format bytes and KATs; no host privilege/limit changes, insecure fallback or deployment. Full relevant regression/native CI and practical revert before merge.

DE: Review-Ergänzung vor Code: app-eigene Zeichen-/Lowercase-/Leet-/Wörterbuchkopien
der Stärkeprüfung ebenfalls vor dem Befüllen sperren. Fallible Auswertung bei der
bereits falliblen Passphrase-Konstruktion; nur öffentliche Bewertungsmetadaten behalten,
keine Aufweichung bei Sperrfehlern. Bewertungsregeln und Ergebnisse unverändert.
EN: Review extension: lock app-owned assessment character/lowercase/leet/dictionary copies
before filling. Evaluate fallibly during passphrase construction, retaining only non-secret
assessment metadata. Preserve assessment rules/results and reject lock failure.
