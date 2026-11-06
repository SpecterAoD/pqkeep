# Known-Answer-Tests / Known-answer tests

DE: Auszüge aus den offiziellen NIST-ACVP-Testvektoren (Repository `usnistgov/ACVP-Server`,
Commit `975de31eb83d87039ec88934fdc47d8c312b892d`, Verzeichnis `gen-val/json-files/`).
Als Werk der US-Bundesregierung gemeinfrei. Pro Parametersatz nur wenige Fälle, um das
Repository klein zu halten. Die Quelle steht in jeder Datei im Feld `source`.

- `ml_kem_keygen.json`: ML-KEM keyGen (Seed `d ‖ z` → Kapselungsschlüssel `ek`)
- `ml_dsa_keygen.json`: ML-DSA keyGen (Seed ξ → öffentlicher Schlüssel `pk`)
- `ml_dsa_sigver.json`: ML-DSA sigVer, Schnittstelle „external/pure“, gültige und ungültige Signaturen
- `ml_kem_decaps_wycheproof.json`: ML-KEM-Entkapselung mit Seed aus **Wycheproof** (C2SP, Apache-2.0,
  Commit `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9`, `testvectors_v1/mlkem_{512,768,1024}_test.json`):
  je Parametersatz 6 gültige Fälle (FIPS 203), alle Fälle zur impliziten Ablehnung, 1 „strcmp“-Fall und
  je 2 ungültige Fälle pro Fehlerart (Seed/Chiffrat zu kurz/zu lang)

Argon2id (kein Dateivektor / no file vector):
- RFC 9106, Abschnitt 5.3: als Konstante in `src/crypto/kdf_tests.rs`
- Referenzwerte für `derive()` (64 MiB, t=3, p=1/4, Passphrase 32×0x01, Salt 32×0x02): berechnet mit der
  C-Referenzimplementierung der Argon2-Autoren über `argon2-cffi` 25.1.0 / `argon2-cffi-bindings` 26.1.0
  (`argon2.low_level.hash_secret_raw`, `Type.ID`, Version 19); Konstanten in `tests/crypto_kat.rs`

EN: Extracts from the official NIST ACVP test vectors (repository `usnistgov/ACVP-Server`,
commit `975de31eb83d87039ec88934fdc47d8c312b892d`, directory `gen-val/json-files/`).
Public domain as a work of the US federal government. Only a few cases per parameter set
to keep the repository small. Each file records its origin in the `source` field.

Wycheproof vectors are licensed under Apache-2.0 (see `NOTICE`). Argon2id reference values were computed
with the Argon2 authors' C reference implementation via `argon2-cffi`.
