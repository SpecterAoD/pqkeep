# Known-Answer-Tests / Known-answer tests

DE: Auszüge aus den offiziellen NIST-ACVP-Testvektoren (Repository `usnistgov/ACVP-Server`,
Commit `975de31eb83d87039ec88934fdc47d8c312b892d`, Verzeichnis `gen-val/json-files/`).
Als Werk der US-Bundesregierung gemeinfrei. Pro Parametersatz nur wenige Fälle, um das
Repository klein zu halten. Die Quelle steht in jeder Datei im Feld `source`.

- `ml_kem_keygen.json`: ML-KEM keyGen (Seed `d ‖ z` → Kapselungsschlüssel `ek`)
- `ml_dsa_keygen.json`: ML-DSA keyGen (Seed ξ → öffentlicher Schlüssel `pk`)
- `ml_dsa_sigver.json`: ML-DSA sigVer, Schnittstelle „external/pure“, gültige und ungültige Signaturen

EN: Extracts from the official NIST ACVP test vectors (repository `usnistgov/ACVP-Server`,
commit `975de31eb83d87039ec88934fdc47d8c312b892d`, directory `gen-val/json-files/`).
Public domain as a work of the US federal government. Only a few cases per parameter set
to keep the repository small. Each file records its origin in the `source` field.
