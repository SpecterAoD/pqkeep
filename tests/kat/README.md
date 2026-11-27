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
- Format v2 (`v2_argon2id.json`): Argon2id mit Secret (Faktordatei) und Associated Data (Domäne) bei
  64 MiB, t=3, danach HKDF-SHA3-256 – erzeugt mit `scripts/v2_argon2_vectors.py` (`argon2pure` 1.3, reines
  Python, vorher gegen RFC 9106 Abschnitt 5.3 geprüft; HKDF mit hashlib/hmac). Nur öffentliche Testbytes.
  Die AES-256-GCM-Hülle in `tests/crypto_v2_kat.rs` stammt aus Python `cryptography` 41.0.7.
- Format v2 (`v2_content.json`): eine ganze `.pqkf` v2 (Passphrase-Zugang mit Faktordatei, eine kleine
  Datei), erzeugt mit `scripts/v2_content_vector.py` ohne den Rust-Code (Header aus `scripts/v2_reference.py`,
  Packschlüssel aus `v2_argon2id.json`, AES-256-GCM aus `cryptography` 41.0.7). Nur öffentliche Testbytes.
- Format v2 (`v2_keyfile.json`): eine ganze Schlüsseldatei `*.key.json` v2 (AES-256, Passphrase +
  Faktordatei), erzeugt mit `scripts/v2_keyfile_vector.py` ohne den Rust-Code (Header und AAD aus
  `scripts/v2_reference.py`, Schlüssel aus `v2_argon2id.json`, AES-256-GCM aus `cryptography` 41.0.7).
  Nur öffentliche Testbytes.

EN: Extracts from the official NIST ACVP test vectors (repository `usnistgov/ACVP-Server`,
commit `975de31eb83d87039ec88934fdc47d8c312b892d`, directory `gen-val/json-files/`).
Public domain as a work of the US federal government. Only a few cases per parameter set
to keep the repository small. Each file records its origin in the `source` field.

Wycheproof vectors are licensed under Apache-2.0 (see `NOTICE`). Argon2id reference values were computed
with the Argon2 authors' C reference implementation via `argon2-cffi`. `v2_argon2id.json` (format v2:
Argon2id with secret and associated data, then HKDF-SHA3-256) was generated with
`scripts/v2_argon2_vectors.py` using `argon2pure` 1.3 (pure Python, checked against RFC 9106 section 5.3
first); the AES-256-GCM wrap in `tests/crypto_v2_kat.rs` comes from Python `cryptography` 41.0.7.
`v2_content.json` is a whole `.pqkf` v2 (passphrase slot with factor file, one small file) generated with
`scripts/v2_content_vector.py` without the Rust code (header from `scripts/v2_reference.py`, wrapping key
from `v2_argon2id.json`, AES-256-GCM from `cryptography` 41.0.7). `v2_keyfile.json` is a whole key file
`*.key.json` v2 (AES-256, passphrase + factor file) generated the same way with
`scripts/v2_keyfile_vector.py` (header and AAD from `scripts/v2_reference.py`). Public test bytes only.

## SHA3/SHAKE workspace vectors / Arbeitsflächenvektoren

DE: hash_workspaces.json enthält ausschließlich öffentliche synthetische Bytes:
byte[i]=(i*29+7)&255, Längen 0/1/7/8/71/72/73/135/136/137/167/168/169/511.
Referenzen unabhängig von Rust mit Python hashlib und der im JSON dokumentierten
OpenSSL-Version erzeugt: sha3_256/sha3_512 sowie jeweils512 Byte shake_128/shake_256.
EN: These are independently generated public fixtures, not NIST ACVP extracts.
Hash/XOF tests exercise prelocked stable owners, all rate boundaries, split calls,
empty reads, output sentinels and repeated borrowed reader initialization.

## AES/GCM workspace vectors / Arbeitsflächenvektoren

DE: aead_workspaces.json enthält 72 unabhängig mit Python cryptography41.0.7
AESGCM erzeugte öffentliche synthetische Fälle. Kein ACVP-Auszug. Schlüsselbyte
ist (i*13+7)&255, Noncebyte (i*19+11)&255, Nachrichtenbyte (i*29+3)&255 und
AAD-Byte (i*17+5)&255. Rust erzeugt diese Eingaben zur Laufzeit in gesperrten Ownern.
EN: Cross product of message lengths 0/1/15/16/17/31/32/33/63/64/65/1024 and
AAD lengths 0/1/15/16/17/65. Expected ciphertext includes the trailing 16-byte tag.
Tests additionally compare fresh random keys and disjoint buffers with the ordinary
provider, reject invalid tags before output writes, and check locked stable owners.

## Argon2/BLAKE2 workspaces / Arbeitsflächen

DE: argon_hash_workspaces.json enthält512 unabhängige Python-hashlib.blake2b-Fälle:
Digestgrößen1..64, Nachrichtenlängen0/1/127/128/129/255/256/1024, Byte[i]=(i*29+7)&255.
Sieben zusätzliche32Byte-Digests prüfen Little-Endian-u32-Framing, einschließlich
65536 und u32::MAX. Keine Schlüssel; Rust erzeugt Eingaben in gesperrten Ownern.
EN: Split updates/empty calls, lazy block boundaries, all digest sizes, sentinel
outputs and finalized/wiped-state refusal are tested against independent values.

DE: argon_operation_workspaces.json enthält76 unabhängige Argon2id1.3-Vektoren der
vorhandenen System-C-Referenz libargon2-1 0~20190702+dfsg-4build1. Binär-SHA-256,
öffentliche Eingabeformeln und Quellen stehen im JSON. Die C-ABI wurde am
[Originalheader20190702](https://github.com/P-H-C/phc-winner-argon2/blob/20190702/include/argon2.h)
und zusätzlich durch erfolgreiche Reproduktion von RFC9106/5.3 geprüft.
EN: Cover lanes1/2/4/8/16, passes1/2/3, minimum/rounded memory, repeated address
blocks and outputs4/16/32/64/65/128/1024, both with and without secret/AD. Synthetic
public fixtures only; no new C runtime dependency or installation. Native Root
tests check every lane's completed segments and real locked stable owners.
