# Testkatalog v2 / Test catalogue v2

**DE** | [EN](#english)

Zu [V2_DRAFT.md](V2_DRAFT.md). `reference` = ausführbare Python-Referenz in `scripts/test_v2_*.py`
(läuft in der CI auf Linux und Windows); `core` = im Rust-Core umgesetzt und in `tests/*.rs` geprüft
oder – bei den U-Fällen – über die Kommandozeile; `planned` = **noch nicht umgesetzt**, gehört zum genannten Folge-Issue. Referenztests prüfen Kodierung und Regeln, nicht die Sicherheit einer Rust-Umsetzung.

| ID | Fall | Soll | Phase | Status |
|---|---|---|---|---|
| V01 | Zugänge: Passphrase mit/ohne Faktor, Empfänger 512/768/1024, ungültige Werte | exakte Bytes, Ablehnung | #39 | reference |
| V02 | Header M mit einem Zugang | exakte Bytes | #39 | reference |
| V03 | 0 Zugänge, 2× Passphrase, Passphrase nicht zuerst, unsortiert, doppelt, Typ 3/4/unbekannt | Ablehnung | #39 | reference |
| V04 | 64/65 Empfänger, Headergrenze 256 KiB inklusive, Hüllenzahl falsch | Grenze inklusive, sonst Ablehnung | #39 | reference |
| V05 | Hüllen-AAD: Index, Domäne, jedes Byte von M | jeweils andere AAD | #39 | reference |
| V06 | Strom-AAD: jedes Byte jeder Hülle | jeweils andere AAD | #39 | reference |
| V07 | HKDF-SHA3-256 Passphrase (file/key × Faktor 0/1) und Empfänger | unabhängige Sollwerte | #39 | reference |
| V08 | Argon2-AD ≤ 32 Byte, Domänen getrennt von v1, alle Info-Werte verschieden | erfüllt | #39 | reference |
| V09 | Faktordatei 0/31/32/33/4096 Byte | nur genau 32 | #39 | reference |
| V10 | Katalog eindeutig, jede `reference`-Zeile hat einen Test, Links gültig | erfüllt | #39 | reference |
| C01 | Argon2id mit Secret F und AD, echte Mindestparameter | unabhängiger Vektor (argon2pure) + RFC 9106 | #40 | core |
| C02 | Hüllen und Inhalt: AES-256-GCM-Vektoren inkl. AAD | unabhängige Vektoren, nicht nur Rundlauf | #40 | core |
| C03 | Faktordatei fehlt/falsch/zu groß/Link/Gerät/zu offene Rechte (D4) | Fehler vor Argon2id, nie neu erzeugt | #40 | core |
| C04 | jedes Header-/Hüllen-/Strom-Byte verändert, Zugang entfernt/vertauscht | Öffnen scheitert, keine Ausgabe | #40/#46 | core |
| C05 | Kürzen an jeder Headerposition, Längen bis u32::MAX, 256-KiB-Budget | begrenzter Parser, keine Panik | #40/#46 | core |
| C06 | v1↔v2-Matrix, Downgrade-Versuche, D3 (v1 wenn möglich) | wie Kompatibilitätstabelle | #40 | core |
| C07 | Schlüsseldatei v2: alle Algorithmen, falscher Faktor, jedes Feld verändert, Version umgeschrieben | Seed unverändert, unabhängiger Vektor, Öffnen scheitert | #40 | core |
| C08 | 1/2/64 Empfänger gemischter KEM-Stufen, eigener Schlüssel fehlt | jeder öffnet, klare Meldung | #46 | core |
| C09 | Fuzzing JSON-/Binärparser v2 | keine Panik, begrenzter Speicher | #40/#46 | core |
| U01 | CLI: `--factor-file`, Faktordatei erzeugen (`pqkeep factor`), `--to` mehrfach, DE/EN-Hilfe | eindeutige Bedienung | #41/#47 | core |
| U02 | Sandbox: Faktordatei lesbar, sonst nichts zusätzlich | Landlock-Freigaben minimal | #41 | core |
| U03 | Geheimnisse nicht in argv/Umgebung/Logs, API lehnt v2-Optionen ab | keine Offenlegung | #41 | core |

## Ausführung

```sh
python3 -m unittest discover -s scripts -p 'test_v2_*.py' -v
```

V07-Sollwerte wurden unabhängig mit `cryptography` 41.0.7 berechnet; die Tests nutzen nur die
Standardbibliothek. C01: Sollwerte in `tests/kat/v2_argon2id.json`, einmalig erzeugt mit
`scripts/v2_argon2_vectors.py` (`argon2pure`, nicht Teil der CI); geprüft in `tests/crypto_v2_kat.rs`,
die HKDF-Schritte zusätzlich in `src/crypto/v2_tests.rs`. C02: unabhängige Hülle in
`tests/crypto_v2_kat.rs` und eine ganze, ohne den Rust-Code gebaute v2-Datei (`tests/kat/v2_content.json`
aus `scripts/v2_content_vector.py`, Python `cryptography`), die `tests/files_v2_kat.rs` öffnen muss. C03:
`tests/crypto_factor.rs`. C04: `tests/files_v2_tamper.rs`; C06 und C08: `tests/files_v2_roundtrip.rs`
(Ver-/Entschlüsseln im Core, noch ohne CLI). C07 und C06 für die Schlüsseldatei: `tests/envelope_v2.rs` sowie eine ohne den Rust-Code gebaute
`*.key.json` v2 (`tests/kat/v2_keyfile.json` aus `scripts/v2_keyfile_vector.py`), die `tests/envelope_v2_kat.rs` entsperren und bytegleich wieder
ausgeben muss; Header und AAD zusätzlich in der Python-Referenz (`test_C07_…`). Dass die veröffentlichten v1-Leser v2 ablehnen, ist nicht
automatisch geprüft (siehe V2_DRAFT.md: Meldung „ungültiges JSON“). Der Header (V01–V06) ist im Rust-Core bytegenau nachgebaut
(`tests/files_v2_header.rs`, gemeinsame Sollwerte mit `test_V02_shared_digests`); C05:
`tests/files_v2_header_limits.rs`. C09: Fuzz-Ziele `pqkf_header_v2` (Binärparser) und `keyfile_parse` (JSON, Version 1 und 2) in der CI, dazu
ein fester Durchlauf (jede Kürzung, Einzelbyte-Änderungen) in `tests/envelope_v2_kat.rs`. Keine echten Geheimnisse im Repository; der C02-Vektor enthält
wie der C07-Vektor nur öffentliche Testbytes. U01 (Teil Faktordatei: `pqkeep factor`, `--factor-file`, Meldungen, Hilfe DE/EN), U02 und U03:
`tests/cli_factor.rs`; U02 zusätzlich die Freigabeliste selbst in `src/cli/access_tests.rs`; U03 zusätzlich `tests/api_generate.rs` (die API lehnt
unbekannte Felder wie `factor_file` ab). Menü, geführter Ablauf und Kontextmenü (U01): welche Fragen gestellt und welche Argumente
weitergegeben werden, prüfen `src/cli/factor_ui_tests.rs`, `src/cli/guide/keygen_tests.rs` und `src/cli/guide/mod_tests.rs`; die Fenster
selbst werden von Hand geprüft. U01 (Teil `--to` mehrfach, #47: 2 und 64 Empfänger, fremder Schlüssel, Doppel, 65, falscher
Schlüsseltyp, v1 bei einem Empfänger, `--with-passphrase` mit Faktordatei, `--each`, Hilfe DE/EN): `tests/cli_recipients.rs`,
dazu `src/cli/recipients_tests.rs` und die Sandbox-Freigaben in `src/cli/access_tests.rs`.

---

## English

Catalogue for [V2_DRAFT.md](V2_DRAFT.md). `reference` = executable Python reference in
`scripts/test_v2_*.py` (runs in CI on Linux and Windows); `core` = implemented in the Rust core and
checked in `tests/*.rs` or – for the U cases – via the command line; `planned` = **not implemented yet**, belongs to the named
follow-up issue. Reference tests check encoding and rules, not the security of a Rust
implementation. Run with the command above. V07 expected values were computed independently with
`cryptography` 41.0.7; the tests use only the standard library. C01: expected values in
`tests/kat/v2_argon2id.json`, generated once with `scripts/v2_argon2_vectors.py` (`argon2pure`, not part
of CI) and checked in `tests/crypto_v2_kat.rs`; C02: independent wrap in `tests/crypto_v2_kat.rs` and a
whole v2 file built without the Rust code (`tests/kat/v2_content.json` from
`scripts/v2_content_vector.py`, Python `cryptography`) that `tests/files_v2_kat.rs` must open; C03:
`tests/crypto_factor.rs`; C04: `tests/files_v2_tamper.rs`; C06 and C08: `tests/files_v2_roundtrip.rs`
(encrypting/decrypting in the core, no CLI yet). C07 and C06 for the key file: `tests/envelope_v2.rs` plus a `*.key.json` v2 built without the
Rust code (`tests/kat/v2_keyfile.json` from `scripts/v2_keyfile_vector.py`) that `tests/envelope_v2_kat.rs` must unlock and write back
byte-identically; header and AAD also in the Python reference (`test_C07_…`). That the released v1 readers reject v2 is not checked
automatically (see V2_DRAFT.md: message "invalid JSON"). The header (V01–V06) is rebuilt byte-exactly in the Rust core
(`tests/files_v2_header.rs`, expected values shared with `test_V02_shared_digests`); C05:
`tests/files_v2_header_limits.rs`. C09: fuzz targets `pqkf_header_v2` (binary parser) and `keyfile_parse` (JSON, versions 1 and 2) in CI, plus a
fixed pass (every truncation, single-byte changes) in `tests/envelope_v2_kat.rs`. No real secrets are committed; the C02 and C07 vectors contain
public test bytes only. U01 (factor file part: `pqkeep factor`, `--factor-file`, messages, help DE/EN), U02 and U03: `tests/cli_factor.rs`;
U02 also the permission list itself in `src/cli/access_tests.rs`; U03 also `tests/api_generate.rs` (the API rejects unknown fields such as
`factor_file`). Menu, guided flow and context menu (U01): which questions are asked and which arguments are passed on is checked in
`src/cli/factor_ui_tests.rs`, `src/cli/guide/keygen_tests.rs` and `src/cli/guide/mod_tests.rs`; the windows themselves are checked by
hand. U01 (repeated `--to`, #47: 2 and 64 recipients, foreign key, duplicates, 65, wrong key kind, v1 for a single
recipient, `--with-passphrase` with factor file, `--each`, help DE/EN): `tests/cli_recipients.rs`, plus
`src/cli/recipients_tests.rs` and the sandbox permissions in `src/cli/access_tests.rs`.
