# Format der Signaturdatei (`.pqsig`) / Signature file format (`.pqsig`)

**DE** | [EN](#english)

Abgesetzte Signatur einer beliebigen Datei mit **ML-DSA-87** (FIPS 204) über den **SHA3-512**
(FIPS 202) ihres Inhalts (SPEC Abschnitt 9, U1). Ablage üblicherweise als `<datei>.pqsig` neben der
Datei. Stand: Bibliothek (`pqkeep::sign`); die Befehle `sign`/`verify` folgen mit U1-2 (#43).

## Was die Signatur beweist – und was nicht

- **Beweist:** Die Datei ist seit dem Signieren unverändert, und signiert hat der Inhaber des privaten
  Schlüssels mit der angegebenen Schlüssel-ID.
- **Beweist nicht, wer dieser Inhaber ist.** Der Fingerabdruck (Schlüssel-ID) des Signierers muss auf
  einem zweiten Weg bestätigt werden (persönlich, Telefon, bekannte Webseite).
- **Keine qualifizierte elektronische Signatur nach eIDAS** (dafür wären ein qualifiziertes Zertifikat
  und ein Vertrauensdiensteanbieter nötig); „rechtssicher“ im juristischen Sinn ist sie damit nicht.
- **Zeitstempel:** Angabe des Signierers nach seiner Systemuhr, signiert und damit nicht nachträglich
  änderbar – aber kein vertrauenswürdiger Zeitnachweis.
- **Dateiname:** nicht signiert. Eine umbenannte Datei bleibt gültig signiert.

## Aufbau (JSON, UTF-8, höchstens 16 KiB)

```json
{
  "magic": "PQKEEP-SIG",
  "format_version": 1,
  "algorithm": "ML-DSA-87",
  "key_id": "<64 Hex-Zeichen: SHA3-256 des öffentlichen Schlüssels>",
  "hash_algorithm": "SHA3-512",
  "file_sha3_512": "<128 Hex-Zeichen>",
  "file_size": 12345,
  "created_utc": "2026-11-08T12:00:00Z",
  "context": "PQKeep/sig/v1",
  "signature": "<Base64, 4627 Byte>"
}
```

Unbekannte oder fehlende Felder, Großbuchstaben im Hex, nicht-kanonisches Base64, falsche Längen und
Zeitstempel außerhalb von `JJJJ-MM-TTThh:mm:ssZ` werden abgelehnt. Andere Werte für `format_version`,
`algorithm` oder `hash_algorithm` ergeben „nicht unterstützt“ (kein Downgrade, nur ML-DSA-87).

## Signierte Nachricht

Signiert werden **nicht** die JSON-Bytes (mehrdeutig formatierbar), sondern diese feste Bytefolge.
`L(x)` = Länge von `x` als u64 Little Endian, gefolgt von `x`:

```
L("PQKEEP-SIG") | format_version u32 LE = 1 | L("ML-DSA-87") | L(key_id, 32 Byte)
| L("SHA3-512") | L(SHA3-512, 64 Byte) | file_size u64 LE | L(created_utc)
```

ML-DSA-87 „hedged“ (randomisiert) mit dem FIPS-204-Kontext-String `PQKeep/sig/v1` (Domänentrennung).
Nach dem Signieren wird die Signatur sofort gegengeprüft (Schutz vor Rechen-/Speicherfehlern).

## Prüfen

1. Öffentlicher Schlüssel muss ML-DSA-87 sein, sonst „nicht unterstützt“.
2. `key_id` muss zum öffentlichen Schlüssel passen.
3. Die Datei wird in 64-KiB-Blöcken gelesen (nie vollständig im Speicher); SHA3-512 und Größe müssen
   übereinstimmen.
4. ML-DSA-87-Prüfung der Nachricht mit dem Kontext-String.

Schlägt 2–4 fehl, lautet das Ergebnis einheitlich **„Signatur ungültig“** – bewusst ohne Unterscheidung.

## Tests

`tests/sign_roundtrip.rs` (SHA3-512-Testvektoren aus FIPS 202, Blockgrenzen, leere und große Daten,
Umbenennen), `tests/sign_tamper.rs` (jede Dateiänderung, Stichprobe über alle Signatur-Bytes,
Zeitstempel/Hash/Größe/Schlüssel-ID ausgetauscht, falscher Schlüssel), `tests/sign_reject.rs`
(strenges Einlesen, falsche Schlüsseltypen), `src/sign/format_tests.rs` (festes Byte-Muster der
signierten Nachricht).

## English

Detached signature of any file with **ML-DSA-87** (FIPS 204) over the **SHA3-512** (FIPS 202) of its
content (SPEC section 9, U1), usually stored as `<file>.pqsig`. Library only (`pqkeep::sign`);
the `sign`/`verify` commands follow with U1-2 (#43).

**What it proves:** the file is unchanged and was signed by the holder of the private key with the given
key ID. **It does not prove who that is** – confirm the signer's fingerprint (key ID) through a second
channel. **Not a qualified electronic signature under eIDAS.** The timestamp is the signer's claim
(signed, so it cannot be changed later, but not a trusted proof of time). The file name is not signed.

**Layout:** JSON (UTF-8, at most 16 KiB) with the fields shown above; unknown or missing fields, upper-case
hex, non-canonical Base64, wrong lengths and non-strict timestamps are rejected. Other values for
`format_version`, `algorithm` or `hash_algorithm` yield "unsupported" (no downgrade, ML-DSA-87 only).

**Signed message:** not the JSON bytes but the fixed length-prefixed byte sequence shown above
(`L(x)` = u64 LE length followed by `x`). Hedged ML-DSA-87 with FIPS 204 context string `PQKeep/sig/v1`;
each new signature is verified immediately (fault protection).

**Verification:** public key must be ML-DSA-87 (else "unsupported"); `key_id` must match it; the file is
hashed in 64 KiB blocks (never held in memory as a whole) and SHA3-512 and size must match; finally the
ML-DSA-87 check. Failures in these steps uniformly yield **"signature invalid"**, deliberately without
distinction.

**Tests:** see the list above (FIPS 202 vectors, block borders, tampering of every signed field, sampled
signature bytes, wrong keys, strict parsing, fixed message layout).
