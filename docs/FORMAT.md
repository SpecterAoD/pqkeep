# Container-Format (Schlüsseldatei) / Container format (key file)

> DE: Format v2 (Faktordatei, mehrere Empfänger) ist ein **nicht implementierter Entwurf**: [V2_DRAFT.md](V2_DRAFT.md).
> EN: Format v2 (factor file, several recipients) is an **unimplemented draft**: [V2_DRAFT.md](V2_DRAFT.md).

**DE** | [EN](#english)

> **Wichtig:** Die Metadaten (Name, Organisation, Firma, Abteilung, Account-Typ) und der öffentliche
> Schlüssel sind **nicht verschlüsselt**. Sie sind nur gegen Änderung geschützt. Bitte
> personenbezogene Daten bewusst eintragen (DSGVO).

## Beispiel (gekürzt)

```json
{
  "magic": "PQKEEP-KEY",
  "format_version": 1,
  "algorithm": "ML-KEM-768",
  "key_id": "3f9c…(64 Hex-Zeichen)…",
  "created_utc": "2026-11-06T20:00:00Z",
  "metadata": {
    "name": "Test User",
    "organization": "Example Org",
    "department": "IT-Sicherheit",
    "account_type": "service"
  },
  "public_key": "…(Base64)…",
  "kdf": {
    "algorithm": "argon2id",
    "version": 19,
    "memory_kib": 262144,
    "iterations": 3,
    "parallelism": 8,
    "salt": "…(Base64, 32 Byte)…"
  },
  "cipher": {
    "algorithm": "aes-256-gcm",
    "nonce": "…(Base64, 12 Byte)…",
    "ciphertext": "…(Base64: Seed bzw. Schlüssel + 16 Byte Tag)…"
  }
}
```

## Felder

| Feld | Inhalt | Prüfung beim Einlesen |
|---|---|---|
| `magic` | `PQKEEP-KEY` | exakt |
| `format_version` | `1` | nur `1` (Downgrade-Schutz, neuere Versionen: „nicht unterstützt“) |
| `algorithm` | `ML-KEM-512/768/1024`, `ML-DSA-44/65/87`, `AES-256` | bekannte ID |
| `key_id` | ML-KEM/ML-DSA: SHA3-256 des öffentlichen Schlüssels; AES: 32 Zufallsbytes | 64 Hex-Zeichen, nur Kleinbuchstaben; bei ML-KEM/ML-DSA muss sie zum öffentlichen Schlüssel passen |
| `created_utc` | RFC 3339, nur UTC: `JJJJ-MM-TTThh:mm:ssZ` | streng (kein Offset, keine Bruchteile, gültiges Datum, 1970–9999) |
| `metadata.name` | Pflicht | 1–128 Zeichen, NFC, keine Steuerzeichen, nicht nur Leerzeichen |
| `metadata.organization/company/department` | optional (fehlt = nicht gesetzt) | wie `name` |
| `metadata.account_type` | optional | wie `name`, höchstens 64 Zeichen |
| `public_key` | Base64; AES: leer | exakte Länge laut FIPS 203/204 |
| `kdf.*` | Argon2id, Version 19 (0x13), m/t/p, Salt | m 64 MiB–1 GiB, t 3–10, p 1–16, Salt 16–64 Byte |
| `cipher.*` | AES-256-GCM, Nonce, Chiffrat | Nonce 12 Byte; Chiffrat = Geheimnislänge + 16 |

Allgemein: unbekannte oder doppelte Felder werden abgelehnt, Base64 streng (Standard-Alphabet mit
Padding, keine nicht-kanonischen Kodierungen, keine Leerzeichen), Dateigröße höchstens 64 KiB,
fehlerhafte Eingaben führen nie zu einem Absturz (Property-Tests).

## Was ist verschlüsselt, was geschützt?

- **Verschlüsselt:** nur der private Teil: ML-KEM-Seed (64 Byte), ML-DSA-Seed (32 Byte) bzw.
  AES-256-Schlüssel (32 Byte).
- **Authentifiziert (AAD):** alle übrigen Felder. Sie werden in fester Reihenfolge mit
  Längenpräfixen kodiert (nicht als JSON-Text, da JSON mehrdeutig formatierbar ist). Jede Änderung
  an Metadaten, Zeit, Schlüssel-ID, öffentlichem Schlüssel, KDF-Parametern oder Salt lässt das
  Entsperren scheitern.
- **Zusätzlich beim Entsperren:** Aus dem Seed wird der öffentliche Schlüssel neu abgeleitet und mit
  dem gespeicherten verglichen.
- **Schlüssel-ID bei AES zufällig:** Ein Hash des Schlüssels würde erlauben, einen geratenen
  Schlüssel ohne Passphrase zu überprüfen.

## Datei

- Atomar geschrieben: Temporärdatei im Zielordner → `fsync` → Veröffentlichen. Ohne Überschreiben
  per Hardlink (scheitert atomar, wenn die Datei existiert), mit ausdrücklichem Überschreiben per
  Umbenennen. Auf Dateisystemen ohne Hardlinks (z. B. FAT) Prüfen + Umbenennen (nicht atomar).
- **Linux:** Rechte `0600`; beim Laden Warnung, wenn Gruppe oder andere lesen dürfen.
- **Windows:** Rechte erbt die Datei vom Zielordner. Empfehlung: im Benutzerprofil ablegen
  (z. B. `%USERPROFILE%\Documents\…`), dort hat standardmäßig nur der Benutzer Zugriff. Eigene
  ACLs setzt das Programm nicht (dafür wäre `unsafe`-Code nötig).
- Der Container enthält keine Pfade.

## Öffentliche Schlüsseldatei (`*.pub.json`)

Zum Weitergeben (z. B. damit andere Dateien für Sie verschlüsseln): `magic` = `PQKEEP-PUB`,
`format_version`, `algorithm` (nur ML-KEM/ML-DSA), `key_id`, `created_utc`, `metadata`,
`public_key`. Enthält **nichts Geheimes** (kein `kdf`, kein `cipher`). Die Datei ist **nicht
signiert**: Ob der Schlüssel wirklich der genannten Person gehört, muss über den Fingerabdruck
(`pqkeep inspect`) auf einem zweiten Weg bestätigt werden. Signaturen folgen mit Update U1.

---

## English

> **Important:** metadata (name, organisation, company, department, account type) and the public key
> are **not encrypted**, only protected against modification. Be deliberate with personal data.

**Fields:** `magic` (`PQKEEP-KEY`), `format_version` (only `1`; downgrade protection),
`algorithm`, `key_id` (SHA3-256 of the public key for ML-KEM/ML-DSA, 32 random bytes for AES;
lowercase hex, checked against the public key), `created_utc` (strict RFC 3339 UTC
`YYYY-MM-DDThh:mm:ssZ`), `metadata` (name required, others optional; 1–128 characters, account type
≤ 64, NFC, no control characters), `public_key` (Base64, exact FIPS length, empty for AES),
`kdf` (Argon2id v19, m 64 MiB–1 GiB, t 3–10, p 1–16, salt 16–64 bytes), `cipher` (AES-256-GCM,
12-byte nonce, ciphertext = secret length + 16).

**Parsing:** unknown/duplicate fields rejected, strict Base64 (no non-canonical encodings), max
64 KiB, never panics (property tests).

**Encrypted vs. authenticated:** only the seed/AES key is encrypted; every other field is bound as
AAD using a length-prefixed binary encoding (not the JSON text). On unlock, the public key is
re-derived from the seed and compared. AES key IDs are random so that a guessed key cannot be
verified without the passphrase.

**Files:** atomic write (temp file in target directory, fsync, hard link without overwrite / rename
with explicit overwrite; FAT fallback check + rename). Linux mode `0600` and a warning when loading
group/world-readable files. On Windows the file inherits the directory ACL; store keys in the user
profile. No paths inside the container.

**Public key file (`*.pub.json`):** magic `PQKEEP-PUB`, ML-KEM/ML-DSA only, contains nothing
secret. Not signed – confirm the fingerprint with the owner through a second channel.
