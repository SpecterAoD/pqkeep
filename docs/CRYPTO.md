# Kryptografie / Cryptography

> DE: Format v2 (Faktordatei, mehrere Empfänger) ist ein **nicht implementierter Entwurf**: [V2_DRAFT.md](V2_DRAFT.md).
> EN: Format v2 (factor file, several recipients) is an **unimplemented draft**: [V2_DRAFT.md](V2_DRAFT.md).

**DE** | [EN](#english)

## Verfahren

| Zweck | Verfahren | Crate (Version) |
|---|---|---|
| Schlüsselaustausch | ML-KEM-512/768/1024 (FIPS 203), Standard ML-KEM-768 | `ml-kem` 0.3.4 |
| Signaturen | ML-DSA-44/65/87 (FIPS 204), Standard ML-DSA-65, „hedged“ (randomisiert) | `ml-dsa` 0.1.2 |
| Symmetrisch | AES-256 (Schlüsselerzeugung), AES-256-GCM (Schutz privater Schlüssel) | `aes-gcm` 0.11.1 |
| Schlüsselableitung | Argon2id (RFC 9106), Version 0x13, mehrere Kerne (`parallel`) | `argon2` 0.6.0 |
| Zufall | ausschließlich OS-CSPRNG | `getrandom` 0.4.3 |
| Streaming (Dateien) | STREAM-Konstruktion mit AES-256-GCM, 64-KiB-Blöcke, Nonce = 7 Byte Präfix ‖ Zähler ‖ Endmarke | `aes-gcm` 0.11.1 |
| Schlüssel einpacken (Dateien) | Passphrase: Argon2id; Empfänger: ML-KEM → HKDF-SHA3-256 (Salt = KEM-Chiffrat, Info = Domäne ‖ Empfänger-ID) | `hkdf` 0.13.0, `sha3` 0.12.0 |
| Dateisignaturen (`.pqsig`) | ML-DSA-87 über SHA3-512 der Datei (gestreamt), Kontext `PQKeep/sig/v1` ([SIGNATURE_FORMAT.md](SIGNATURE_FORMAT.md)) | `ml-dsa` 0.1.2, `sha3` 0.12.0 |
| Löschen von Geheimnissen | `Zeroize`/`ZeroizeOnDrop` | `zeroize` 1.9.1 |

## Begründung der Crate-Wahl

Geprüft wurden RustCrypto (`ml-kem`, `ml-dsa`, `aes-gcm`, `argon2`) und `libcrux` (Stand 06.11.2026,
crates.io und RustSec-Datenbank).

- **RustCrypto gewählt:** reine Rust-Implementierungen aus einem Projekt, gemeinsame Basistypen,
  Seed-Schnittstelle (`from_seed`/`to_seed`), private Schlüssel `ZeroizeOnDrop`, `Debug` gibt keine
  Geheimnisse aus. Keine offenen RustSec-Meldungen für die verwendeten Versionen
  (RUSTSEC-2025-0144 für `ml-dsa` ist ab 0.1.0-rc.3 behoben, RUSTSEC-2023-0096 für `aes-gcm` ab 0.10.3).
  Lizenzen MIT/Apache-2.0.
- **`libcrux` nicht gewählt:** formal verifiziert, aber Version 0.0.x und 2026 vier RustSec-Meldungen
  zu ML-DSA (u. a. fehlerhafte Prüfung bei der Verifikation), alle inzwischen behoben.
  Ein späterer Wechsel bleibt möglich, da Kryptologik nur in `src/crypto/` liegt.
- **MSRV 1.88:** `ml-kem` 0.3.4 und `ml-dsa` 0.1.2 verlangen 1.87; 1.88 wegen `proptest` (Tests sollen mit der MSRV laufen).

## Speicherung privater Schlüssel

- ML-KEM: 64-Byte-Seed (`d ‖ z`), ML-DSA: 32-Byte-Seed (ξ), AES: 32-Byte-Schlüssel. Der expandierte
  Schlüssel wird beim Laden neu abgeleitet.
- Schutz (`crypto::protect`): Argon2id(Passphrase, Salt 32 Byte) → AES-256-GCM-Schlüssel, Nonce 96 Bit.
  Für **jede** Verschlüsselung werden Salt, Schlüssel und Nonce neu erzeugt.
- Als AAD authentifiziert: Domänen-Tag `PQKeep/protect/v1`, Algorithmus-ID, m/t/p, Salt und die
  Metadaten des Aufrufers (Längenpräfixe, feste Reihenfolge). Die Nonce ist durch GCM gebunden.
- Falsche Passphrase und Manipulation sind bewusst nicht unterscheidbar (`Error::Decrypt`).

## Argon2id-Parameter

| | m (Speicher) | t | p |
|---|---|---|---|
| Profil `standard` | 256 MiB | 3 | Kerne, max. 8 |
| Profil `hardened` | 1 GiB | 4 | Kerne, max. 8 |
| zulässig (Erzeugen und Lesen) | 64 MiB … 1 GiB | 3 … 10 | 1 … 16 |

Zu schwache Parameter werden auch beim Lesen abgelehnt (Downgrade-Schutz), zu hohe verhindern
Ressourcenerschöpfung durch manipulierte Header. Die Prüfung erfolgt **vor** der Ableitung.

## Tests

Roundtrips aller Parametersätze, Manipulation jedes einzelnen Bytes von Chiffrat/Tag/Nonce/AAD,
abgeschnittene Daten, falsche Passphrase, KDF-Grenzwerte, Eindeutigkeit von Nonces über 10 000
Durchläufe, Zeroize. Known-Answer-Tests (`tests/kat/`, `src/crypto/kdf_tests.rs`):

| Was | Quelle | Prüft |
|---|---|---|
| ML-KEM keyGen | NIST ACVP | Seed → öffentlicher Schlüssel |
| ML-KEM decaps mit Seed | Wycheproof (C2SP) | Entkapselung, **implizite Ablehnung** (exaktes Ersatz-Geheimnis), ungültige Längen |
| ML-DSA keyGen / sigVer | NIST ACVP | Seed → öffentlicher Schlüssel; gültige und ungültige Signaturen |
| Argon2id intern | RFC 9106, Abschnitt 5.3 | Variante, Version, Parameter, Secret/AD des Argon2id-Kerns |
| Argon2id öffentlich | C-Referenzimplementierung (argon2-cffi) | `derive()` mit unseren Mindestparametern (64 MiB, t=3, p=1 und p=4) |
| SHA3-512 (Signaturen) | FIPS 202 (Leer-/„abc“-Beispiel) | gestreamter Hash über Blockgrenzen |
| HKDF-SHA3-256 intern | unabhängige Python-Berechnung (hashlib/hmac, an RFC 5869 Fall 1 geprüft) | Ableitung des Packschlüssels: Hash, Rollen von Salt/IKM/Info, Domänen-Tag |

Warum zwei Argon2id-Tests: Der RFC-Vektor nutzt 32 KiB und liegt unter unserer Mindestgrenze, er läuft
daher intern gegen den Kern ohne Grenzprüfung. Der Referenzvektor prüft den echten öffentlichen Weg.
Ein Roundtrip allein würde z. B. eine versehentlich falsche Variante (Argon2i statt Argon2id) nicht
bemerken, da Ver- und Entschlüsseln denselben Fehler machen; das wurde per Mutationstest bestätigt.

Warum Wycheproof statt NIST für die Entkapselung: Die NIST-ACVP-Vektoren liefern den privaten Schlüssel
nur in expandierter Form; unsere Schnittstelle akzeptiert bewusst nur den Seed. Wycheproof enthält
Seed-basierte Fälle, darunter Prüfungen der impliziten Ablehnung nach FIPS 203.

## Grenzen (ehrlich)

- **Nicht FIPS-140-validiert, nicht extern auditiert.** Die Verfahren entsprechen FIPS 203/204, die
  Implementierungen sind aber nicht zertifiziert.
- **Zeroize ist „best effort“:** Der Compiler kann Kopien anlegen (Register, Stack, Verschiebungen),
  das Betriebssystem kann Speicher auslagern (Swap) oder in Core Dumps schreiben. Speicherseiten
  mit Geheimnissen werden gesperrt und Core Dumps abgeschaltet (Linux); Details und Grenzen in
  [`MEMORY_HARDENING.md`](MEMORY_HARDENING.md).
- **Zwischenwerte der Crates:** Interne Zwischenwerte der Krypto-Crates liegen außerhalb unserer
  Kontrolle; wir verlassen uns auf deren eigene Zeroize-Unterstützung (aktiviert per Feature).
- **Zufallsfehler:** ML-KEM-Kapselung nutzt intern `UnwrapErr(SysRng)`; liefert das Betriebssystem
  keinen Zufall, bricht der Prozess ab statt einen Fehler zurückzugeben. Das ist auf unterstützten
  Systemen praktisch ausgeschlossen.
- **Timing:** Die Crates zielen auf konstante Laufzeit, garantiert ist das für die Zielhardware nicht.

---

## Entscheidungen vor der ersten Beta

- **Kein Hybrid-Verfahren (X25519 + ML-KEM) in der Beta.** ML-KEM ist seit FIPS 203 standardisiert;
  ein Hybrid schützt zusätzlich gegen einen unerwarteten Bruch von ML-KEM, verdoppelt aber
  Schlüsselformate, Tests und Angriffsfläche. Für ein Werkzeug ohne Echtzeit-Protokoll (gespeicherte
  Dateien) überwiegt vorerst die Einfachheit. Neubewertung in Issue #56, sobald sich ein Format für
  hybride Schlüssel etabliert hat.
- **TLS nicht eingebaut** (SPEC 5b nennt optional rustls): Die API lauscht standardmäßig nur auf
  127.0.0.1; für Netzzugriff ist ein Reverse Proxy mit TLS vorgesehen ([`API.md`](API.md)). Das hält
  die TLS-Bibliothek samt eigener Sicherheitsmeldungen aus dem Programm heraus.
- **Optionaler zweiter Faktor** (Pepper/Schlüsseldatei, SPEC 5b) auf ein Update verschoben
  (Issues #39–#41), weil er eine neue Formatversion kurz vor der Beta erfordert hätte.

## English

**Algorithms:** ML-KEM-512/768/1024 (FIPS 203, default 768) via `ml-kem` 0.3.4; ML-DSA-44/65/87
(FIPS 204, default 65, hedged signing) via `ml-dsa` 0.1.2; AES-256 key generation and AES-256-GCM via
`aes-gcm` 0.11.1; Argon2id (RFC 9106, multi-core) via `argon2` 0.6.0; OS CSPRNG only via `getrandom`;
`zeroize` for secrets. Detached file signatures (`.pqsig`): ML-DSA-87 over the streamed SHA3-512 of the
file, context `PQKeep/sig/v1` (see SIGNATURE_FORMAT.md).

**Why RustCrypto:** pure Rust from a single project, seed API, `ZeroizeOnDrop` private keys, no secrets
in `Debug`, no open RustSec advisories for the versions used, MIT/Apache-2.0. `libcrux` is formally
verified but still 0.0.x and had four ML-DSA advisories in 2026 (all fixed). Crypto logic is confined to
`src/crypto/`, so switching later remains possible. MSRV 1.88 (`ml-kem`/`ml-dsa` need 1.87, `proptest` 1.88 so tests run on the MSRV too).

**Private key storage:** ML-KEM 64-byte seed, ML-DSA 32-byte seed, AES 32-byte key; expanded keys are
re-derived on load. Protection: Argon2id(passphrase, 32-byte salt) → AES-256-GCM key, 96-bit nonce;
salt, key and nonce are fresh for **every** encryption. AAD covers domain tag, algorithm ID, m/t/p, salt
and caller metadata (length-prefixed). Wrong passphrase and tampering are deliberately indistinguishable.

**Argon2id parameters:** `standard` 256 MiB / t=3, `hardened` 1 GiB / t=4, p = cores (max. 8). Accepted
range for creating and reading: 64 MiB…1 GiB, t 3…10, p 1…16; checked **before** derivation (downgrade
and DoS protection).

**Limitations:** not FIPS 140 validated, not externally audited; zeroization is best effort (compiler
copies, swap, core dumps; see MEMORY_HARDENING.md for page locking and core dump suppression); internal intermediate values of the crates are
outside our control (we rely on their zeroize support); ML-KEM encapsulation aborts if the OS RNG fails; constant time is a goal of the crates, not a
guarantee for the target hardware.

**File encryption building blocks:** STREAM construction with AES-256-GCM (64 KiB chunks, nonce = 7-byte prefix ‖ counter ‖ last flag) and file-key wrapping via Argon2id (passphrase) or ML-KEM → HKDF-SHA3-256 (recipient); the HKDF wiring is checked against an independently computed reference value.

**Known-answer tests:** NIST ACVP (ML-KEM keyGen, ML-DSA keyGen/sigVer), Wycheproof (ML-KEM
decapsulation from seed incl. implicit rejection and invalid lengths; NIST decaps vectors need the
expanded key, which our seed-only API deliberately does not accept), RFC 9106 Argon2id vector against
the internal core (32 KiB is below our public minimum) and reference-implementation vectors through the
public `derive()`. A round trip alone would not detect e.g. Argon2i used instead of Argon2id; this was
confirmed by a mutation test.

**Decisions before the first beta:** no hybrid scheme (X25519 + ML-KEM) yet – ML-KEM is standardised
(FIPS 203); a hybrid would double key formats, tests and attack surface for a file tool without a
real-time protocol; re-evaluation in issue #56. No built-in TLS – the API listens on 127.0.0.1 by
default and relies on a reverse proxy for network access. The optional second factor is deferred to an
update (issues #39–#41) because it requires a new format version.
