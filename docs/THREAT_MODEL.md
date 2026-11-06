# Bedrohungsmodell / Threat model

**DE** | [EN](#english)

## Schutzziele

- Vertraulichkeit und Integrität gespeicherter **privater Schlüssel** bei Verlust oder Diebstahl der
  Schlüsseldatei (Offline-Angreifer).
- Vertraulichkeit und Integrität **verschlüsselter Dateien und Ordner** (`.pqkf`), auch gegenüber
  künftigen Quantenrechnern (ML-KEM, AES-256).

## Im Rahmen (in scope)

| Bedrohung | Maßnahme |
|---|---|
| Brute-Force auf die Passphrase | Argon2id mit hohen Mindestparametern, Passphrase-Regeln (≥ 80 Bit geschätzt), Generator |
| Manipulierte Schlüsseldateien | AEAD mit vollständigem Header als AAD, strenger Parser, Downgrade-Schutz, Ableitung des öffentlichen Schlüssels beim Entsperren |
| Manipulierte `.pqkf`-Dateien | STREAM-Konstruktion (Kippen, Vertauschen, Abschneiden, Anhängen), Header-Hash als AAD, Prüfsummen |
| **Bösartige, korrekt verschlüsselte Archive** (Empfänger-Modus: jeder mit dem öffentlichen Schlüssel kann sie bauen) | Strenge Pfadregeln, keine Symlinks/Geräte, Grenzen, Ausgabe nur über Temporärordner, keine Teilausgabe, kein Überschreiben |
| Fehlerhafte/bösartige Eingaben (CLI, API) | Validierung, Größen- und Längengrenzen, Property-Tests „keine Panik“ |
| Ressourcenerschöpfung über die API | KDF-Obergrenzen vor der Ableitung, Body-Limits, Rate-Limiting, Semaphore (Schritt 5); keine Dateiverschlüsselung über die API |
| Geheimnisse in Swap/Core Dumps | Speichersperre, Core-Dump-Sperre (Linux), sofortiges Nullen (best effort, siehe `MEMORY_HARDENING.md`) |
| Lieferkette | Gesperrte Abhängigkeiten, `cargo deny`, wöchentliches Audit, signierte Commits/Releases |

## Sichtbar trotz Verschlüsselung

- Schlüsseldatei: Metadaten (Name, Organisation …), öffentlicher Schlüssel, Algorithmus, Zeitpunkt.
- `.pqkf`: Modus, KDF-Parameter bzw. Empfänger-ID, ungefähre Gesamtgröße.

## Außerhalb des Rahmens (out of scope)

- **Kompromittierter Rechner:** Schadsoftware mit Speicherzugriff, Keylogger, manipulierte
  Systembibliotheken. Wer den laufenden Prozess beobachten kann, sieht Passphrasen und Klartext.
- **Seitenkanäle auf Hardware-Ebene** (Strom, elektromagnetische Abstrahlung, Cache-Angriffe von
  Mitbenutzern auf derselben Hardware). Die Krypto-Crates zielen auf konstante Laufzeit; garantiert
  ist das nicht.
- Lokale Angreifer mit Schreibrechten im Quellordner während des Verschlüsselns (TOCTOU, siehe
  `FILE_FORMAT.md`).
- Sicheres Löschen von Originalen (auf SSDs unzuverlässig; Verschlüsselung statt Löschen).
- Nicht FIPS-140-validiert, nicht extern auditiert.

---

## English

**Goals:** confidentiality and integrity of stored private keys against offline attackers who obtain
the key file, and of encrypted files/directories (`.pqkf`), also against future quantum computers.

**In scope:** passphrase brute force (Argon2id, passphrase rules, generator); tampered key files
(full-header AAD, strict parser, downgrade protection, public key re-derivation); tampered `.pqkf`
files (STREAM, header hash as AAD, checksums); **malicious but correctly encrypted archives** in
recipient mode (strict path rules, no symlinks/devices, limits, temporary output, no partial output,
no overwriting); malformed CLI/API input (validation, limits, property tests); API resource
exhaustion (KDF bounds before derivation, body limits, rate limiting, semaphore; no file encryption via
API); secrets in swap/core dumps (page locking, core dump suppression on Linux, immediate zeroing –
best effort); supply chain (locked dependencies, cargo-deny, weekly audit, signed commits/releases).

**Visible despite encryption:** key file metadata, public key, algorithm, creation time; `.pqkf`
mode, KDF parameters or recipient ID, approximate total size.

**Out of scope:** compromised host (malware, keyloggers), hardware side channels, local attackers with
write access to the source directory during encryption (TOCTOU), secure deletion of originals, FIPS 140
validation and external audit.
