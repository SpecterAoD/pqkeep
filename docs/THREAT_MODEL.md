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
| Ressourcenerschöpfung über die API | Body ≤ 64 KiB, Header-Timeout 10 s, Gesamt-Timeout 30 s, kein Keep-Alive, max. 64 Verbindungen, Rate-Limit je Client, Speicherbudget für Argon2 (sonst 503); keine Dateiverschlüsselung über die API (`API.md`) |
| Unbefugter API-Zugriff, Token-Raten | Standard nur 127.0.0.1, 256-Bit-Token nur als Hash gespeichert, Vergleich in konstanter Zeit, Sperre nach 5 Fehlversuchen; Netzwerkzugriff nur hinter Reverse Proxy mit TLS |
| Rückschlüsse aus der Antwortzeit von `/v1/validate` | Jede Antwort wird auf eine feste Mindestdauer aufgefüllt |
| Ausnutzen einer Lücke in pqkeep oder einer Bibliothek (Parser) | Sandbox unter Linux: Landlock (nur genannte Pfade, API gar keine) und Seccomp (kein `execve`/`fork`/`ptrace`, kein Netzwerk in der CLI, keine neuen Sockets in der API), Menü-Aktionen als eigene Prozesse (`SANDBOX.md`) |
| Passphrase im Kontextmenü (Fenster-Modus) | Weg nur per Pipe vom Passwortfenster in den Kindprozess mit Sandbox, nie über Argumente/Umgebung; Grenze: zenity/kdialog halten sie kurz ungenullt im eigenen Speicher (`INTEGRATION.md`) |
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
- **Kontextmenü-Einträge** (Linux `~/.local/share`, Windows `HKCU\Software\Classes`): Programme des
  eigenen Benutzerkontos können sie verändern und so einen anderen Befehl unterschieben. Das entspricht
  dem kompromittierten Rechner; `integrate status` meldet geänderte Einträge (`INTEGRATION.md`).
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
exhaustion (body ≤ 64 KiB, header/overall timeouts, no keep-alive, connection cap, per-client rate
limit, Argon2 memory budget → 503; no file encryption via API); unauthorised API access (loopback by
default, 256-bit token stored as hash, constant-time comparison, lockout after 5 failures, TLS via reverse
proxy); timing of `/v1/validate` (padded to a fixed minimum duration); exploitation of a bug in pqkeep or a library (Linux sandbox: Landlock limits paths – none for the
API – and seccomp forbids `execve`/`fork`/`ptrace`, network in the CLI and new sockets in the API; menu
actions run as separate processes, see `SANDBOX.md`); the context menu passphrase in window mode (only
through a pipe from the password window into the sandboxed child, never via arguments/environment;
limit: zenity/kdialog keep it briefly unzeroed in their own memory); secrets in swap/core dumps (page locking, core dump suppression on Linux, immediate zeroing –
best effort); supply chain (locked dependencies, cargo-deny, weekly audit, signed commits/releases).

**Visible despite encryption:** key file metadata, public key, algorithm, creation time; `.pqkf`
mode, KDF parameters or recipient ID, approximate total size.

**Out of scope:** compromised host (malware, keyloggers), hardware side channels, local attackers with
write access to the source directory during encryption (TOCTOU), programs of the same user account
changing the context menu entries (Linux `~/.local/share`, Windows `HKCU\Software\Classes`; `integrate
status` reports modified entries), secure deletion of originals, FIPS 140
validation and external audit.
