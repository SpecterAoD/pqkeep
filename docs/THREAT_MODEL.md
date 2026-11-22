# Bedrohungsmodell / Threat model

> DE: Format v2 ist im Rust-Core umgesetzt. Über die Kommandozeile ist davon die **Faktordatei** nutzbar (`--factor-file`) sowie mehrere Empfänger (`--to` mehrfach, `--with-passphrase`); nur dann entsteht v2. Dieses Dokument beschreibt v1. Siehe [V2_DRAFT.md](V2_DRAFT.md).
> EN: Format v2 is implemented in the Rust core. From the command line the **factor file** is usable (`--factor-file`) as well as several recipients (repeated `--to`, `--with-passphrase`); only then v2 is written. This document describes v1. See [V2_DRAFT.md](V2_DRAFT.md).

**DE** | [EN](#english)

## Schutzziele

- Vertraulichkeit und Integrität gespeicherter **privater Schlüssel** bei Verlust oder Diebstahl der
  Schlüsseldatei (Offline-Angreifer).
- Vertraulichkeit und Integrität **verschlüsselter Dateien und Ordner** (`.pqkf`), auch gegenüber
  künftigen Quantenrechnern (ML-KEM, AES-256).

## Im Rahmen (in scope)

| Bedrohung | Maßnahme |
|---|---|
| Brute-Force auf die Passphrase | Argon2id mit hohen Mindestparametern, Passphrase-Regeln (≥ 128 Bit geschätzt, wählbar bis 256), Generator |
| Manipulierte Schlüsseldateien | AEAD mit vollständigem Header als AAD, strenger Parser, Downgrade-Schutz, Ableitung des öffentlichen Schlüssels beim Entsperren |
| Manipulierte `.pqkf`-Dateien | STREAM-Konstruktion (Kippen, Vertauschen, Abschneiden, Anhängen), Header-Hash als AAD, Prüfsummen |
| **Bösartige, korrekt verschlüsselte Archive** (Empfänger-Modus: jeder mit dem öffentlichen Schlüssel kann sie bauen) | Strenge Pfadregeln, keine Symlinks/Geräte, Grenzen, Ausgabe nur über Temporärordner, keine Teilausgabe, kein Überschreiben |
| Gefälschter Absender einer `.pqkf` (Empfänger-Modus: jeder kann für einen öffentlichen Schlüssel verschlüsseln) | Optionale Absender-Signatur (Format v3, #44): ML-DSA-87 über Header samt Empfängern und Chiffrat, Schlüsselbindung gegen unterschiedliche Klartexte je Empfänger, Prüfung vor jeder Ausgabe, `--signer` erzwingt einen bestimmten Absender; die Identität hinter dem Fingerabdruck bleibt eine externe Vertrauensfrage |
| Fehlerhafte/bösartige Eingaben (CLI, API) | Validierung, Größen- und Längengrenzen, Property-Tests „keine Panik“ |
| Ressourcenerschöpfung über die API | Body ≤ 64 KiB, Header-Timeout 10 s, Gesamt-Timeout 30 s, kein Keep-Alive, max. 64 Verbindungen, Rate-Limit je Client, Speicherbudget für Argon2 (sonst 503); keine Dateiverschlüsselung über die API (`API.md`) |
| Unbefugter API-Zugriff, Token-Raten | Standard nur 127.0.0.1, 256-Bit-Token nur als Hash gespeichert, Vergleich in konstanter Zeit, Sperre nach 5 Fehlversuchen; Netzwerkzugriff nur hinter Reverse Proxy mit TLS |
| Webseite im Browser spricht die lokale API an (Aussperren, DNS-Rebinding, #253) | Browser-Anfragen (`Origin`/`Sec-Fetch-Site`) → 403, ohne `--allow-remote` nur lokale `Host`-Werte, Anfragen ohne Token zählen nicht zur Sperre |
| Rückschlüsse aus der Antwortzeit von `/v1/validate` | Jede Antwort wird auf eine feste Mindestdauer aufgefüllt |
| Ausnutzen einer Lücke in pqkeep oder einer Bibliothek (Parser) | Sandbox unter Linux: Landlock (nur genannte Pfade, API gar keine) und Seccomp (kein `execve`/`fork`/`ptrace`, kein Netzwerk in der CLI, keine neuen Sockets in der API), Menü-Aktionen als eigene Prozesse (`SANDBOX.md`) |
| Passphrase im Kontextmenü (Fenster-Modus) | Weg nur per Pipe vom Passwortfenster in den Kindprozess mit Sandbox, nie über Argumente/Umgebung; Grenze: zenity/kdialog bzw. PowerShell/.NET halten sie kurz ungenullt im eigenen Speicher (`INTEGRATION.md`) |
| Geheimnisse in Swap/Core Dumps | Speichersperre, Core-Dump-Sperre (Linux), sofortiges Nullen (best effort, siehe `MEMORY_HARDENING.md`) |
| Lieferkette | Gesperrte Abhängigkeiten, `cargo deny`, wöchentliches Audit, signierte Commits/Releases |

## Nachweise und Grenzen (#151)

Die [Angriffstest-Matrix](security/ATTACK_TEST_MATRIX.md) trennt implementiert, abgedeckt und
tatsächlich ausgeführt. Gültige alte Schlüsseldateien und `.pqkf` bleiben lesbar: kein Replay-
Register, kein vertrauenswürdiger Frischezähler und kein globaler Mindestversionszustand. Frische
Nonces verhindern kein Replay der gesamten Datei. Versionsumschreiben/KDF-Absenken/Slot-Manipulation
werden separat geprüft; v1 bleibt unterstützt. Neuverschlüsselung widerruft keine alten Kopien.
Normales Fehler-Cleanup beweist keine Crash-/OOM-/Stromausfall-Recovery: bei Abort/SIGKILL läuft
Drop nicht, temporärer Klartext kann bleiben. Windows ohne Sandbox/eigene ACL-Prüfung; Landlock bleibt kernelabhängig.
Secret-Speicher muss vollständig gesperrt sein, sonst Fehler (siehe security/LOCKED_SECRETS.md). Source-/Publish-/FAT-Rennen siehe FILE_FORMAT.md
und FORMAT.md. STREAM-Puffer sind begrenzt, Source-/Pfadlisten und Argon2 benötigen weiteren Speicher.

Der freigegebene [Fault-/Recovery-Testentwurf](security/FAULT_RECOVERY.md) (#152) definiert
Commitgrenze, Bestandsschutz und isolierte Prozessabbrüche. Schritt B implementiert lokale
Envelope-/STREAM-Fehlertests; C ergänzt Faktor-/Archiv-/Decrypt-/Cleanup- und Eltern-sync-Fehler
sowie Windows-Sharing-Locks. D ergänzt bestätigte Child-Kills und frische Prüfprozesse.
[Native Nachweise](security/FAULT_RECOVERY_EVIDENCE.md) liegen vor; OS-/Stromausfallgarantien bleiben offen.

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

**Evidence and boundaries (#151):** the [attack matrix](security/ATTACK_TEST_MATRIX.md) separates
implementation, coverage and execution. Old valid key files and `.pqkf` remain readable: no replay
register, trusted freshness counter or global minimum-version state. Fresh nonces do not prevent
whole-file replay. Version relabelling, reduced KDF parameters and slot tampering are checked
separately; v1 remains supported. Re-encryption cannot revoke old copies. Ordinary error cleanup
does not prove crash/OOM/power-loss recovery: abort/SIGKILL skips Drop and temporary plaintext may
remain. Windows lacks an equivalent sandbox/dedicated ACL validation; Landlock remains kernel-dependent.
Secret memory must be fully locked or processing fails (see security/LOCKED_SECRETS.md). See FILE_FORMAT.md/FORMAT.md for source/publication/FAT races. STREAM buffers
are bounded, but source/path bookkeeping and Argon2 require additional memory.

The approved [fault/recovery test design](security/FAULT_RECOVERY.md) (#152) defines the
commit boundary, preservation and isolated process termination. Step B implements local
envelope/STREAM fault tests; C adds factor/archive/decrypt/cleanup and parent-sync faults plus
Windows sharing locks. D adds acknowledged child kills and fresh verification processes.
[Native evidence](security/FAULT_RECOVERY_EVIDENCE.md) is recorded; OS/power-loss guarantees remain open.

**Goals:** confidentiality and integrity of stored private keys against offline attackers who obtain
the key file, and of encrypted files/directories (`.pqkf`), also against future quantum computers.

**In scope:** passphrase brute force (Argon2id, passphrase rules, generator); tampered key files
(full-header AAD, strict parser, downgrade protection, public key re-derivation); tampered `.pqkf`
files (STREAM, header hash as AAD, checksums); **malicious but correctly encrypted archives** in
recipient mode (strict path rules, no symlinks/devices, limits, temporary output, no partial output,
no overwriting); malformed CLI/API input (validation, limits, property tests); API resource
exhaustion (body ≤ 64 KiB, header/overall timeouts, no keep-alive, connection cap, per-client rate
limit, Argon2 memory budget → 503; no file encryption via API); unauthorised API access (loopback by
default, 256-bit token stored as hash, constant-time comparison, lockout after 5 failures; browser requests and foreign `Host` values rejected so a web page cannot use the local API or lock the user out, #253; TLS via reverse
proxy); timing of `/v1/validate` (padded to a fixed minimum duration); exploitation of a bug in pqkeep or a library (Linux sandbox: Landlock limits paths – none for the
API – and seccomp forbids `execve`/`fork`/`ptrace`, network in the CLI and new sockets in the API; menu
actions run as separate processes, see `SANDBOX.md`); the context menu passphrase in window mode (only
through a pipe from the password window into the sandboxed child, never via arguments/environment;
limit: zenity/kdialog or PowerShell/.NET keep it briefly unzeroed in their own memory); secrets in swap/core dumps (page locking, core dump suppression on Linux, immediate zeroing –
best effort); supply chain (locked dependencies, cargo-deny, weekly audit, signed commits/releases).
A forged sender of a `.pqkf` is addressed by the optional sender signature (format v3, #44): ML-DSA-87 over
the header including recipients and the ciphertext, a key commitment against different plaintexts per
recipient, verification before any output and `--signer` to require a specific sender; who stands behind
the fingerprint remains an out-of-band trust question.

**Visible despite encryption:** key file metadata, public key, algorithm, creation time; `.pqkf`
mode, KDF parameters or recipient ID, approximate total size.

**Out of scope:** compromised host (malware, keyloggers), hardware side channels, local attackers with
write access to the source directory during encryption (TOCTOU), programs of the same user account
changing the context menu entries (Linux `~/.local/share`, Windows `HKCU\Software\Classes`; `integrate
status` reports modified entries), secure deletion of originals, FIPS 140
validation and external audit.

## Rekey (#109): interrupted replacement / unterbrochener Austausch

EN: Authenticate old protection before writing; require a strong new passphrase and the same
v2 factor. Keep key identity and format, disallow KDF reduction. New outputs/backups use strict
no-replace publication; confirmed in-place replacement commits an exact old encrypted backup
first. Never adopt stale temps or overwrite a committed backup. Trusted directories and one
writer are required: snapshot checks are not atomic CAS or process locks. Process-kill tests
prove no OS-crash/power-loss durability; parent sync remains best effort. Windows sharing tests
add no AV/reparse/ACL guarantee. Old copies retain old protection and are not revoked/securely
erased. See [REKEY.md](REKEY.md) and [design/test invariants](security/REKEY_DESIGN.md).

DE: Alten Schutz vor Schreibzugriffen authentifizieren, neue starke Passphrase und denselben
v2-Faktor verlangen. Identität/Format erhalten, keine KDF-Absenkung. Neue Ziele/Sicherungen strikt
ohne Ersetzen; bestätigter Austausch erst nach exakter verschlüsselter Altsicherung. Keine Temps
übernehmen oder bestehende Sicherung ersetzen. Vertrauenswürdige Verzeichnisse/ein Schreiber
nötig: Snapshotprüfung ist kein atomarer CAS/Prozesslock. Prozessabbrüche belegen keine OS-/
Stromverlustgarantie, Eltern-sync bleibt best effort. Windows-Sperrtests ergänzen keine AV-/
Reparse-/ACL-Garantie. Alte Kopien behalten alten Schutz, werden nicht widerrufen/sicher gelöscht.
Siehe [REKEY.md](REKEY.md) und [Entwurf/Testinvarianten](security/REKEY_DESIGN.md).


## Archivliste / Archive listing (#117)

DE: Explizite Metadatenfreigabe über `list`: Nutzdaten verwerfen, Namen/Größen erst nach
vollständiger Integritäts-/Strukturprüfung, begrenzte Sammlung ohne Disk-Spool. Fehler enthalten
keine Archiv-Inhaltspfade; nur der ausdrücklich angeforderte List-Vertrag zeigt diese nach Erfolg.
Integrität beweist keine Absenderidentität. Pfadkonflikte werden unabhängig von Eintragsreihenfolge
geprüft. Metadaten/PathSet brauchen zusätzlichen begrenzten Speicher; keine vollständige
RAM-Lösch-/OOM-Garantie. Vorhandene Source-/OS-Grenzen gelten weiter. [Grenzen](LIST.md),
[Abgrenzung und Tests](security/LIST_DESIGN.md).

EN: Explicit `list` metadata disclosure: discard payload, release bounded names/sizes only after
full integrity/structure checks, no disk spool. Errors contain no internal archive paths; only
the requested listing contract exposes them after success. Integrity is not sender identity.
Conflicts are checked independently of entry order; metadata/bookkeeping consume additional
bounded memory, without full erasure/OOM guarantees. Existing source/OS boundaries remain.
