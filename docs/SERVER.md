# PQKeep auf Servern / PQKeep on servers

**DE** | [EN](#english)

PQKeep braucht auf Servern **keine eigene Variante**: dasselbe Programm läuft ohne grafische
Oberfläche, über SSH, in cron und systemd. Optional ohne REST-API und Netzwerkcode bauen:
`cargo build --release --locked --no-default-features`.

## Grundidee: Der Server hat nur den öffentlichen Schlüssel

```text
Server (Backups)                         Offline / Admin-Rechner
  pqkeep encrypt --to backup.pub.json      pqkeep decrypt --key backup.key.json
  → nur öffentlicher Schlüssel             → privater Schlüssel + Passphrase
```

- Im **Empfänger-Modus** liegt auf dem Server **kein Geheimnis**. Wird er kompromittiert, kann der
  Angreifer künftige Daten mitlesen (er sieht den Klartext vor dem Verschlüsseln), aber **keine
  bisherigen Backups** öffnen.
- Schlüsselpaar einmalig auf einem vertrauenswürdigen Rechner erzeugen (ML-KEM-1024 entspricht
  NIST-Kategorie 5; Standard ist ML-KEM-768, Kategorie 3):

```sh
pqkeep generate -a ml-kem-1024 --name "Backup 2026" --out backup.key.json
pqkeep export backup.key.json --out backup.pub.json      # nur diese Datei auf den Server
```

- Den privaten Schlüssel offline sichern ([KEY_MANAGEMENT.md](KEY_MANAGEMENT.md)); Fingerabdruck
  (`pqkeep inspect backup.pub.json`) auf dem Server einmal gegenprüfen.

## Beispiel: Datenbank-Backup

```sh
#!/bin/sh
set -eu
umask 077
dir=/var/backups/pqkeep; mkdir -p "$dir"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
pg_dump -Fc meine_db > "$dir/db-$stamp.dump"
pqkeep --batch encrypt --to /etc/pqkeep/backup.pub.json "$dir/db-$stamp.dump"
rm -f "$dir/db-$stamp.dump"                      # Klartext-Dump sofort entfernen
rclone copy "$dir/db-$stamp.dump.pqkf" remote:backups/   # oder rsync, aws s3 cp, …
```

- Der Klartext-Dump liegt kurz auf der Platte: Ordner mit `umask 077`, besser auf `tmpfs`.
  Verschlüsseln direkt aus einer Pipe ist geplant (#83, nur Verschlüsseln).
- **restic/Borg** verschlüsseln selbst (nicht post-quanten-sicher); PQKeep davor schalten, wenn die
  Backup-Dateien zusätzlich quantenfest geschützt sein sollen.
- Mehrere Admins mit eigenem Schlüssel: `--to` mehrfach (bis 64 Empfänger, Format v2).

## systemd-Timer (empfohlen)

```ini
# /etc/systemd/system/pqkeep-backup.service
[Service]
Type=oneshot
User=backup
ExecStart=/usr/local/bin/backup.sh
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/backups/pqkeep
CapabilityBoundingSet=
# Nur falls eine Passphrase nötig ist (z. B. Passphrase-Modus):
# LoadCredential=pqkeep-pass:/etc/pqkeep/pass
# im Skript: pqkeep --batch --passphrase-file "$CREDENTIALS_DIRECTORY/pqkeep-pass" …

# /etc/systemd/system/pqkeep-backup.timer
[Timer]
OnCalendar=*-*-* 03:17
Persistent=true
[Install]
WantedBy=timers.target
```

cron geht genauso (`17 3 * * * backup /usr/local/bin/backup.sh`); systemd bietet die Härtung oben.
PQKeep selbst läuft unter Linux zusätzlich in seiner Sandbox (Landlock, seccomp).

## Unbeaufsichtigt: `--batch` und `--passphrase-file`

| Option | Wirkung |
|---|---|
| `--batch` | fragt **nie** nach; fehlt eine Eingabe, Abbruch mit Exit-Code 2 |
| `--passphrase-file <pfad>` | Passphrase aus Datei: reguläre Datei, keine Verknüpfung, ≤ 4 KiB, eine Zeile; Linux: nur für den Eigentümer lesbar (`chmod 600`/`400`), Eigentümer = aufrufender Benutzer oder root (systemd-Credentials) |
| `--passphrase-stdin` | eine Zeile von stdin (nicht zusammen mit `--passphrase-file`) |

- **Keine Umgebungsvariablen** für Passphrasen: sie sind über `/proc`, Absturzberichte und Kindprozesse
  sichtbar. Unter Windows prüft PQKeep die Rechte der Passphrase-Datei nicht (keine ACL-Prüfung ohne
  `unsafe`) – dort selbst für passende Rechte sorgen.
- Eine Passphrase auf dem Server ist schwächer als der Empfänger-Modus: wer den Server übernimmt, hat
  sie. Für Backups daher den Empfänger-Modus bevorzugen.

## Exit-Codes

`0` Erfolg · `1` Fehler · `2` Bedienfehler (auch `--batch` ohne Eingabe) · `3` Entschlüsselung
fehlgeschlagen · `4` Passphrase zu schwach · `5` Ziel existiert · `6` keine Fenster (Kontextmenü) ·
`7` Signatur ungültig (`verify`). Maschinenlesbare Ausgabe (`--json`): geplant (#85).

## Backups prüfen (`pqkeep check`)

Ein Backup ist nur so gut wie seine Wiederherstellung. `pqkeep check` prüft verschlüsselte Dateien
**vollständig** – alle Blöcke, Prüfsummen und Archivpfade wie beim Entschlüsseln –, schreibt aber
**nichts** (keine Ziel- und keine Temporärdateien; die Sandbox erlaubt nur Lesen). Dafür ist der
private Schlüssel bzw. die Passphrase nötig, also auf dem Admin-Rechner, nicht auf dem Server:

```sh
pqkeep check --key backup.key.json /mnt/backups/*.pqkf
```

- Eine Zeile je Datei (`OK: …` auf stdout, `FEHLER: …` auf stderr), am Ende eine Zusammenfassung.
  Jede Datei wird geprüft, auch wenn eine scheitert.
- Exit-Code: 0 alles in Ordnung, 3 falscher Schlüssel bzw. falsche Passphrase **oder** Manipulation
  (bewusst nicht unterscheidbar), 1 sonstiger Fehler (z. B. keine pqkeep-Datei, nicht lesbar), 2
  Bedienfehler. Bei mehreren Dateien zählt der erste Fehler.
- Ohne Geheimnis zeigt `pqkeep inspect` nur die Kopfdaten – das ist **keine** Integritätsprüfung.

## Grenzen

- Kein Dienst/Daemon und keine eigene Upload-Anbindung: Die CLI-Sandbox verbietet Netzwerkzugriffe
  bewusst; Uploads erledigen bewährte Werkzeuge.
- Release-Programme gibt es für x86_64 (Linux, Windows); andere Architekturen (z. B. ARM-Server,
  Raspberry Pi) aus dem Quelltext bauen.
- Backups regelmäßig mit `pqkeep check` prüfen (siehe oben) und gelegentlich wirklich wiederherstellen.

---

## English

PQKeep needs **no separate server variant**: the same program runs without a GUI, over SSH, in cron
and systemd (optionally built without REST API and network code: `--no-default-features`).

**Core idea – the server only holds the public key:** in **recipient mode** there is **no secret** on the
server; a compromised server can read future data but **cannot open existing backups**. Create the key
pair once on a trusted machine (ML-KEM-1024 = NIST category 5; default ML-KEM-768 = category 3), copy only
`backup.pub.json` to the server, keep the private key offline and check the fingerprint once.

**Database backup example and systemd timer:** see the script and units above (dump with `umask 077`,
ideally on tmpfs; encrypt with `--batch --to`; delete the plaintext dump; upload with rclone/rsync/S3 CLI;
systemd hardening with `NoNewPrivileges`, `ProtectSystem=strict`, `ReadWritePaths`; optional
`LoadCredential=` plus `--passphrase-file "$CREDENTIALS_DIRECTORY/…"`). restic/Borg encrypt themselves (not
post-quantum); put PQKeep in front for quantum-resistant backup files. Encrypting from a pipe is planned
(#83, encryption only); several admins with their own keys: repeated `--to` (up to 64 recipients, format v2).

**Checking backups (`pqkeep check`):** checks encrypted files **completely** – all chunks, checksums and
archive paths as when decrypting – but writes **nothing** (no target or temporary files; the sandbox only
allows reading). It needs the private key or passphrase, so run it on the admin machine:
`pqkeep check --key backup.key.json /mnt/backups/*.pqkf`. One line per file (`OK: …` on stdout, `ERROR: …`
on stderr) plus a summary; every file is checked. Exit code 0 all fine, 3 wrong key/passphrase **or**
tampering (deliberately indistinguishable), 1 other error, 2 usage; with several files the first error
counts. `pqkeep inspect` without a secret only shows header data – **no** integrity check.

**Unattended options:** `--batch` never prompts (missing input → exit code 2); `--passphrase-file <path>`
reads one line from a regular, non-link file ≤ 4 KiB, on Linux readable by the owner only (`chmod 600`/`400`)
and owned by the calling user or root (systemd credentials); `--passphrase-stdin` reads one line (not
together with `--passphrase-file`). **No environment variables** for passphrases (visible via `/proc`, crash
reports, child processes). Windows: no permission check of the file (no ACL check without `unsafe`).
A passphrase on the server is weaker than recipient mode – prefer recipient mode for backups.

**Exit codes:** 0 success, 1 error, 2 usage (also `--batch` without input), 3 decryption failed, 4 weak
passphrase, 5 target exists, 6 no windows (context menu), 7 invalid signature. `--json`: planned (#85).

**Limits:** no daemon and no own upload (the CLI sandbox forbids network access by design); release
binaries for x86_64 only – build other architectures (ARM servers, Raspberry Pi) from source; check
backups regularly with `pqkeep check` and do a real restore now and then.
