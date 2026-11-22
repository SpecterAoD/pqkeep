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
| `--sign-passphrase-file <pfad>` | nur mit `encrypt --sign-with`: Passphrase des Signaturschlüssels (Absender-Signatur, #44/#286), gleiche Regeln wie `--passphrase-file`; nötig, wenn die Datei selbst eine Passphrase bekommt |

- **Keine Umgebungsvariablen** für Passphrasen: sie sind über `/proc`, Absturzberichte und Kindprozesse
  sichtbar. Unter Windows prüft PQKeep die Rechte der Passphrase-Datei nicht (keine ACL-Prüfung ohne
  `unsafe`) – dort selbst für passende Rechte sorgen.
- Eine Passphrase auf dem Server ist schwächer als der Empfänger-Modus: wer den Server übernimmt, hat
  sie. Für Backups daher den Empfänger-Modus bevorzugen.

## Exit-Codes

`0` Erfolg · `1` Fehler · `2` Bedienfehler (auch `--batch` ohne Eingabe) · `3` Entschlüsselung
fehlgeschlagen · `4` Passphrase zu schwach · `5` Ziel existiert · `6` keine Fenster (Kontextmenü) ·
`7` Signatur ungültig (`verify`). Die Exit-Codes sind eine stabile Schnittstelle. Maschinenlesbare
Ausgabe: `--json` bei `encrypt`, `decrypt`, `check`, `inspect`, `verify` (Schema und Beispiele:
[JSON.md](JSON.md)).

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

## Monitoring mit JSON (Linux und Windows)

Die ausführbaren Beispiele [check_backups.sh](../scripts/check_backups.sh) und
[check_backups.ps1](../scripts/check_backups.ps1) prüfen die ausgewählten Dateien mit
`pqkeep --batch check --json --key … --passphrase-file …`. Sie benötigen Bash mit **jq ≥ 1.6**
bzw. **PowerShell ≥ 7.4** (`pwsh`, nicht Windows PowerShell 5.1). Skripte aus einem geprüften
Checkout verwenden und die folgenden Programm-, Schlüssel-, Passphrase- und Backup-Pfade anpassen.
Alle Dateien einer Auswahl müssen mit demselben Schlüssel und dessen Passphrase prüfbar sein;
die Beispiele sind für Empfänger-Backups ohne zusätzliche Faktordatei vorgesehen.

**Linux – als eigenes Bash-Skript speichern und ausführen:**

```bash
#!/usr/bin/env bash
shopt -s nullglob
files=(/mnt/backups/*.pqkf)
exec bash /opt/pqkeep/scripts/check_backups.sh \
  /usr/local/bin/pqkeep /secure/backup.key.json /secure/pass "${files[@]}"
```

`nullglob` erzeugt bei keinem Treffer eine leere Liste; das Monitoring meldet dann einen Fehler.
Eine explizite Soll-Liste, z. B. `files=("/mnt/backups/daily.pqkf" "/mnt/backups/weekly.pqkf")`,
erkennt auch einzelne fehlende Dateien. Ein Glob kennt nur vorhandene Einträge und kann diese
Vollständigkeit nicht garantieren. Auswahl: 1–1000 Quellen pro Aufruf (CLI-Grenze).

**Windows – als eigenes `.ps1`-Skript mit `pwsh -NoProfile -NonInteractive -File` ausführen:**

```powershell
$ErrorActionPreference = 'Stop'
$files = @(Get-ChildItem -LiteralPath 'D:\Backups' -Filter '*.pqkf' -File |
    ForEach-Object { $_.FullName })
& 'C:\Tools\pqkeep\scripts\check_backups.ps1' `
    -Pqkeep 'C:\Tools\pqkeep\pqkeep.exe' `
    -KeyFile 'C:\Secure\backup.key.json' -PassphraseFile 'C:\Secure\pass' -Sources $files
exit $LASTEXITCODE
```

Auch hier ist eine Soll-Liste möglich: `$files = @('D:\Backups\daily.pqkf', 'D:\Backups\weekly.pqkf')`.
`-LiteralPath` und Argumentlisten erhalten Leerzeichen, Unicode und Sonderzeichen. Die Skripte
als eigene Prozesse ausführen, nicht mit `source` bzw. Dot-Sourcing in die eigene Sitzung laden.
Keine Execution-Policy-Umgehung erforderlich; die lokale Richtlinie muss das geprüfte Skript erlauben.

**Auswertung und Exit-Codes:** Beide Beispiele prüfen ausschließlich dokumentierte Felder aus
[JSON.md](JSON.md): `schema`, `command`, `ok`, `exit_code`, `results` und `summary` sowie
`error.code`/`error.kind`. Zusätzliche Felder sind erlaubt. Die Ergebnisquellen müssen zur Auswahl
passen, Zähler und Fehlercodes konsistent sein. Fehler werden mit maskiertem Quellpfad und stabiler
Fehlerart ausgegeben, z. B. `FEHLER / ERROR: "…/daily.pqkf" (decrypt_failed)`, gefolgt von Zählern.
`decrypt_failed` unterscheidet absichtlich nicht zwischen falschem Schlüssel/Passphrase und Manipulation.

- Exit **0** nur bei vollständigem, konsistentem Erfolg. Nicht-null-Exit-Codes von PQKeep werden
  beibehalten; bei mehreren Dateifehlern zählt der erste, nicht der höchste Code.
- Frühe Fehler (z. B. fehlender Schlüssel, eine einzelne fehlende Quelle) können nur `error`
  enthalten. Dann wird der Gesamtaufruf als fehlgeschlagen und die Auswahl als **nicht bestätigt**
  gemeldet; `results` und `summary` werden nicht vorausgesetzt.
- Leere Auswahl/ungültige Skriptargumente → **2**; fehlende Werkzeuge/Startfehler → **1**.
  Fehlendes, ungültiges oder widersprüchliches JSON → Fehler, vorhandener Nicht-null-Prozesscode
  bleibt erhalten, sonst **1**. Argumentfehler von PQKeep können Exit 2 **ohne JSON** liefern.
- Bash fängt den Programmaufruf mit `if` ab, damit `set -e` die Auswertung nicht überspringt.
  PowerShell sichert `$LASTEXITCODE` sofort und behandelt native Fehlercodes im Skript selbst;
  `ConvertFrom-Json`-Fehler werden abgefangen. stderr wird nicht in JSON gemischt.

**Geheimnisse und Grenzen:** Die Skripte lesen die Passphrase-Datei nicht selbst. Sie übergeben
nur deren Pfad; keine Passphrase in Code, Argumenten oder Umgebungsvariablen. Die Datei muss
bereits sicher bereitgestellt sein: UTF-8 ohne BOM, eine Zeile, höchstens 4 KiB, reguläre Datei;
Linux Eigentümerrechte `0600`/`0400`, Windows restriktive ACL (PQKeep prüft diese dort nicht).
Privater Schlüssel und Passphrase gehören auf den vertrauenswürdigen Prüf-/Admin-Rechner.
Keine Klartexte werden aus den Backups geschrieben, die Sandbox bleibt aktiv. Bash speichert nur
die JSON-Antwort kurz in einer privaten temporären Datei (`mktemp`, Modus `0600`) und entfernt sie
beim Beenden; so werden auch ungültige NUL-Bytes erkannt. PowerShell hält die Antwort im Speicher.

Die Statusausgabe enthält ausgewählte Dateipfade; Logs entsprechend schützen. Rohe JSON-Antworten,
stderr und Parserdetails werden nicht ausgegeben. Diese Beispiele prüfen weder Alter noch
Soll-Inventar der Backups und ersetzen keine Wiederherstellungsprobe. Für sehr große Auswahlen
ggf. kleinere Aufrufe und ein Zeitlimit des Schedulers vorsehen; ein Timeout muss als Fehler gelten.
Einbindung in cron, systemd oder Aufgabenplanung separat prüfen; hier wird kein Dienst eingerichtet.

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

### JSON monitoring (Linux and Windows)

Use the executable [Bash example](../scripts/check_backups.sh) with **jq ≥ 1.6**, or the
[PowerShell example](../scripts/check_backups.ps1) with **PowerShell ≥ 7.4** (`pwsh`, not Windows
PowerShell 5.1). Both run `pqkeep --batch check --json --key … --passphrase-file …`.
Use scripts from a reviewed checkout and adapt all executable, key, passphrase and backup paths.
The selection must use the same key and its passphrase; these examples target recipient backups
without an additional factor file.

**Linux – save as a standalone Bash script:**

```bash
#!/usr/bin/env bash
shopt -s nullglob
files=(/mnt/backups/*.pqkf)
exec bash /opt/pqkeep/scripts/check_backups.sh \
  /usr/local/bin/pqkeep /secure/backup.key.json /secure/pass "${files[@]}"
```

`nullglob` makes an unmatched glob an empty list, which fails monitoring. To detect individual
missing backups too, use expected paths, e.g.
`files=("/mnt/backups/daily.pqkf" "/mnt/backups/weekly.pqkf")`. A glob only knows existing entries;
it cannot guarantee completeness. Select 1–1000 sources per invocation (the CLI limit).

**Windows – save as a standalone `.ps1` script and run with `pwsh -NoProfile -NonInteractive -File`:**

```powershell
$ErrorActionPreference = 'Stop'
$files = @(Get-ChildItem -LiteralPath 'D:\Backups' -Filter '*.pqkf' -File |
    ForEach-Object { $_.FullName })
& 'C:\Tools\pqkeep\scripts\check_backups.ps1' `
    -Pqkeep 'C:\Tools\pqkeep\pqkeep.exe' `
    -KeyFile 'C:\Secure\backup.key.json' -PassphraseFile 'C:\Secure\pass' -Sources $files
exit $LASTEXITCODE
```

An expected list also works: `$files = @('D:\Backups\daily.pqkf', 'D:\Backups\weekly.pqkf')`.
Literal paths and argument arrays preserve spaces, Unicode and special characters. Run the
scripts as separate processes; do not source/dot-source them into your session. No execution-policy
bypass is needed; local policy must permit the reviewed script.

**Validation and exit codes:** Only documented [JSON.md](JSON.md) fields are used: `schema`,
`command`, `ok`, `exit_code`, `results`, `summary` and `error.code`/`error.kind`. Additional fields
are allowed. Result sources must match the selection, counts and codes must agree. Failed sources
are printed with escaped paths and stable kinds, e.g. `FEHLER / ERROR: "…/daily.pqkf" (decrypt_failed)`,
followed by counters. `decrypt_failed` deliberately cannot distinguish wrong credentials from tampering.

- **0** only for complete, consistent success. Non-zero PQKeep process codes are preserved;
  for multiple file failures the first code counts, not the highest one.
- Early errors (e.g. missing key or a single missing source) may have only `error`. Report the
  command failure and mark the selection **unverified**, without requiring `results`/`summary`.
- Empty selection/invalid script arguments → **2**; missing tools/start failure → **1**.
  Missing, invalid or inconsistent JSON fails: preserve a non-zero process code, otherwise **1**.
  PQKeep argument errors can return 2 **without JSON**.
- Bash guards the invocation with `if` so `set -e` does not skip parsing. PowerShell immediately
  saves `$LASTEXITCODE`, handles native exit codes locally and catches `ConvertFrom-Json` errors.
  stderr is kept out of the JSON stream.

**Secrets and limits:** The scripts never read the passphrase file themselves; only its path is
passed. No passphrase in code, arguments or environment variables. Provision the file securely
beforehand: UTF-8 without BOM, one line, at most 4 KiB, regular file; Linux owner-only permissions
`0600`/`0400`, restrictive Windows ACL (not checked by PQKeep). Keep the private key and passphrase
on the trusted checking/admin machine. No backup plaintext is written; sandboxing stays enabled.
Bash briefly stores only the JSON response in a private temporary file (`mktemp`, mode `0600`),
removed on exit, so invalid NUL bytes are detected too. PowerShell keeps the response in memory.

Status output contains selected file paths, so protect logs accordingly. Raw JSON, stderr and
parser details are not printed. These examples do not check backup age or expected inventory and
do not replace restore drills. For large selections use smaller invocations and consider a scheduler
timeout; a timeout must count as failure. Review cron/systemd/Task Scheduler integration separately;
these examples do not install a service.

**Unattended options:** `--batch` never prompts (missing input → exit code 2); `--passphrase-file <path>`
reads one line from a regular, non-link file ≤ 4 KiB, on Linux readable by the owner only (`chmod 600`/`400`)
and owned by the calling user or root (systemd credentials); `--passphrase-stdin` reads one line (not
together with `--passphrase-file`); `encrypt --sign-with … --sign-passphrase-file <path>` reads the signing
key's passphrase with the same rules (needed when the file itself gets a passphrase, #286). **No environment variables** for passphrases (visible via `/proc`, crash
reports, child processes). Windows: no permission check of the file (no ACL check without `unsafe`).
A passphrase on the server is weaker than recipient mode – prefer recipient mode for backups.

**Exit codes:** 0 success, 1 error, 2 usage (also `--batch` without input), 3 decryption failed, 4 weak
passphrase, 5 target exists, 6 no windows (context menu), 7 invalid signature – a stable interface.
`--json` for `encrypt`, `decrypt`, `check`, `inspect`, `verify` ([JSON.md](JSON.md)).

**Limits:** no daemon and no own upload (the CLI sandbox forbids network access by design); release
binaries for x86_64 only – build other architectures (ARM servers, Raspberry Pi) from source; check
backups regularly with `pqkeep check` and do a real restore now and then.
