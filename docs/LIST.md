# Archivliste ohne Extraktion / Archive listing without extraction

## Deutsch

`pqkeep list DATEI.pqkf` zeigt auf ausdrücklichen Aufruf Namen, Pfade, Typen und Dateigrößen
nach vollständiger Prüfung des Containers. Dateiinhalte werden gestreamt geprüft und verworfen.
Das Programm legt dafür keine Ausgabedatei und keinen temporären Klartext-Spool an.

```
pqkeep list backup.pqkf
pqkeep list backup.pqkf --key backup.key.json --json
pqkeep --batch --passphrase-file /geschuetzt/passphrase list backup.pqkf --json
```

Passphrases werden wie bei `decrypt` verdeckt, über `--passphrase-stdin` oder eine geschützte
Passphrase-Datei gelesen; niemals als Argument oder Umgebungsvariable. `--factor-file` ergänzt
bei Bedarf den Zugang oder die geschützte Schlüsseldatei. Kein stilles Ignorieren eines fehlenden
oder überflüssigen Faktors. Eine Quelle pro Aufruf; kein `--out`, keine Extraktion.

**Die Liste enthält vertrauliche Metadaten.** Sie gehört nur in ausdrücklich gewählte Ausgaben,
nicht in automatische Logs. Wer stdout umleitet, speichert diese Metadaten selbst als Klartext.
Textausgabe zitiert Namen; die Spalten sind Typ, Bytes (`-` beim Ordner), Pfad. Die Zusammenfassung
enthält Dateien, Ordner, Dateibytes. Die Reihenfolge entspricht dem Archiv. Leere Ordner und leere
Dateien werden unterschieden.

**Geprüfte Containerintegrität bedeutet keine Absenderidentität.** Jeder mit einem öffentlichen
Empfängerschlüssel kann einen gültigen Container erstellen. Absender-Signaturen bleiben #44;
die Liste ersetzt weder Signaturprüfung noch Backup-Manifest oder Restore-Probe.

Alle Blöcke, Inhaltsprüfsummen, Pfade, Konflikte, Eintragszahl, Archivende und STREAM-Ende werden
geprüft, bevor die Bibliothek ein Ergebnis liefert und die CLI Namen ausgibt. Bei falschem Zugang,
Manipulation, Lesefehler oder Listengrenze gibt es keine Teilliste. stdout ist kein atomarer
Transport: Nach erfolgreicher Prüfung kann ein Schreib-/Flush-Fehler die Ausgabe verkürzen;
der Exit-Code ist dann ungleich null. Bei JSON müssen Aufrufer das vollständige Objekt **und**
den Exit-Code prüfen. Bei einem späteren Ausgabefehler können `ok`/`exit_code` im bereits
geschriebenen Objekt noch den erfolgreichen Prüfschritt beschreiben; der echte Prozess-Exit
zeigt dann den Übertragungsfehler. Es wird kein zweites JSON-Objekt angehängt.

### Grenzen und Kompatibilität

- Nur vorhandene v1/v2-Datei-/Verzeichniscontainer. Keine Formatmigration, kein neuer Stream-Typ.
- Listengrenzen: **10.000 Einträge und 16 MiB summierte UTF-8-Pfadbytes**, zusätzlich zu bestehenden
  Pfadregeln. Bei Überschreitung Fehler, kein Abschneiden oder Disk-Fallback. `check`/`decrypt`
  behalten ihre bisherigen Grenzen und können größere gültige Archive weiter prüfen/entpacken.
- Inhaltspuffer sind gestreamt, Metadaten und Prüfstrukturen benötigen weiteren begrenzten Speicher;
  16 MiB ist keine Garantie über den gesamten Prozessspeicher. Der gesamte Inhalt muss gelesen
  werden; eine Liste großer Archive kann entsprechend lange dauern.
- Bestehende Source-Pfad-/TOCTOU-, Argon2-, Speicherhärtungs- und Plattformgrenzen gelten weiter.
  Linux: vorhandene Sandbox mit ausschließlich notwendigen Lesepfaden; Windows: keine gleichwertige
  Sandbox oder neue ACL-/Antivirus-Garantie. Keine Wiederaufnahme oder temporäre Datenübernahme.
- Exit-Codes wie bisher: 0 Erfolg, 1 allgemeiner Fehler/Listengrenze, 2 Bedienfehler/Faktorbedarf,
  3 falscher Zugang oder kryptografische Manipulation. Parserfehler bleiben entsprechend klassifiziert.

### JSON-Vertrag

Nur `list --json` verwendet **`pqkeep-list/1`**, weil es bewusst Archivpfade zeigt. Die bisherigen
Befehle behalten `pqkeep-json/1` und zeigen weiterhin keine Archiv-Inhaltspfade. Ein Objekt/eine
Zeile; gemeinsame Felder `schema`, `command`, `ok`, `exit_code`. Erfolg enthält `source`
(Argumentpfad), `authentication: "container_integrity"`, `entries` und `summary`.
Ein Eintrag hat `kind: "file" | "directory"`, `path` und `bytes` (Zahl oder `null` beim Ordner).
Bei Fehlern nur die gemeinsame Hülle und `error: {code, kind, message}`; keine `entries`, keine
inneren Archivnamen und keine Erfolgs-/Authentisierungszusage. Auch frühe Datei-/Sandboxfehler
verwenden das List-Schema. Fehler der Argumentparser selbst: stderr/Exit2 ohne JSON wie bisher.
Feldreihenfolge ist unerheblich; unbekannte Felder ignorieren. Der allgemeine Core-/Protokollvertrag
bleibt #98, eine GUI bleibt #63. Entwurf/Testzuordnung: [LIST_DESIGN.md](security/LIST_DESIGN.md).

## English

`pqkeep list FILE.pqkf` explicitly requests archive names, paths, kinds and sizes after complete
container verification. Payload is streamed, checked and discarded; no output file or temporary
plaintext spool is created. Use a hidden prompt, `--passphrase-stdin` or a protected global
`--passphrase-file` as with `decrypt`; never put credentials in arguments/environment.
`--factor-file` is required when appropriate for the access/key; missing or unused factors fail.
One source per invocation, no `--out` or extraction. Examples are shown above.

**The listing is confidential metadata.** Do not automatically log it; redirecting stdout stores
metadata in plaintext under the caller's control. Text quotes paths, with kind/bytes/path columns
(`-` for directory), then file/directory/byte totals; archive order is preserved. Empty files and
empty directories are distinct.

**Container integrity is not sender identity.** Anyone holding the recipient public key can build
a valid container. Embedded sender signatures remain #44; listing is no backup manifest or restore
verification. No names are returned/printed until all chunks, file checksums, paths/conflicts,
entry count, archive end and STREAM end are verified. Access/authentication/read/limit failure
returns no partial list. stdout is not atomic: a later write/flush failure may truncate already
verified output and must return nonzero. JSON consumers check both complete parsing and exit code.
An already written object can describe successful verification in ok/exit_code even when a later
output failure makes the actual process exit nonzero; no second object is appended.

Only current v1/v2 file/directory containers, no migration/stream type. Listing caps: **10,000 entries,
16 MiB aggregate UTF-8 path bytes**, plus existing path rules. Exceeding either fails without
truncation or disk fallback. Existing `check`/`decrypt` limits remain unchanged. Payload buffering
is streamed; metadata/validation structures use additional bounded memory, so 16 MiB is not a
whole-process memory guarantee. All payload must be read. Existing source/TOCTOU, KDF/memory and
OS limits apply. Linux reuses read-only sandbox grants; Windows gains no equivalent sandbox,
ACL/antivirus guarantee, resume protocol or stale-temp recovery.

Exit codes remain 0 success, 1 general/limit error, 2 usage/factor requirements, 3 incorrect access
or cryptographic tampering; structural/parser errors retain their classification.
Only `list --json` uses **`pqkeep-list/1`**; existing `pqkeep-json/1` operations keep their no-archive-
paths contract. Exactly one object/line with common schema/command/ok/exit_code fields. Success
adds source (argument path), authentication=container_integrity, entries and summary. Each entry
has kind=file|directory, path and bytes (null for directory). Errors have only common fields and
error={code,kind,message}, without entries/internal names/success-authentication claims. Early
file/sandbox errors use the same list schema; argument parser errors remain stderr/exit2 without
JSON. Ignore field order/unknown fields. General API contracts remain #98, GUI remains #63.
See the linked bilingual design for stable test mappings and limits.
