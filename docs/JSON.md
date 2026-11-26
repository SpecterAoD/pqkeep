# Maschinenlesbare Ausgabe (`--json`) und Exit-Codes / Machine-readable output and exit codes

**DE** | [EN](#english)

Für Skripte und Monitoring geben `encrypt`, `decrypt`, `check`, `inspect` und `verify` mit `--json`
ihr Ergebnis als **genau ein JSON-Objekt** auf stdout aus (eine Zeile). Exit-Codes und Schema sind eine **stabile Schnittstelle**: Inkompatible Änderungen gibt es
nur mit neuer Schema-Kennung.

## Exit-Codes

| Code | `kind` | Bedeutung |
|---|---|---|
| 0 | `ok` | Erfolg |
| 1 | `error` | Fehler (z. B. Datei fehlt, keine pqkeep-Datei, Ein-/Ausgabefehler) |
| 2 | `usage` | Bedienfehler (Argumente, fehlende Eingabe mit `--batch`, Faktordatei fehlt/überflüssig) |
| 3 | `decrypt_failed` | Entschlüsselung fehlgeschlagen: falsche Passphrase/Schlüssel/Faktordatei **oder** Manipulation (bewusst nicht unterscheidbar) |
| 4 | `weak_passphrase` | Passphrase zu schwach |
| 5 | `target_exists` | Ziel existiert bereits |
| 6 | `no_windows` | keine Fenster möglich (Kontextmenü) |
| 7 | `invalid_signature` | Signatur ungültig (`verify`) |

## Gemeinsame Hülle (Schema `pqkeep-json/1`)

```json
{"schema":"pqkeep-json/1","command":"check","ok":true,"exit_code":0, …}
```

- `schema`, `command`, `ok` (`true` genau bei Exit-Code 0), `exit_code` (gleich dem echten Exit-Code).
- Scheitert ein Befehl als Ganzes (z. B. Schlüsseldatei fehlt), steht dort zusätzlich
  `"error": {"code": 1, "kind": "error", "message": "…"}`. `code`/`kind` sind stabil, nur
  `message` folgt `--lang`.
- **Ausnahme:** Fehler in den Argumenten selbst (unbekannte Option, fehlender Pfad) meldet der
  Parser als Text auf stderr, Exit-Code 2 – ohne JSON.
- Die Passphrase-Abfrage läuft weiter über das Terminal (bzw. `--passphrase-stdin`,
  `--passphrase-file`); stdout enthält nur das JSON.
- Feldreihenfolge ist nicht festgelegt; unbekannte Felder bitte ignorieren (neue Felder können
  hinzukommen, ohne dass sich die Schema-Kennung ändert).
- **Keine Geheimnisse** und keine Pfade aus dem Inhalt verschlüsselter Archive – nur die angegebenen
  Dateien, Zähler und Kopfdaten.

## `check --json`

```json
{"schema":"pqkeep-json/1","command":"check","ok":false,"exit_code":3,
 "results":[{"source":"a.pqkf","ok":true,"files":1,"directories":0,"bytes":5},
            {"source":"b.pqkf","ok":false,"error":{"code":3,"kind":"decrypt_failed","message":"…"}}],
 "summary":{"total":2,"ok":1,"failed":1}}
```

`exit_code` ist der erste Fehler der Liste (wie ohne `--json`). Erfolgreiche Einträge haben zusätzlich
`signer`: Schlüssel-ID des **geprüften** Absenders bei signierten Dateien (Format v3, #44), sonst `null`.

## `inspect --json`

- Öffentlicher Schlüssel: `type: "public_key"`, `algorithm`, `key_id`, `created_utc`, `metadata`
  (`name`, `organization`, `company`, `department`, `account_type`; fehlende Werte `null`).
- Schlüsseldatei: `type: "key_file"`, dieselben Felder plus `kdf` (`memory_kib`, `iterations`,
  `parallelism`), `factor_required`, `warnings` (Texte nach `--lang`).
- Verschlüsselte Datei: `type: "encrypted_file"`, `format_version` (1, 2 oder 3), `content`
  (`file`/`directory`), `slots`: je Zugang `{"kind":"passphrase","kdf":{…},"factor_required":…}`
  oder `{"kind":"recipient","algorithm":"ML-KEM-768","recipient_id":"…"}`; `signer`: bei v3
  `{"key_id":"…","verified":false}` (nur aus dem Header, **ungeprüft**), sonst `null`.
- Immer zusätzlich `file` (der angegebene Pfad).

## `verify --json`

Gültig: `"valid": true`, `signer` (`key_id`, `name`), `created_utc` (Angabe des Signierers, nicht
vertrauenswürdig), Exit 0. Ungültig: `"valid": false`, `signer_matches` (stammt die Signatur vom
angegebenen Schlüssel?), Exit 7. Immer zusätzlich `file`.

## `encrypt --json` und `decrypt --json`

```json
{"schema":"pqkeep-json/1","command":"encrypt","ok":false,"exit_code":5,
 "results":[{"source":"a.txt","target":"a.txt.pqkf","ok":true,"files":1,"directories":0,"bytes":6,"skipped":0},
            {"source":"b.txt","target":"b.txt.pqkf","ok":false,"error":{"code":5,"kind":"target_exists","message":"…"}}],
 "summary":{"total":2,"ok":1,"failed":1}}
```

- `results`: je erzeugtem Ziel `source`, `target`, `ok`, dann `files`, `directories`, `bytes`,
  `skipped` (Anzahl übersprungener Einträge wie Symlinks – ohne Pfade), `signer` (beim
  Entschlüsseln: Schlüssel-ID des geprüften Absenders oder `null`; beim Verschlüsseln `null`) oder `error`.
- Beim Container (`encrypt` mit mehreren Quellen und `--out`) ist `source` eine **Liste**; bei
  `encrypt --stdin` ist `source` `"-"` (`--json` nicht zusammen mit `--stdout`).
- Mehrere Einträge gibt es nur bei `encrypt --each` und `decrypt` mit mehreren Dateien; dort läuft
  jede Datei, auch wenn eine scheitert, und `exit_code` ist der erste Fehler.
- Scheitert der Befehl als Ganzes (eine Quelle, Container, zu schwache oder falsche Passphrase,
  Ziel existiert bei einer Quelle), gibt es nur `error`, keine `results`.

---

## English

With `--json`, `encrypt`, `decrypt`, `check`, `inspect` and `verify` print their result as **exactly one JSON object** on
stdout (one line); so do `encrypt` and `decrypt`. Exit codes and schema are a
**stable interface**: incompatible changes only come with a new schema identifier.

**Exit codes:** 0 `ok`; 1 `error` (e.g. file missing, not a pqkeep file, I/O); 2 `usage` (arguments,
missing input with `--batch`, factor file missing/superfluous); 3 `decrypt_failed` (wrong
passphrase/key/factor file **or** tampering, deliberately indistinguishable); 4 `weak_passphrase`;
5 `target_exists`; 6 `no_windows` (context menu); 7 `invalid_signature` (`verify`).

**Envelope (schema `pqkeep-json/1`):** `schema`, `command`, `ok` (`true` exactly for exit code 0),
`exit_code` (equal to the real exit code). If a command fails as a whole, there is also
`"error": {"code", "kind", "message"}`; `code`/`kind` are stable, only `message` follows `--lang`.
**Exception:** errors in the arguments themselves are reported by the parser as text on stderr with
exit code 2, without JSON. The passphrase prompt still uses the terminal (or `--passphrase-stdin`,
`--passphrase-file`); stdout contains only the JSON. Field order is not fixed; please ignore unknown
fields (new fields may be added without changing the schema identifier). **No secrets** and no paths
from encrypted archive contents – only the given files, counters and header data.

**`check --json`:** `results` (per source: `source`, `ok`, then `files`, `directories`, `bytes`,
`signer` – key ID of the **verified** sender of a signed file (format v3, #44) or `null` – or `error`)
and `summary` (`total`, `ok`, `failed`); `exit_code` is the first error of the list.

**`inspect --json`:** public key (`type: "public_key"`, `algorithm`, `key_id`, `created_utc`,
`metadata` with `null` for missing values); key file (`type: "key_file"`, same fields plus `kdf`,
`factor_required`, `warnings`); encrypted file (`type: "encrypted_file"`, `format_version` 1–3, `content`,
`slots` with `kind` `passphrase` – `kdf`, `factor_required` – or `recipient` – `algorithm`,
`recipient_id`; `signer` for v3 `{"key_id":…,"verified":false}` – header only, **unverified** – else
`null`). Always `file` as well.

**`verify --json`:** valid → `"valid": true`, `signer` (`key_id`, `name`), `created_utc` (claimed by
the signer, not trusted), exit 0; invalid → `"valid": false`, `signer_matches`, exit 7. Always `file`.

**`encrypt --json`, `decrypt --json`:** `results` per created target (`source`, `target`, `ok`, then
`files`, `directories`, `bytes`, `skipped` – a count, no paths – or `error`) and `summary`. For a
container (`encrypt` with several sources and `--out`) `source` is a **list**; with `encrypt --stdin` it is
`"-"` (`--json` not together with `--stdout`). Several entries only
with `encrypt --each` and `decrypt` with several files; every file is processed even if one fails and
`exit_code` is the first error. If the command fails as a whole (one source, container, weak or wrong
passphrase, existing target with one source) there is only `error`, no `results`.


## Archivliste: separates Schema / Archive listing: separate schema

DE: Ausschließlich der ausdrücklich aufgerufene Befehl `list --json` verwendet `pqkeep-list/1`.
Er zeigt bewusst vertrauliche Archivpfade, erst nach vollständiger Containerprüfung. Alle oben
beschriebenen `pqkeep-json/1`-Befehle behalten ihre Verträge und zeigen keine Archiv-Inhaltspfade.
Erfolgsfelder: `source`, `authentication: "container_integrity"`, `entries` (je `kind`, `path`,
`bytes`; Ordner `bytes: null`) und `summary` (`files`, `directories`, `bytes`), plus gemeinsame
Hülle. Fehler: nur Hülle/`error`, keine Einträge oder Authentisierungszusage; auch frühe
Datei-/Sandboxfehler verwenden das List-Schema. Argumentparserfehler bleiben stderr/Exit2.
Bei Ausgabefehlern ist der echte Prozess-Exit maßgeblich: ein bereits geschriebenes Erfolgsobjekt
kann nicht zurückgenommen werden. Immer Objekt und Prozess-Exit prüfen, kein zweites JSON wird
angehängt. Keine Absenderidentitätszusage. Grenzen und Anleitung: [LIST.md](LIST.md).

EN: Only the explicit `list --json` command uses `pqkeep-list/1`, deliberately revealing archive
paths after full verification. Existing `pqkeep-json/1` commands and their no-archive-path contract
remain unchanged. Success adds source, authentication=container_integrity, entries (kind/path/bytes,
null bytes for directory) and summary (files/directories/bytes), plus the common envelope.
Errors have only envelope/error, no entries/authentication claim; early file/sandbox errors use
this schema too. Argument parser errors remain stderr/exit2. For output errors the actual process
exit is authoritative: an already written success object cannot be withdrawn. Check both object
and process status; no second JSON object is appended. No sender identity claim. See LIST.md.
