# REST-API / REST API

Deutsch zuerst, [English below](#english).

## Überblick

`keyforge serve` startet eine kleine HTTP-API (HTTP/1.1, JSON). Sie ist für den Zugriff
**vom selben Rechner** gedacht (Standard `127.0.0.1:8787`). Der Server speichert nichts:
erzeugte Schlüssel werden nur in der Antwort zurückgegeben. Datei- und Ordnerverschlüsselung
gibt es bewusst **nicht** über die API (SPEC Abschnitt 4a).

Die API ist ein Cargo-Feature (`api`, standardmäßig an). Mit
`cargo build --no-default-features` entsteht eine reine CLI ohne Netzwerkcode.

## Start und Token

```sh
keyforge serve --init-token --token-file api.token   # Token einmal anzeigen, nur Hash speichern
keyforge serve --token-file api.token                # API auf 127.0.0.1:8787
keyforge serve --token-file api.token --bind 127.0.0.1:9000
```

- Das Token (`kf1_…`, 256 Bit Zufall) wird **nur beim Anlegen** angezeigt. Die Datei enthält
  nur dessen SHA3-256-Hash (Linux: Rechte `0600`). `--force` ersetzt eine vorhandene Datei; das
  alte Token wird damit ungültig.
- Tokens aus Umgebungsvariablen werden bewusst nicht unterstützt (landen leicht in Logs und
  Prozesslisten).
- Jede Anfrage außer `/v1/health` braucht `Authorization: Bearer <Token>`.
- Beenden mit Strg+C.

### Zugriff über das Netz

Andere Adressen als localhost (z. B. `--bind 0.0.0.0:8787`) werden nur mit `--allow-remote`
akzeptiert und erzeugen eine Warnung. **TLS ist nicht eingebaut** – Token und Passphrasen
würden sonst im Klartext übertragen. Für Netzzugriff einen Reverse Proxy mit TLS (z. B. Caddy,
nginx) davorschalten und die API selbst auf `127.0.0.1` lassen. Hinweis: Hinter einem Proxy
sehen alle Anfragen wie eine Adresse aus; Rate-Limit und Sperre gelten dann für alle gemeinsam.
`X-Forwarded-For` wird bewusst ignoriert (fälschbar).

## Endpunkte

### `GET /v1/health`

Ohne Anmeldung. Antwort `200 {"status":"ok"}` – bewusst ohne Versionsangabe.

### `POST /v1/validate`

Prüft eine Passphrase (gleiche Regeln wie `keyforge validate`).

```json
{ "passphrase": "…", "lang": "de" }
```

`lang` ist optional (`de` Standard, `en`). Antwort `200`:

```json
{ "strong": false, "entropy_bits": 41,
  "reasons": [ { "code": "too_short", "message": "zu kurz: 8 Zeichen, mindestens 16" } ] }
```

Jede Antwort – auch Fehler – wird auf mindestens **300 ms** aufgefüllt, damit die Antwortzeit
nichts über den Aufbau der Passphrase verrät.

Feste Codes: `too_short`, `too_long`, `missing_lowercase`, `missing_uppercase`, `missing_digit`,
`missing_special`, `control_character`, `repetition`, `sequence`, `keyboard_pattern`,
`blocklisted`, `dictionary_words`, `low_entropy`.

### `POST /v1/generate`

Erzeugt einen Schlüssel und schützt ihn mit der Passphrase (Argon2id).

```json
{
  "passphrase": "…",
  "algorithm": "ml-kem-768",
  "profile": "standard",
  "lang": "de",
  "metadata": { "name": "Max Muster", "organization": "Beispiel AG",
                "company": null, "department": null, "account_type": null }
}
```

- `algorithm` (optional): `ml-kem-512`, `ml-kem-768` (Standard), `ml-kem-1024`, `ml-dsa-44`,
  `ml-dsa-65`, `ml-dsa-87`, `aes-256` – nur Kleinschreibung.
- `profile` (optional): `standard` (256 MiB, Standard) oder `hardened` (1 GiB).
- `metadata.name` ist Pflicht; Grenzen wie in der CLI. Metadaten werden **nicht verschlüsselt**,
  nur gegen Änderung geschützt.

Antwort `201`:

```json
{ "algorithm": "ML-KEM-768", "key_id": "…",
  "key_file": { … }, "public_key_file": { … } }
```

`key_file` ist der Inhalt einer `*.key.json` (siehe [FORMAT.md](FORMAT.md)), `public_key_file`
der einer `*.pub.json` (bei `aes-256`: `null`). Beides als Datei speichern, z. B. mit `jq`:

```sh
curl -s -H "Authorization: Bearer $(cat token.txt)" -H 'Content-Type: application/json' \
  --data @anfrage.json http://127.0.0.1:8787/v1/generate > antwort.json
jq .key_file antwort.json > max.key.json
jq .public_key_file antwort.json > max.pub.json
```

Schwache Passphrase → `422`:

```json
{ "error": "weak_passphrase", "entropy_bits": 41, "reasons": [ … ] }
```

## Fehler

Fehler sind bewusst generisch: `{"error":"<code>"}`, nie mit Eingabedaten.

| Status | Code | Bedeutung |
|---|---|---|
| 400 | `bad_request` | Ungültiges JSON, unbekannte/fehlende Felder, ungültige Werte |
| 401 | `unauthorized` | Token fehlt oder falsch (`WWW-Authenticate: Bearer`) |
| 404 | `not_found` | Unbekannter Pfad |
| 405 | `method_not_allowed` | Falsche Methode |
| 413 | `payload_too_large` | Body > 64 KiB |
| 415 | `unsupported_media_type` | `Content-Type` nicht `application/json` |
| 422 | `weak_passphrase` | Passphrase zu schwach (nur `/v1/generate`) |
| 429 | `too_many_requests` | Rate-Limit überschritten oder Client gesperrt |
| 500 | `internal` | Interner Fehler (ohne Details) |
| 503 | `busy` | Speicherbudget für Argon2 ausgeschöpft (`Retry-After: 5`) |

## Grenzen und Schutzmaßnahmen

| Maßnahme | Wert |
|---|---|
| Body-Größe | 64 KiB |
| Zeit für die Header (Slowloris) | 10 s |
| Höchstdauer je Verbindung | 30 s |
| Anfragen je Verbindung | 1 (kein Keep-Alive) |
| Gleichzeitige Verbindungen | 64 (weitere werden sofort geschlossen) |
| Rate-Limit | 60 Anfragen/Minute je Client (IPv6: je /64-Netz) |
| Sperre | 15 min nach 5 falschen Tokens |
| Argon2-Speicherbudget | 1024 MiB gesamt: 4 × `standard` oder 1 × `hardened` gleichzeitig, sonst sofort 503 |
| Sandbox (Linux) | Nach dem Binden: kein Dateizugriff (Landlock), keine neuen Sockets, kein `execve`/`fork`/`ptrace` (Seccomp); `--no-sandbox` nur zur Fehlersuche (mit Warnung) |
| Antwort-Header | `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`; kein CORS |

## Bekannte Grenzen

- Kein eingebautes TLS (siehe oben).
- Puffer von hyper/axum, in denen der Request-Body liegt, können nicht genullt werden; die
  Passphrase selbst wird nach dem Einlesen genullt (siehe [MEMORY_HARDENING.md](MEMORY_HARDENING.md)).
- `hardened` kann auf langsamen Rechnern länger als 30 s dauern; die Verbindung wird dann
  geschlossen, die Berechnung läuft zu Ende und hält so lange ihr Speicherbudget.
- Keine Protokollierung von Anfragen (auch keine Zugriffs-Logs).

---

## English

`keyforge serve` starts a small HTTP API (HTTP/1.1, JSON) meant for access **from the same
machine** (default `127.0.0.1:8787`). The server stores nothing: generated keys are only returned
in the response. File and directory encryption is deliberately **not** available via the API.
The API is a cargo feature (`api`, on by default); `cargo build --no-default-features` builds a
pure CLI without network code.

**Start and token:** `keyforge serve --init-token --token-file api.token` shows the token
(`kf1_…`, 256 random bits) **once** and stores only its SHA3-256 hash (Linux mode `0600`);
`--force` replaces an existing file and invalidates the old token. Then
`keyforge serve --token-file api.token [--bind 127.0.0.1:9000]`. Every request except
`/v1/health` needs `Authorization: Bearer <token>`. Tokens from environment variables are
deliberately unsupported. Stop with Ctrl+C.

**Network access:** non-loopback addresses require `--allow-remote` and print a warning. **No
built-in TLS** – put a reverse proxy with TLS in front and keep the API on `127.0.0.1`. Behind a
proxy all requests share one address, so rate limit and lockout apply to all of them together;
`X-Forwarded-For` is ignored on purpose (spoofable).

**Endpoints:**

- `GET /v1/health` – no authentication, `200 {"status":"ok"}`, deliberately without version.
- `POST /v1/validate` – body `{"passphrase": "…", "lang": "de"|"en"}` (`lang` optional, default
  `de`); answer `200 {"strong", "entropy_bits", "reasons": [{"code", "message"}]}`. Every response,
  errors included, is padded to at least **300 ms** so timing reveals nothing about the
  passphrase. Reason codes are listed in the German section.
- `POST /v1/generate` – body `{"passphrase", "algorithm"?, "profile"?, "lang"?, "metadata":
  {"name", "organization"?, "company"?, "department"?, "account_type"?}}`; algorithms as in the
  CLI (lowercase, default `ml-kem-768`), profile `standard` (256 MiB, default) or `hardened`
  (1 GiB). Answer `201 {"algorithm", "key_id", "key_file", "public_key_file"}` – the contents
  of `*.key.json` and `*.pub.json` (`null` for `aes-256`). Metadata is **not encrypted**, only
  integrity-protected. Weak passphrase → `422 {"error":"weak_passphrase", "entropy_bits",
  "reasons"}`.

**Errors** are generic `{"error":"<code>"}` without input data; status codes and codes as in the
table above (400 `bad_request`, 401 `unauthorized`, 404, 405, 413, 415, 422, 429
`too_many_requests`, 500 `internal`, 503 `busy` with `Retry-After: 5`).

**Limits:** body 64 KiB; header read 10 s; 30 s per connection; one request per connection; 64
concurrent connections (more are closed immediately); 60 requests/minute per client (IPv6 per
/64); lockout for 15 min after 5 wrong tokens; Argon2 memory budget 1024 MiB in total (4 ×
`standard` or 1 × `hardened` at a time, otherwise 503 immediately); security headers as listed
above; no CORS. Sandbox (Linux): after binding no file access (Landlock), no new sockets, no
`execve`/`fork`/`ptrace` (seccomp); `--no-sandbox` only for troubleshooting (with a warning).

**Known limitations:** no built-in TLS; hyper/axum buffers holding the request body cannot be
zeroed (the passphrase itself is zeroed after reading); `hardened` may exceed 30 s on slow
machines – the connection is then closed while the computation finishes and holds its budget;
no request logging at all.
