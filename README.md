# PQC KeyForge

**DE** | [EN](#english)

> Status: in Entwicklung (Schritte 0–5: Kern, Passphrasen, Container, Datei-/Ordnerverschlüsselung, CLI, REST-API). Noch keine veröffentlichte Version – bitte noch nicht für echte Geheimnisse verwenden. Die verbindliche Spezifikation liegt in [`docs/SPEC.md`](docs/SPEC.md), der Fahrplan in [`docs/ROADMAP.md`](docs/ROADMAP.md).

Sichere, speichersichere Anwendung (Windows und Linux) in reinem Rust zur Erzeugung und Verwaltung von Post-Quanten-Schlüsseln (ML-KEM nach FIPS 203, ML-DSA nach FIPS 204) und symmetrischen AES-256-Schlüsseln. Private Schlüssel werden mit AES-256-GCM verschlüsselt, der Schlüssel wird per Argon2id aus einer starken Passphrase abgeleitet. Bedienung per CLI und REST-API, keine Telemetrie, keine ausgehenden Netzwerkverbindungen.

- Lizenz: [Apache License 2.0](LICENSE)
- Sicherheit melden: siehe [`SECURITY.md`](SECURITY.md)
- Mitwirken: siehe [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Code-Signierung: siehe [`CODE_SIGNING_POLICY.md`](CODE_SIGNING_POLICY.md)

Hinweis: Die verwendeten Krypto-Bibliotheken sind nicht FIPS-140-validiert. Das Projekt ist bisher nicht extern auditiert.

## Kurzanleitung

```
keyforge                                   # interaktives Menü (im Terminal)
keyforge passphrase                        # sichere Passphrase erzeugen
keyforge generate --name "Max Muster" --out max.key.json
keyforge export max.key.json --out max.pub.json   # öffentlichen Schlüssel weitergeben
keyforge encrypt bericht.pdf               # mit Passphrase
keyforge encrypt Ordner --to anna.pub.json # für eine Empfängerin (ML-KEM)
keyforge decrypt Ordner.pqkf --key anna.key.json
keyforge help security                     # Hilfethemen: passphrase, algorithms, container, files, security, verify
keyforge serve --init-token --token-file api.token   # API-Token einmal anzeigen, nur Hash speichern
keyforge serve --token-file api.token      # REST-API auf 127.0.0.1:8787 (Bearer-Token), siehe docs/API.md
```
Sprache: `--lang de|en` (Standard: Systemsprache). Passphrasen nie als Argument, nur verdeckt oder über `--passphrase-stdin`.

---

## English

> Status: in development (steps 0–5: core, passphrases, container, file/directory encryption, CLI, REST API). No published release yet – please do not use for real secrets yet. The binding specification is in [`docs/SPEC.md`](docs/SPEC.md) (German), the roadmap in [`docs/ROADMAP.md`](docs/ROADMAP.md).

A secure, memory-safe application (Windows and Linux) written in pure Rust to generate and manage post-quantum keys (ML-KEM per FIPS 203, ML-DSA per FIPS 204) and symmetric AES-256 keys. Private keys are encrypted with AES-256-GCM; the key is derived from a strong passphrase using Argon2id. Usable via CLI and REST API, with no telemetry and no outbound network connections.

- License: [Apache License 2.0](LICENSE)
- Report a vulnerability: see [`SECURITY.md`](SECURITY.md)
- Contributing: see [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Code signing: see [`CODE_SIGNING_POLICY.md`](CODE_SIGNING_POLICY.md)

Note: the cryptographic libraries used are not FIPS 140 validated. The project has not been externally audited.

## Quick start

```
keyforge                                   # interactive menu (in a terminal)
keyforge passphrase                        # generate a secure passphrase
keyforge generate --name "Jane Doe" --out jane.key.json
keyforge export jane.key.json --out jane.pub.json # share your public key
keyforge encrypt report.pdf                # with a passphrase
keyforge encrypt folder --to anna.pub.json # for a recipient (ML-KEM)
keyforge decrypt folder.pqkf --key anna.key.json
keyforge help security                     # topics: passphrase, algorithms, container, files, security, verify
keyforge serve --init-token --token-file api.token   # show API token once, store hash only
keyforge serve --token-file api.token      # REST API on 127.0.0.1:8787 (bearer token), see docs/API.md
```
Language: `--lang de|en` (default: system language). Passphrases are never arguments, only hidden or via `--passphrase-stdin`.
