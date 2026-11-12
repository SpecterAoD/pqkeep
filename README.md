# PQKeep

**Post-quantum keys, kept simple and documented.**

[English](#english) | [Deutsch](#deutsch)

> **Status: beta (`v0.1.0-beta.1`) – not audited, not FIPS 140 validated.**
> File formats and options may still change before 1.0. Please do not use PQKeep to protect
> secrets you cannot afford to lose. See [Status and limitations](#status-and-limitations).

---

## English

PQKeep is a command-line tool with a local REST API, written in Rust, for generating and storing
post-quantum keys – **ML-KEM** (FIPS 203) and **ML-DSA** (FIPS 204) – and AES-256 keys, and for
encrypting files and directories with a passphrase or for the holder of an ML-KEM public key.
Private keys are stored in a documented JSON container, encrypted with **AES-256-GCM** under a key
derived from a strong passphrase with **Argon2id**. It runs on Windows and Linux, sends no
telemetry and opens no outgoing network connections.

### Features

- **Keys:** ML-KEM-512/768/1024, ML-DSA-44/65/87 and AES-256; metadata (name, organisation …)
  integrity-protected; public key export with fingerprint.
- **File and directory encryption** (`.pqkf`): passphrase mode or recipient mode (ML-KEM-768),
  streaming AEAD, safe extraction rules, no partial output.
- **Signatures:** `sign`/`verify` with ML-DSA-87 over the file's SHA3-512 (detached `.pqsig`;
  not an eIDAS signature).
- **Passphrases:** strength check with reasons (Unicode NFKC, patterns, word lists), generator.
- **Interfaces:** CLI with interactive menu and bilingual help (English/German); local REST API
  (`/v1/generate`, `/v1/validate`, `/v1/health`) bound to 127.0.0.1 by default.
- **Hardening:** no own `unsafe` code, memory locking, core dumps disabled, zeroisation (best
  effort); on Linux a Landlock and seccomp sandbox per command.

### Quick start

Download the archive for your platform from the [releases page](https://github.com/SpecterAoD/pqkeep/releases),
[verify it](#verifying-a-release) and unpack it. Linux builds need glibc ≥ 2.35 (e.g. Ubuntu 22.04+,
Debian 12+, Linux Mint 21+). Releases after v0.1.0-beta.1 also provide Linux ARM64 (64-bit) archives
and Debian packages (`.deb`) for amd64 and arm64 – see [installation](docs/INSTALL.md).
Alternatively build from source (Rust ≥ 1.88):

```
git clone https://github.com/SpecterAoD/pqkeep
cd pqkeep
cargo build --release --locked        # binary: target/release/pqkeep
```

```
pqkeep                                   # interactive menu (in a terminal)
pqkeep generate                          # guided: purpose, strength, details, passphrase
pqkeep passphrase                        # generate a secure passphrase
pqkeep generate --name "Jane Doe" --out jane.key.json
pqkeep export jane.key.json --out jane.pub.json   # share your public key
pqkeep encrypt report.pdf                # with a passphrase
pqkeep encrypt folder --to anna.pub.json # for a recipient (ML-KEM)
pqkeep decrypt folder.pqkf --key anna.key.json
pqkeep sign --key anna.key.json contract.pdf      # → contract.pdf.pqsig (ML-DSA-87 key)
pqkeep verify --pub anna.pub.json contract.pdf    # [VERIFIED] / [INVALID]
pqkeep help security                     # topics: passphrase, algorithms, container, files, security, verify
pqkeep serve --init-token --token-file api.token   # show API token once, store hash only
pqkeep serve --token-file api.token      # REST API on 127.0.0.1:8787 (bearer token)
pqkeep integrate install                 # right-click menu in Nemo/Nautilus/Dolphin/Thunar (Linux)
```

Language: `--lang en|de` (default: system language). Passphrases are never command-line
arguments – only a hidden prompt, `--passphrase-stdin` or `--passphrase-file` (servers: see
[`docs/SERVER.md`](docs/SERVER.md)).

### Security at a glance

- Cryptography from the RustCrypto project (`ml-kem`, `ml-dsa`, `aes-gcm`, `argon2`); no own
  primitives.
- Known-answer tests against NIST ACVP (ML-KEM, ML-DSA), Wycheproof (AES-GCM) and RFC 9106
  (Argon2); property-based tests for parsers.
- Container and file formats authenticate their full header; strict parsing, downgrade checks.
- Supply chain: locked dependencies, `cargo-deny` and RustSec checks in CI, weekly audit, signed
  commits, CI on Linux and Windows.
- Threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) · Sandbox:
  [`docs/SANDBOX.md`](docs/SANDBOX.md) · Report a vulnerability: [`SECURITY.md`](SECURITY.md)

### Status and limitations

- **Development status:** first beta (`v0.1.0-beta.1`), active development. Formats and options
  may change before 1.0. Changes: [`CHANGELOG.md`](CHANGELOG.md).
- **Audit status:** no external security audit has been performed. An independent review is
  planned before 1.0.
- **Validation status:** the libraries implement FIPS 203 and FIPS 204 but are **not FIPS 140
  validated** modules. PQKeep is not suitable where FIPS 140 validated cryptography is required.
- **Platforms:** the sandbox is Linux only; on Windows there is no equivalent.

### How this project is developed

PQKeep is developed by a single maintainer with the help of an AI coding assistant (Claude by
Anthropic), which writes most of the code and documentation under the maintainer's direction.
Every change follows the written specification ([`docs/SPEC.md`](docs/SPEC.md), German), is
planned and approved by the maintainer before implementation, goes through a pull request with CI
on Linux and Windows (formatting, lints, tests, known-answer tests, dependency audit) and is
merged only by the maintainer. AI-assisted commits carry a `Co-Authored-By` trailer. AI
assistance is not a substitute for an independent security review.

### Verifying a release

Releases are built by GitHub Actions from this repository only. Each archive and each Debian
package comes with a SHA-256 checksum, a build provenance attestation, a Sigstore signature and
an SBOM (CycloneDX). Replace `<version>` and `<target>` with the values of the file you
downloaded; the commands work the same way for `.zip` and `.deb` files
(`pqkeep-<version>-amd64.deb`, `pqkeep-<version>-arm64.deb`):

```
sha256sum -c SHA256SUMS --ignore-missing          # Windows: Get-FileHash <file> -Algorithm SHA256
gh attestation verify pqkeep-<version>-<target>.tar.gz --repo SpecterAoD/pqkeep
cosign verify-blob --bundle pqkeep-<version>-<target>.tar.gz.sigstore.json \
  --certificate-identity "https://github.com/SpecterAoD/pqkeep/.github/workflows/release.yml@refs/tags/v<version>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  pqkeep-<version>-<target>.tar.gz
```

The Windows binary is not yet Authenticode-signed (see the [code signing policy](CODE_SIGNING_POLICY.md)),
so Windows SmartScreen may warn when it is started for the first time.

### Documentation

| Topic | Document |
|---|---|
| Cryptography | [`docs/CRYPTO.md`](docs/CRYPTO.md) |
| Key file format | [`docs/FORMAT.md`](docs/FORMAT.md) |
| File encryption format | [`docs/FILE_FORMAT.md`](docs/FILE_FORMAT.md) |
| Signature file format | [`docs/SIGNATURE_FORMAT.md`](docs/SIGNATURE_FORMAT.md) |
| REST API | [`docs/API.md`](docs/API.md) |
| Threat model | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) |
| Sandbox (Linux) | [`docs/SANDBOX.md`](docs/SANDBOX.md) |
| Memory hardening | [`docs/MEMORY_HARDENING.md`](docs/MEMORY_HARDENING.md) |
| Passphrase rules | [`docs/SECURITY_PASSPHRASE.md`](docs/SECURITY_PASSPHRASE.md) |
| File manager context menu (Linux, Windows) | [`docs/INTEGRATION.md`](docs/INTEGRATION.md) |
| Servers (cron/systemd, unattended) | [`docs/SERVER.md`](docs/SERVER.md) |
| Key management (backup, rotation) | [`docs/KEY_MANAGEMENT.md`](docs/KEY_MANAGEMENT.md) |
| Security self-review | [`docs/SECURITY_REVIEW.md`](docs/SECURITY_REVIEW.md) |
| Release process | [`docs/RELEASE.md`](docs/RELEASE.md) |
| Roadmap | [`docs/ROADMAP.md`](docs/ROADMAP.md) |

### Project

- License: [Apache License 2.0](LICENSE)
- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md) · Code of conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- [Code signing policy](CODE_SIGNING_POLICY.md)
- Privacy: this program will not transfer any information to other networked systems unless
  specifically requested by the user or the person installing or operating it.

---

## Deutsch

PQKeep ist ein Kommandozeilenwerkzeug mit lokaler REST-API, geschrieben in Rust, zum Erzeugen und
Speichern von Post-Quanten-Schlüsseln – **ML-KEM** (FIPS 203) und **ML-DSA** (FIPS 204) – und
AES-256-Schlüsseln sowie zum Verschlüsseln von Dateien und Ordnern mit einer Passphrase oder für
den Inhaber eines öffentlichen ML-KEM-Schlüssels. Private Schlüssel liegen in einem
dokumentierten JSON-Container, verschlüsselt mit **AES-256-GCM**; der Schlüssel wird mit
**Argon2id** aus einer starken Passphrase abgeleitet. Läuft unter Windows und Linux, ohne
Telemetrie und ohne ausgehende Netzwerkverbindungen.

> **Status: Beta (`v0.1.0-beta.1`), nicht auditiert.** Dateiformate und Optionen
> können sich bis 1.0 ändern. Bitte nicht für Geheimnisse verwenden, deren Verlust nicht
> verkraftbar ist. Die verwendeten Krypto-Bibliotheken sind nicht FIPS-140-validiert.

### Kurzanleitung

Archiv für die eigene Plattform von der [Release-Seite](https://github.com/SpecterAoD/pqkeep/releases)
laden, [prüfen](#release-prüfen) und entpacken (Linux: glibc ≥ 2.35, z. B. Ubuntu 22.04+, Debian 12+,
Linux Mint 21+). Releases nach v0.1.0-beta.1 enthalten zusätzlich Linux-ARM64-Archive (64 Bit) und
Debian-Pakete (`.deb`) für amd64 und arm64 – siehe [Installation](docs/INSTALL.md). Alternativ Bau aus dem Quelltext (Rust ≥ 1.88): `cargo build --release --locked`,
Programm unter `target/release/pqkeep`.

```
pqkeep                                   # interaktives Menü (im Terminal)
pqkeep generate                          # geführt: Zweck, Stärke, Angaben, Passphrase
pqkeep passphrase                        # sichere Passphrase erzeugen
pqkeep generate --name "Max Muster" --out max.key.json
pqkeep export max.key.json --out max.pub.json   # öffentlichen Schlüssel weitergeben
pqkeep encrypt bericht.pdf               # mit Passphrase
pqkeep encrypt Ordner --to anna.pub.json # für eine Empfängerin (ML-KEM)
pqkeep decrypt Ordner.pqkf --key anna.key.json
pqkeep sign --key anna.key.json vertrag.pdf       # → vertrag.pdf.pqsig (ML-DSA-87-Schlüssel)
pqkeep verify --pub anna.pub.json vertrag.pdf     # [VERIFIED] / [INVALID]
pqkeep help security                     # Hilfethemen: passphrase, algorithms, container, files, security, verify
pqkeep serve --init-token --token-file api.token   # API-Token einmal anzeigen, nur Hash speichern
pqkeep serve --token-file api.token      # REST-API auf 127.0.0.1:8787 (Bearer-Token)
pqkeep integrate install                 # Rechtsklick-Menü in Nemo/Nautilus/Dolphin/Thunar (Linux)
```

Sprache: `--lang de|en` (Standard: Systemsprache). Passphrasen nie als Argument, nur verdeckt oder
über `--passphrase-stdin`. Unter Linux läuft jeder Befehl in einer Sandbox
([`docs/SANDBOX.md`](docs/SANDBOX.md)).

### Wie das Projekt entwickelt wird

PQKeep wird von einem Maintainer mit Hilfe eines KI-Assistenten (Claude von Anthropic)
entwickelt, der den Großteil von Code und Dokumentation nach Vorgabe des Maintainers schreibt.
Jede Änderung folgt der Spezifikation ([`docs/SPEC.md`](docs/SPEC.md)), wird vorher geplant und
freigegeben, läuft per Pull Request durch die CI (Linux und Windows) und wird nur vom Maintainer
gemergt. KI-gestützte Commits tragen einen `Co-Authored-By`-Vermerk. Das ersetzt kein
unabhängiges Sicherheitsreview.

### Release prüfen

Releases baut ausschließlich GitHub Actions aus diesem Repository. Jedes Archiv und jedes
Debian-Paket hat eine SHA-256-Prüfsumme, eine Build-Attestation, eine Sigstore-Signatur und eine
SBOM. Prüfung wie im englischen Abschnitt „Verifying a release“ (`sha256sum -c`,
`gh attestation verify`, `cosign verify-blob`) – für `.tar.gz`, `.zip` und `.deb` gleich. Das Windows-Programm ist noch nicht Authenticode-signiert; SmartScreen kann
beim ersten Start warnen.

### Projekt

Lizenz [Apache 2.0](LICENSE) · Sicherheitslücken melden: [`SECURITY.md`](SECURITY.md) ·
Mitwirken: [`CONTRIBUTING.md`](CONTRIBUTING.md) · [Code signing policy](CODE_SIGNING_POLICY.md) ·
Datenschutz: Das Programm überträgt keine Informationen an andere Systeme, außer auf
ausdrücklichen Wunsch der Person, die es nutzt, installiert oder betreibt.
