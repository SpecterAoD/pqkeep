# Release-Ablauf / Release process

**DE** | [EN](#english)

Für den Maintainer. Technische Grundlage: `.github/workflows/release.yml`, Anforderungen: SPEC 5a,
Häkchenliste: [`CHECKLIST.md`](CHECKLIST.md) („Release-Checkliste“).

## Trockenlauf (ohne Veröffentlichung)

1. GitHub → *Actions* → *Release* → *Run workflow* (Branch `main`).
2. Nach Build, Rauchtest, Paketinstallationen und Manifestabgleich wartet der Job „Signieren und bereitstellen“ auf die Freigabe:
   *Review deployments* → `release` → *Approve*.
3. Ergebnis: Artefakt `release-bundle` (Pakete, SBOMs, `SHA256SUMS`, Sigstore-Bundles); der Job
   „Prüfung“ muss grün sein. Es entsteht **kein** GitHub-Release. Hinweis: Attestationen und
   Sigstore-Einträge sind öffentlich und dauerhaft (nur Prüfsummen und Workflow-Identität).

**Paketinhalt:** Linux `pqkeep`; Windows `pqkeep.exe` und das Startprogramm `pqkeepw.exe` (Kontextmenü
ohne Konsolenfenster). Beide Windows-Programme durchlaufen die Härtungsprüfung; fehlt `pqkeepw.exe`,
bricht das Verpacken ab. Mit SignPath wären beide zu signieren.

## Release oder Beta

1. Version in `Cargo.toml` setzen (z. B. `0.1.0-beta.1`), `Cargo.lock` aktualisieren, per PR mergen.
2. Lokal auf dem aktuellen `main` einen **signierten** Tag erstellen und prüfen:
   ```
   git switch main && git pull --ff-only
   git tag -s v0.1.0-beta.1 -m "PQKeep v0.1.0-beta.1"
   git verify-tag v0.1.0-beta.1
   git push origin v0.1.0-beta.1
   ```
   Der Workflow bricht ab, wenn die Signatur nicht zu `.github/allowed_signers` passt oder Tag und
   `Cargo.toml` nicht übereinstimmen.
3. Freigabe wie beim Trockenlauf (*Review deployments*).
4. Wenn „Prüfung“ grün ist: *Releases* → Entwurf öffnen, Assets und Text prüfen (Betas sind als
   *Pre-release* markiert) → *Publish release*.
5. Fehlgeschlagen: Entwurf löschen, Ursache beheben, Tag löschen (`git push --delete origin <tag>`,
   `git tag -d <tag>`) und neu erstellen – nur solange nichts veröffentlicht wurde.

## Artefakte und Manifest (Issue #93, Phase 6)

Ein Release besteht aus genau fünf Nutzartefakten, je mit eigener CycloneDX-SBOM:

| Artefakt | Datei | SBOM |
|---|---|---|
| Linux AMD64 | `pqkeep-<Version>-x86_64-unknown-linux-gnu.tar.gz` | `…-x86_64-unknown-linux-gnu.cdx.json` |
| Linux ARM64 | `pqkeep-<Version>-aarch64-unknown-linux-gnu.tar.gz` | `…-aarch64-unknown-linux-gnu.cdx.json` |
| Windows | `pqkeep-<Version>-x86_64-pc-windows-msvc.zip` | `…-x86_64-pc-windows-msvc.cdx.json` |
| Debian amd64 | `pqkeep-<Version>-amd64.deb` | `pqkeep-<Version>-amd64.deb.cdx.json` |
| Debian arm64 | `pqkeep-<Version>-arm64.deb` | `pqkeep-<Version>-arm64.deb.cdx.json` |

Dazu kommen `SHA256SUMS` (alle zehn Dateien) und je ein Sigstore-Bundle (`.sigstore.json`) für
die fünf Artefakte und `SHA256SUMS`. Jedes Artefakt erhält eine Build-Provenance- und eine
CycloneDX-Attestation.

- **Manifest:** `scripts/release_manifest.py` enthält die Liste fest. Der Job
  „Artefaktmanifest“ (läuft auch in PRs, ohne Rechte) prüft die Build-Artefakte `dist-*`:
  fehlende, zusätzliche, doppelte oder falsch zugeordnete Dateien brechen ab. Geprüft wird
  auch die Zuordnung: SBOM ↔ Ziel und Commit, Paket ↔ Architektur, Programm im Paket ↔
  Programm im Archiv derselben Architektur. Signiert wird nur das Ergebnis (`release-input`).
  Der Job „Prüfung“ gleicht das fertige Bündel erneut mit dem Manifest ab.
- **Reihenfolge:** Signiert wird erst, wenn alle Installations- und Lebenszyklusjobs
  (`debian`) grün sind. `candidate-debian-*` (Eingabe dieser Tests, bytegleich mit dem
  Release-Paket) und `lifecycle-debian-*` (Nachfolger-Testpaket) werden nie veröffentlicht.
- **Paketversion:** Bei einem signierten Tag `<Upstream>-<Revision>` mit `~` vor einer
  Vorabkennung (z. B. `0.1.0~beta.2-1`), sonst CI-Schema `…~ci.<UTC-Zeit>.<Commit>`. Der
  Dateiname im Release folgt dem Schema der Archive, weil GitHub `~` in Asset-Namen ersetzt.
  Die Paketrevision steht in `packaging/debian/metadata.json`.
- **Paket-SBOM:** aus der SBOM des Archivs derselben Architektur abgeleitet, mit eigener
  `serialNumber` und den Eigenschaften `pqkeep:debian:package`, `…:version`,
  `…:architecture`, `…:binary-sha256`.
- **Builds:** beide Linux-Ziele nativ (`ubuntu-22.04`, `ubuntu-22.04-arm`), glibc-Symbole bis
  2.35; getestete Distributionen und Grenzen: [Testmatrix](issue-93-testmatrix.md).

Berichte der Phasen: [2](issue-93-phase2.md), [3](issue-93-phase3.md), [4](issue-93-phase4.md),
[5](issue-93-phase5.md), [6](issue-93-phase6.md).

## Windows-Signatur (SignPath)

Erst nach Zusage der SignPath Foundation: Signierschritt vor dem Verpacken einbauen, Zugangsdaten
nur als Secret im Environment `release`, Hinweis gemäß [`CODE_SIGNING_POLICY.md`](../CODE_SIGNING_POLICY.md).

---

## English

For the maintainer. Implementation: `.github/workflows/release.yml`; requirements: SPEC 5a;
checklist: [`CHECKLIST.md`](CHECKLIST.md).

**Dry run:** Actions → Release → Run workflow (`main`); after build, package installation tests and
the manifest check, approve the `release` environment when asked;
the artifact `release-bundle` is produced and the "verification" job must pass. No GitHub release
is created. Attestations and Sigstore entries are public and permanent (checksums and workflow
identity only).

**Release or beta:** set the version in `Cargo.toml` via PR; on current `main` run
`git tag -s v<version> -m "PQKeep v<version>"`, `git verify-tag v<version>`,
`git push origin v<version>`; approve the `release` environment; when verification is green, open
the draft under Releases, review it and publish. If something fails before publishing: delete the
draft and the tag, fix, tag again.

**Package content:** Linux `pqkeep`; Windows `pqkeep.exe` plus the launcher `pqkeepw.exe` (context menu
without a console window). Both Windows programs pass the hardening check; packaging fails if
`pqkeepw.exe` is missing. With SignPath both would have to be signed.

**Windows signing (SignPath):** only after approval by the SignPath Foundation – add the signing
step before packaging, credentials only as secrets of the `release` environment.

**Artifacts and manifest (issue #93, phase 6):** a release consists of exactly five user
artifacts, each with its own CycloneDX SBOM (file names: see the table above): Linux AMD64 and
ARM64 archives, the Windows ZIP, and Debian packages for amd64 and arm64. `SHA256SUMS` covers
all ten files; the five artifacts and `SHA256SUMS` each get a Sigstore bundle, and every
artifact gets a build provenance and a CycloneDX attestation. `scripts/release_manifest.py`
holds the fixed list. The "artifact manifest" job (also in PRs, without permissions) rejects
missing, additional, duplicate or wrongly assigned files and checks the assignment: SBOM ↔
target and commit, package ↔ architecture, program in the package ↔ program in the archive of
the same architecture. Only its result (`release-input`) is signed, and only after all
installation and lifecycle jobs passed; the "verification" job checks the finished bundle
against the manifest again. `candidate-debian-*` and `lifecycle-debian-*` are never published.
For a signed tag the package version is `<upstream>-<revision>` with `~` before a pre-release
identifier (e.g. `0.1.0~beta.2-1`), otherwise the CI scheme `…~ci.<UTC time>.<commit>`; the
release file name follows the archive scheme because GitHub replaces `~` in asset names. The
package SBOM is derived from the archive SBOM of the same architecture, with its own
`serialNumber` and `pqkeep:debian:*` properties. Both Linux targets build natively with glibc
symbols capped at 2.35; tested distributions and limits: [test matrix](issue-93-testmatrix.md).
Phase reports (German): [2](issue-93-phase2.md), [3](issue-93-phase3.md),
[4](issue-93-phase4.md), [5](issue-93-phase5.md), [6](issue-93-phase6.md).
