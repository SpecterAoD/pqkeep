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

## Artefakte und Manifest

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
CycloneDX-Attestation; die Provenance liegt zusätzlich als `pqkeep-<Version>.intoto.jsonl` im
Release (Sigstore-Bundle, offline prüfbar mit `gh attestation verify <datei> --bundle …`; der Job
„Prüfung“ prüft sie gegen jedes Artefakt).

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
  2.35; getestete Distributionen und Grenzen: [Paket-Tests](PACKAGE_TESTS.md).

## Windows-Signatur (SignPath)

Erst nach Zusage der SignPath Foundation: Signierschritt vor dem Verpacken einbauen, Zugangsdaten
nur als Secret im Environment `release`, Hinweis gemäß [`CODE_SIGNING_POLICY.md`](../CODE_SIGNING_POLICY.md).

## Vorschau-Builds (wöchentlich)

Neben Betas und Releases entsteht jede Woche (Sonntag, früher Morgen UTC) eine **Vorschau** von
`main`: Workflow `.github/workflows/preview.yml`. Sie nutzt denselben Build wie die Releases
(`.github/workflows/build.yml`: bauen, Härtungsprüfung, Rauchtest, Archive, `.deb`, SBOM,
Installationstests, Manifest). Nur das Veröffentlichen unterscheidet sich.

| | Beta / Release | Vorschau |
|---|---|---|
| Auslöser | signierter Tag `v*` (Release-Workflow) | Zeitplan oder *Run workflow* |
| Version in `--version` | `0.1.0-beta.3` | `0.1.0-beta.3+preview.<Datum>.<Commit>` |
| Im Programm | – | Banner (Terminal), „PREVIEW“ in Fenstertiteln |
| Dateiname | `pqkeep-0.1.0-beta.3-…` | `pqkeep-0.1.0-beta.3-preview.<Datum>.<Commit>-…` |
| GitHub | Entwurf, von Hand veröffentlicht | Pre-Release `preview-<Datum>.<Commit>`, nie „Latest“ |
| Signierung | Sigstore, Freigabe im Environment `release` | Keyless Sigstore, Build-/SBOM-Attestationen und Prüfsummen; kein Environment `release` |
| Aufbewahrung | dauerhaft | die letzten vier |

Ablauf: Der Zeitplan überspringt den Lauf, wenn es seit der letzten Vorschau keinen neuen Commit
gibt oder die CI auf dem Commit nicht grün ist; von Hand startet er immer. Bei Pull Requests läuft
`preview.yml` nicht; Änderungen an `build.yml` baut und testet `release.yml` im Pull Request.

**Betas und Releases bleiben unberührt:** Die Kennzeichnung entsteht nur beim Bauen über
`PQKEEP_CHANNEL=preview` und `PQKEEP_BUILD_ID`; Release-Builds setzen die Variablen gar nicht, und
der Schritt „Kanal prüfen“ in `build.yml` bricht ab, wenn ein Release `+preview.` trägt oder eine
Vorschau nicht. Wer `build.yml` ändert, prüft das mit einem Trockenlauf des Release-Workflows.

Neue Vorschauen ab PR #281 werden vor Veröffentlichung geprüft: Prüfsummen für fünf Pakete und
fünf SBOMs, Sigstore-Bundles für die fünf Pakete und `SHA256SUMS`, Build-Provenance (auch als
`.intoto.jsonl`) und CycloneDX-Attestationen für alle fünf Pakete. Verifikation wie bei Releases,
aber mit Identität `https://github.com/SpecterAoD/pqkeep/.github/workflows/preview.yml@refs/heads/main`.
Alte Vorschauen erhalten nachträglich keine Signaturen. Kein SignPath/Authenticode; Signaturen
belegen Herkunft und Unverändertheit, keine unabhängige Sicherheitsprüfung.
Vorschauen sind **nicht unabhängig geprüft** und nicht für Daten gedacht, die nicht verloren gehen dürfen.

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

**Artifacts and manifest:** a release consists of exactly five user
artifacts, each with its own CycloneDX SBOM (file names: see the table above): Linux AMD64 and
ARM64 archives, the Windows ZIP, and Debian packages for amd64 and arm64. `SHA256SUMS` covers
all ten files; the five artifacts and `SHA256SUMS` each get a Sigstore bundle, and every
artifact gets a build provenance and a CycloneDX attestation; the provenance is also attached as
`pqkeep-<version>.intoto.jsonl` (Sigstore bundle, verifiable offline with
`gh attestation verify <file> --bundle …`; the "verification" job checks it against every artifact). `scripts/release_manifest.py`
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
symbols capped at 2.35; tested distributions and limits: [package tests](PACKAGE_TESTS.md).


## Preview builds (weekly)

Besides betas and releases, a **preview** of `main` is built every week (Sunday, early morning UTC):
workflow `.github/workflows/preview.yml`. It uses the same build as the releases
(`.github/workflows/build.yml`: build, hardening check, smoke test, archives, `.deb`, SBOM,
installation tests, manifest). Only publishing differs.

| | Beta / release | Preview |
|---|---|---|
| Trigger | signed tag `v*` (release workflow) | schedule or *Run workflow* |
| Version in `--version` | `0.1.0-beta.3` | `0.1.0-beta.3+preview.<date>.<commit>` |
| In the program | – | banner (terminal), "PREVIEW" in window titles |
| File name | `pqkeep-0.1.0-beta.3-…` | `pqkeep-0.1.0-beta.3-preview.<date>.<commit>-…` |
| GitHub | draft, published by hand | pre-release `preview-<date>.<commit>`, never "Latest" |
| Signing | Sigstore, approval in environment `release` | keyless Sigstore, build/SBOM attestations and checksums; no `release` environment |
| Retention | permanent | the last four |

Flow: the schedule skips the run when there is no new commit since the last preview or CI on the
commit is not green; a manual start always runs. `preview.yml` does not run on pull
requests; changes to `build.yml` are built and tested by `release.yml` in the pull request.

**Betas and releases stay untouched:** the marking exists only at build time through
`PQKEEP_CHANNEL=preview` and `PQKEEP_BUILD_ID`; release builds do not set the variables at all, and
the step "check channel" in `build.yml` fails if a release carries `+preview.` or a preview does
not. Whoever changes `build.yml` checks it with a dry run of the release workflow.

New previews from PR #281 are verified before publication: checksums for five packages and
five SBOMs, Sigstore bundles for the five packages and `SHA256SUMS`, build provenance (also as
`.intoto.jsonl`) and CycloneDX attestations for all five packages. Verify as for releases,
but use identity `https://github.com/SpecterAoD/pqkeep/.github/workflows/preview.yml@refs/heads/main`.
Older previews do not gain signatures retroactively. No SignPath/Authenticode; signatures prove
origin and integrity, not an independent security audit.
Previews are **not independently audited** and not meant for data you cannot lose.
