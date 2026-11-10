# Release-Ablauf / Release process

**DE** | [EN](#english)

Für den Maintainer. Technische Grundlage: `.github/workflows/release.yml`, Anforderungen: SPEC 5a,
Häkchenliste: [`CHECKLIST.md`](CHECKLIST.md) („Release-Checkliste“).

## Trockenlauf (ohne Veröffentlichung)

1. GitHub → *Actions* → *Release* → *Run workflow* (Branch `main`).
2. Nach Build und Rauchtest wartet der Job „Signieren und bereitstellen“ auf die Freigabe:
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

## Linux ARM64 als CI-Kandidat (Issue #93, Phase 2)

`aarch64-unknown-linux-gnu` wird auf `ubuntu-22.04-arm` nativ gebaut und getestet.
Wie bei AMD64 gilt glibc 2.35 als Obergrenze der benötigten glibc-Symbolversionen.
ELF-Architektur, Loader, PIE, Full RELRO und NX werden geprüft; der vorhandene Rauchtest
führt das Release-Binary einschließlich Sandbox und Verschlüsselungsrundlauf aus.
Die Archivprüfung vergleicht das verpackte Programm bytegenau mit diesem Binary.

Das Actions-Artefakt `candidate-aarch64-unknown-linux-gnu` enthält das `.tar.gz` und
die zielbezogene CycloneDX-SBOM. Es ist 14 Tage verfügbar und gehört noch nicht zum
signierten `release-bundle`: Signaturen, Attestationen und Veröffentlichung der neuen
Artefakte folgen erst nach gesonderter Freigabe in Phase 6. Debian-Pakete sind in Phase 2
nicht enthalten. Details und Abnahme: [Phase-2-Bericht](issue-93-phase2.md).

## Debian AMD64 als CI-Kandidat (Issue #93, Phase 3)

Der bestehende AMD64-Build erzeugt zusätzlich `candidate-debian-amd64`, getrennt von
`dist-*` und dem signierten Release-Bundle. Der Paketierer verwendet genau das geprüfte
Release-Binary und prüft dessen unveränderte Identität im `.deb`. Zwei Paketläufe müssen
bytegleich sein. Die CI führt Lintian und echte Installation/Smoke/Entfernung auf
Debian 12 und Ubuntu 22.04 in nativen AMD64-Containern aus; vorhandene Testschlüssel und
Nutzerdateien müssen dabei unverändert bleiben. Details: [Installation DE/EN](INSTALL.md)
und [Phase-3-Bericht](issue-93-phase3.md). Kein neues Artefakt wird in Phase 3 veröffentlicht.

## Windows-Signatur (SignPath)

Erst nach Zusage der SignPath Foundation: Signierschritt vor dem Verpacken einbauen, Zugangsdaten
nur als Secret im Environment `release`, Hinweis gemäß [`CODE_SIGNING_POLICY.md`](../CODE_SIGNING_POLICY.md).

---

## English

For the maintainer. Implementation: `.github/workflows/release.yml`; requirements: SPEC 5a;
checklist: [`CHECKLIST.md`](CHECKLIST.md).

**Dry run:** Actions → Release → Run workflow (`main`); approve the `release` environment when asked;
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

**Linux ARM64 CI candidate (issue #93, phase 2):** `aarch64-unknown-linux-gnu` builds and
tests natively on `ubuntu-22.04-arm`, with required glibc symbol versions capped at 2.35.
Checks cover ELF architecture, loader, PIE, full RELRO and NX. The existing smoke test
executes the release binary, including sandboxing and an encryption round trip. The
archive check verifies that the packaged executable is identical to the tested binary.
The Actions artifact `candidate-aarch64-unknown-linux-gnu` contains the `.tar.gz` and
target-specific CycloneDX SBOM, retained for 14 days. It is not yet part of the signed
`release-bundle`; signing, attestations and publishing require separate phase 6 approval.
Debian packages are outside phase 2. See the [phase 2 report](issue-93-phase2.md) (German).

**Debian AMD64 CI candidate (issue #93, phase 3):** the existing AMD64 build also produces
`candidate-debian-amd64`, separate from `dist-*` and the signed release bundle. Packaging
uses the exact tested executable and checks its identity inside the `.deb`. Repeated
packaging must be byte-identical. CI runs Lintian and real installation/smoke/removal
checks in native AMD64 Debian 12 and Ubuntu 22.04 containers, preserving existing test
keys and user files. See [installation instructions](INSTALL.md) and the
[phase 3 report](issue-93-phase3.md) (German). No new artifact is published in phase 3.
