# CI- und Release-Sicherheit / CI and release security

**DE** | [EN](#english)

Bestandsaufnahme der GitHub-Actions-Umgebung von PQKeep: was läuft, mit welchen Rechten, was
geprüft ist, welche Restrisiken bleiben. **Stand: 15.11.2026.** Die Angaben zu den
GitHub-Einstellungen wurden über die GitHub-API gelesen (nur Namen und Regeln, keine Secret-Werte).
Einstellungen können sich ändern – vor einem Release erneut prüfen.

## Workflows und Rechte

Alle Workflows setzen oben `permissions: contents: read`; Standardrecht des Tokens im Repository
ist ebenfalls „read“. Alle Actions sind auf vollständige Commit-SHAs gepinnt (in den Einstellungen
erzwungen).

| Workflow | Auslöser | Zusätzliche Rechte | Secrets |
|---|---|---|---|
| `ci.yml` | Push auf `main`, Pull Request | keine | keine |
| `codeql.yml` | Push, Pull Request, wöchentlich, manuell | Job: `security-events: write`, `actions: read` | keine |
| `fuzz.yml` | wöchentlich, manuell, Pull Request (Pfadfilter) | keine | keine |
| `audit.yml` | wöchentlich, manuell | keine | keine |
| `security-policy.yml` | Push/Pull Request bei Workflow-Änderungen, manuell | keine | keine |
| `dependency-review.yml` | Pull Request | keine | keine |
| `scorecard.yml` | Push auf `main`, wöchentlich, Änderung am Branch-Schutz, manuell – **nie** Pull Request | Job: `security-events: write`, `id-token: write`, `actions: read` | keine |
| `release.yml` | Tag `v*`, manuell, Pull Request (Pfadfilter, ohne `publish`/`draft`) | `publish`: OIDC/Attestationsrechte, `contents: read`; `verify`: Lesen; nur `draft`: `contents: write` | keine (Signatur schlüssellos über OIDC) |

Pull Requests aus Forks laufen mit Lesetoken und ohne Secrets. Code aus einem Pull Request
(Build-Skripte, Tests) gilt als nicht vertrauenswürdig; deshalb gibt es keine
`pull_request_target`- oder `workflow_run`-Auslöser, und Workflows mit Schreibrechten laufen nicht
für Pull Requests.

## Automatische Prüfungen

| Prüfung | Wo | Zweck |
|---|---|---|
| Eigene Regeln (`scripts/check_actions_policy.py`) | `security-policy.yml` | explizite Rechte, SHA-Pinning, keine gefährlichen Auslöser, keine Secrets/Schreibrechte in PR-Workflows, kein `curl \| sh`, keine Downloads ohne Prüfsumme |
| actionlint, zizmor (offline, mit Prüfsummen installiert) | `security-policy.yml` | Syntax, Shell-Fehler, Injection über `${{ }}`, Rechte |
| Dependency Review | `dependency-review.yml` | neue/geänderte Abhängigkeiten je PR mit bekannten Schwachstellen (ab „moderate“) |
| OpenSSF Scorecard | `scorecard.yml` | Messgröße für die Lieferkette; Ergebnis öffentlich und als Kennzeichen in der README |
| CodeQL (Rust, Python, Actions) | `codeql.yml` | statische Analyse |
| gitleaks (Archiv mit SHA-256 geprüft) | `ci.yml` | Geheimnisse in der Historie |
| cargo-deny, wöchentliches Advisory-Audit | `ci.yml`, `audit.yml` | Lizenzen, Quellen, bekannte Schwachstellen im ganzen Baum |
| Dependabot (wöchentlich, 7 Tage Wartezeit), Sicherheitsupdates | `.github/dependabot.yml` | Aktualität von Crates und Actions |
| Secret Scanning mit Push Protection | GitHub-Einstellung | Geheimnisse beim Push abweisen |

Bewusst **nicht** eingesetzt: Trivy, GitGuardian, SonarCloud, Semgrep, Checkov/KICS, ZAP, Renovate –
sie doppeln vorhandene Prüfungen oder passen nicht zu einem CLI-Projekt ohne Container,
Infrastruktur-Code und Webdienst. Eine automatische SonarCloud-Analyse lief kurzzeitig (bis
25.11.2026) und wurde wieder entfernt: keine Befunde im Rust-Code, 29 Befunde nur in Hilfsskripten und
Workflows, davon 22 Fehlalarme; CodeQL (Rust, Python, Actions), clippy pedantic, `check_limits.sh`,
zizmor und actionlint decken dasselbe ab. Die berechtigten Kleinigkeiten (HTTPS-Zwang bei `curl`,
actionlint als geprüfte Binärdatei) sind umgesetzt.

## Downloads und Abfluss von Daten

**Was zur Laufzeit geladen wird:** Actions (per Commit-SHA), gitleaks (Archiv mit fester
SHA-256), zizmor (`pip --require-hashes`), actionlint (`go install` mit fester Version, geprüft über
die Go-Prüfsummendatenbank), cargo-deny und cargo-cyclonedx (`cargo install --locked` mit fester
Version), Rust-Abhängigkeiten (`Cargo.lock`, `--locked`). Der eigene Prüfer meldet jeden Download
mit `curl`/`wget` ohne `sha256sum -c` bzw. `--require-hashes`.

**Abflusswege** aus einem kompromittierten Job: HTTP(S) und DNS ins Internet, Artefakte, Caches,
Protokolle. GitHub-gehostete Runner sind **nicht** netzwerkisoliert. Begrenzung bei PQKeep: Es gibt
keine Secrets, die abfließen könnten; kurzlebige Schreib-/OIDC-Rechte sind auf `publish`, `draft`, `preview` und `scorecard`
begrenzt; Release-Rechte verlangen das `release`-Environment, keine dieser Grenzen führt PR-Code aus. Was ein manipuliertes
Werkzeug erreichen könnte, sind falsche Prüfergebnisse – nicht Schlüssel oder Signaturrechte
anderer Jobs.

**Harden-Runner (Egress-Allowlist): vorerst nicht eingesetzt.** Er wäre selbst eine fremde Action
mit weitgehendem Zugriff auf den Runner, und ohne Secrets ist der Nutzen gering. Neu bewerten, falls
`publish` je ein langlebiges Secret braucht (z. B. eine SignPath-Anbindung, #88).

## GitHub-Einstellungen (gelesen am 15.11.2026)

| Bereich | Ist | Bewertung |
|---|---|---|
| Ruleset `main` | kein Löschen, kein Force-Push, lineare Historie, signierte Commits, nur Pull Request mit Squash, alle Review-Threads gelöst, 9 Pflichtprüfungen (CI auf Linux/Windows, MSRV, Limits, Binär-Härtung, cargo-deny, gitleaks); **keine** Umgehungsberechtigten | gut |
| Ruleset Tags `v*` | kein Löschen, Ändern, Force-Push; Umgehung nur für Repository-Admins | gut (nötig, um Tags anzulegen) |
| CODEOWNERS | Datei vorhanden, Code-Owner-Review im Ruleset **nicht** verlangt | richtig so: mit einem einzigen Maintainer würde die Pflicht jeden Merge blockieren |
| Environment `release` | Freigabe durch den Maintainer nötig; erlaubte Refs nur Tag `v*` und Branch `main` (Trockenlauf) | gut |
| Actions-Einstellungen | alle Actions erlaubt, SHA-Pinning **erzwungen**, Token „read“, Actions dürfen keine Reviews freigeben | gut |
| Secrets | keine (Repository und Environment `release`) | gut |

## Angriffskatalog (#151)

Die [versionierte Matrix und Baseline](ATTACK_TEST_MATRIX.md) trennen Testabdeckung und Ausführung.
`ci.yml:test` prüft Datenvertrag, lokale Test-/Workflow-Verweise und Validator-Negativtests offline
auf Linux x86_64/ARM64 und Windows x86_64. Zwei neue Replay-Tests laufen in der bestehenden
Rust-Suite; sie belegen akzeptierte gültige alte Dateien, keine Frischegarantie. Zusätzlich läuft
die No-default-Rust-Suite je einmal auf Ubuntu latest und Windows latest. Ubuntu 22.04/ARM64
behalten No-default-Clippy ohne weiteren Runtime-Lauf. Keine neuen Jobs/Pflichtchecks oder Rechte.
Fuzzing bleibt pfadgefiltert/historisch referenziert; cfg-/Landlock-/root-Auslassungen sind keine
bestandenen Assertions. Nachweis-SHAs und tatsächliche Plattformgrenzen stehen im Katalog.

## Offene Punkte

1. **Release-Kette (#186):** `publish` signiert nur; `verify` prüft Manifest, Prüfsummen,
   Signaturen und Build-/SBOM-Attestationen gegen erwartetes Repository, Workflow, Ref und Commit.
   Erst danach darf `draft` mit `contents: write` das erneut geprüfte Bündel als privaten Entwurf
   bereitstellen. Beide schreibenden/signierenden Grenzen behalten das `release`-Environment;
   Veröffentlichung bleibt manuell. [Plan und Grenzen](RELEASE_CHAIN_DESIGN.md).
2. **Nicht als Pflichtprüfung eintragen:** `Workflow-Prüfung / workflow policy` (läuft nur bei
   Workflow-Änderungen) – eine Pflichtprüfung, die nicht startet, blockiert jeden anderen PR.
   Dependency Review kann Pflichtprüfung werden, sobald sie sich einige Wochen bewährt hat.
3. **Externe Überwachung** gibt es bewusst nicht; für ein Ein-Personen-Projekt genügen die
   GitHub-Benachrichtigungen zu Workflow-Läufen, Releases und Sicherheitswarnungen.

## Grenzen

- Regeln im Repository schützen nicht vor einer Übernahme des Maintainer-Kontos. Dagegen helfen
  nur starkes Passwort und zweiter Faktor (beides aktiv).
- Der Maintainer kann als Admin Tags anlegen und Einstellungen ändern; das ist gewollt.
- Diese Datei beschreibt den Stand eines Tages. Maßgeblich sind die Einstellungen selbst.

## Vorfall: was tun

1. **Sichern, nicht löschen:** Zeitpunkt, Lauf-Nummer, Commit, Workflow-Datei und Protokolle
   festhalten (Bildschirmfoto oder Download) – Läufe und Protokolle können verschwinden.
2. **Anhalten:** betroffenen Workflow deaktivieren (Actions → Workflow → „Disable workflow“),
   offenen Release-Entwurf nicht veröffentlichen, Freigabe im Environment `release` verweigern.
3. **Zugänge:** nur betroffene Geheimnisse widerrufen und neu anlegen; bei Verdacht auf
   Kontoübernahme Passwort ändern, Sitzungen, Tokens, SSH-/Signaturschlüssel und zugelassene Apps
   prüfen.
4. **Prüfen:** letzte Commits auf `main` (Signatur!), Tags, Releases und deren Dateien gegen
   `SHA256SUMS`, Attestierungen und Sigstore-Bündel; Rulesets und Environment-Regeln.
5. **Wiederherstellen** über einen geprüften Pull Request; ein manipuliertes Release zurückziehen
   und in den Release-Notizen und per Sicherheitshinweis (`SECURITY.md`) darauf hinweisen.
6. **Aufschreiben:** Ablauf, Betroffenes, was sicher ist und was nicht, Folgemaßnahmen.

## English

Inventory of PQKeep's GitHub Actions setup: what runs, with which permissions, what is checked,
which residual risks remain. **As of 2026-11-15.** GitHub settings were read through the GitHub
API (names and rules only, no secret values). Settings can change – check again before a release.

### Workflows and permissions

Every workflow sets top-level `permissions: contents: read`; the repository's default token
permission is "read" as well. All actions are pinned to full commit SHAs (enforced in the settings).

| Workflow | Trigger | Extra permissions | Secrets |
|---|---|---|---|
| `ci.yml` | push to `main`, pull request | none | none |
| `codeql.yml` | push, pull request, weekly, manual | job: `security-events: write`, `actions: read` | none |
| `fuzz.yml` | weekly, manual, pull request (path filter) | none | none |
| `audit.yml` | weekly, manual | none | none |
| `security-policy.yml` | push/pull request on workflow changes, manual | none | none |
| `dependency-review.yml` | pull request | none | none |
| `scorecard.yml` | push to `main`, weekly, branch protection change, manual – **never** pull requests | job: `security-events: write`, `id-token: write`, `actions: read` | none |
| `release.yml` | tag `v*`, manual, pull request (path filter, without `publish`/`draft`) | `publish`: OIDC/attestations, `contents: read`; `verify`: read; only `draft`: `contents: write` | none (keyless signing via OIDC) |

Pull requests from forks run with a read token and without secrets. Code from a pull request
(build scripts, tests) is untrusted; hence no `pull_request_target` or `workflow_run` triggers, and
workflows with write permissions do not run for pull requests.

### Automatic checks

| Check | Where | Purpose |
|---|---|---|
| Own rules (`scripts/check_actions_policy.py`) | `security-policy.yml` | explicit permissions, SHA pinning, no dangerous triggers, no secrets/write permissions in PR workflows, no `curl \| sh`, no downloads without a checksum |
| actionlint, zizmor (offline, installed with hashes) | `security-policy.yml` | syntax, shell errors, injection via `${{ }}`, permissions |
| Dependency Review | `dependency-review.yml` | new/changed dependencies per PR with known vulnerabilities (from "moderate") |
| OpenSSF Scorecard | `scorecard.yml` | measure for the supply chain; result public and as a README badge |
| CodeQL (Rust, Python, Actions) | `codeql.yml` | static analysis |
| gitleaks (archive verified by SHA-256) | `ci.yml` | secrets in history |
| cargo-deny, weekly advisory audit | `ci.yml`, `audit.yml` | licences, sources, known vulnerabilities in the whole tree |
| Dependabot (weekly, 7-day cooldown), security updates | `.github/dependabot.yml` | current crates and actions |
| Secret scanning with push protection | GitHub setting | reject secrets on push |

Deliberately **not** used: Trivy, GitGuardian, SonarCloud, Semgrep, Checkov/KICS, ZAP, Renovate –
they duplicate existing checks or do not fit a CLI project without containers, infrastructure code
or a web service. An automatic SonarCloud analysis ran briefly (until 2026-11-25) and was removed
again: no findings in the Rust code, 29 findings only in helper scripts and workflows, 22 of them false
positives; CodeQL (Rust, Python, Actions), clippy pedantic, `check_limits.sh`, zizmor and actionlint
cover the same ground. The valid minor points (HTTPS-only `curl`, actionlint as a verified binary) are
implemented.

### Downloads and data exfiltration

**Downloaded at runtime:** actions (by commit SHA), gitleaks (archive with fixed SHA-256), zizmor
(`pip --require-hashes`), actionlint (`go install` at a fixed version, verified through the Go
checksum database), cargo-deny and cargo-cyclonedx (`cargo install --locked` at fixed versions),
Rust dependencies (`Cargo.lock`, `--locked`). The own checker reports every `curl`/`wget` download
without `sha256sum -c` or `--require-hashes`.

**Exfiltration paths** from a compromised job: HTTP(S) and DNS to the internet, artefacts, caches,
logs. GitHub-hosted runners are **not** network-isolated. Limitation in PQKeep: there are no
secrets that could leak; short-lived write/OIDC permissions are confined to `publish`, `draft`, `preview` and
`scorecard`; release privileges require environment approval, never running PR code. A manipulated tool could
produce wrong check results – not obtain keys or other jobs' signing rights.

**Harden-Runner (egress allowlist): not used for now.** It would itself be a third-party action with
broad access to the runner, and without secrets the benefit is small. Reassess if `publish` ever
needs a long-lived secret (e.g. a SignPath integration, #88).

### GitHub settings (read on 2026-11-15)

| Area | Current | Assessment |
|---|---|---|
| Ruleset `main` | no deletion, no force push, linear history, signed commits, pull request with squash only, all review threads resolved, 9 required checks (CI on Linux/Windows, MSRV, limits, binary hardening, cargo-deny, gitleaks); **no** bypass actors | good |
| Ruleset tags `v*` | no deletion, update, force push; bypass for repository admins only | good (needed to create tags) |
| CODEOWNERS | file present, code owner review **not** required by the ruleset | correct: with a single maintainer the requirement would block every merge |
| Environment `release` | maintainer approval required; allowed refs only tag `v*` and branch `main` (dry run) | good |
| Actions settings | all actions allowed, SHA pinning **enforced**, token "read", Actions cannot approve reviews | good |
| Secrets | none (repository and environment `release`) | good |

### Attack catalogue (#151)

The [versioned matrix and baseline](ATTACK_TEST_MATRIX.md) separate coverage from execution.
`ci.yml:test` checks the data contract, local test/workflow references and validator rejection tests
offline on Linux x86_64/ARM64 and Windows x86_64. Two replay tests run in the existing Rust suite:
they characterize accepted old valid files, not freshness. The no-default Rust suite additionally
runs once on Ubuntu latest and Windows latest; Ubuntu 22.04/ARM64 retain no-default clippy without
another runtime run. No new jobs, required checks or privileges. Fuzzing remains path-filtered and
historically referenced; cfg/Landlock/root skips are not passing assertions. Recorded source SHAs
and actual platform limitations remain explicit in the catalogue.

### Open items

1. **Release chain (#186):** signing/staging → complete verification → independently gated draft.
   Verify repository/workflow/ref/source and signer commits, inventory, signatures and attestations;
   reverify after the draft job downloads the bundle. Only draft gets release write permission;
   both privileged boundaries retain the environment approval. Publication stays manual.
   [Design and limits](RELEASE_CHAIN_DESIGN.md).
2. **Do not make required:** `Workflow-Prüfung / workflow policy` (runs only on workflow changes) –
   a required check that never starts blocks every other PR. Dependency Review can become required
   once it has proven itself for a few weeks.
3. **External monitoring** deliberately does not exist; for a one-person project GitHub's
   notifications for workflow runs, releases and security alerts are enough.

### Limits

- Repository rules do not protect against a takeover of the maintainer account. Only a strong
  password and a second factor help there (both active).
- As admin, the maintainer can create tags and change settings; this is intended.
- This file describes the state of one day. The settings themselves are authoritative.

### Incident: what to do

1. **Preserve, do not delete:** record time, run number, commit, workflow file and logs
   (screenshot or download) – runs and logs can disappear.
2. **Stop:** disable the affected workflow (Actions → workflow → "Disable workflow"), do not
   publish an open release draft, deny approval in the `release` environment.
3. **Access:** revoke and recreate only the affected secrets; if an account takeover is suspected,
   change the password and review sessions, tokens, SSH/signing keys and authorised apps.
4. **Check:** latest commits on `main` (signature!), tags, releases and their files against
   `SHA256SUMS`, attestations and Sigstore bundles; rulesets and environment rules.
5. **Restore** through a reviewed pull request; withdraw a manipulated release and point it out in
   the release notes and by security advisory (`SECURITY.md`).
6. **Write down:** timeline, what was affected, what is certain and what is not, follow-up actions.
