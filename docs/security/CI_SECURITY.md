# CI- und Release-Sicherheit / CI and release security

**DE** | [EN](#english)

Bestandsaufnahme der GitHub-Actions-Umgebung von PQKeep (#180–#187): was läuft, mit welchen
Rechten, was geprüft ist, was offen bleibt. **Stand: 14.11.2026.** Die Angaben zu den
GitHub-Einstellungen wurden an diesem Tag über die GitHub-API gelesen (nur Namen und Regeln, keine
Secret-Werte). Einstellungen können sich ändern – vor einem Release erneut prüfen.

## Workflows und Rechte

Alle Workflows setzen oben `permissions: contents: read`; Standardrecht des Tokens im Repository
ist ebenfalls „read“. Alle Actions sind auf vollständige Commit-SHAs gepinnt.

| Workflow | Auslöser | Zusätzliche Rechte | Secrets |
|---|---|---|---|
| `ci.yml` | Push auf `main`, Pull Request | keine | keine |
| `codeql.yml` | Push, Pull Request, wöchentlich, manuell | Job: `security-events: write`, `actions: read` | keine |
| `fuzz.yml` | wöchentlich, manuell, Pull Request (Pfadfilter) | keine | keine |
| `audit.yml` | wöchentlich, manuell | keine | keine |
| `security-policy.yml` | Push/Pull Request bei Workflow-Änderungen, manuell | keine | keine |
| `release.yml` | Tag `v*`, manuell, Pull Request (Pfadfilter, ohne `publish`) | nur Job `publish`: `contents: write`, `id-token: write`, `attestations: write`; `verify`: `attestations: read` | keine (Signatur schlüssellos über OIDC) |

Pull Requests aus Forks laufen mit Lesetoken und ohne Secrets. Code aus einem Pull Request
(Build-Skripte, Tests) gilt als nicht vertrauenswürdig; deshalb gibt es keine
`pull_request_target`- oder `workflow_run`-Auslöser.

## Automatische Prüfungen

| Prüfung | Wo | Zweck |
|---|---|---|
| Eigene Regeln (`scripts/check_actions_policy.py`) | `security-policy.yml` | explizite Rechte, SHA-Pinning, keine gefährlichen Auslöser, keine Secrets/Schreibrechte in PR-Workflows, kein `curl \| sh` |
| actionlint, zizmor (offline) | `security-policy.yml` | Syntax, Shell-Fehler, Injection über `${{ }}`, Rechte |
| CodeQL (Rust, Python, Actions) | `codeql.yml` | statische Analyse |
| gitleaks (Archiv mit SHA-256 geprüft) | `ci.yml` | Geheimnisse in der Historie |
| cargo-deny, wöchentliches Advisory-Audit | `ci.yml`, `audit.yml` | Lizenzen, Quellen, bekannte Schwachstellen |
| Dependabot (wöchentlich, 7 Tage Wartezeit), Sicherheitsupdates | `.github/dependabot.yml` | Aktualität von Crates und Actions |
| Secret Scanning mit Push Protection | GitHub-Einstellung | Geheimnisse beim Push abweisen |

Bewusst **nicht** eingesetzt (Begründung in #180/#181/#185): Trivy, GitGuardian, SonarCloud,
Semgrep, Checkov/KICS, ZAP, Renovate – sie doppeln vorhandene Prüfungen oder passen nicht zu einem
CLI-Projekt ohne Container, Infrastruktur-Code und Webdienst.

## GitHub-Einstellungen (gelesen am 14.11.2026)

| Bereich | Ist | Bewertung |
|---|---|---|
| Ruleset `main` | kein Löschen, kein Force-Push, lineare Historie, signierte Commits, nur Pull Request mit Squash, alle Review-Threads gelöst, 9 Pflichtprüfungen (CI auf Linux/Windows, MSRV, Limits, Binär-Härtung, cargo-deny, gitleaks); **keine** Umgehungsberechtigten | gut |
| Ruleset Tags `v*` | kein Löschen, Ändern, Force-Push; Umgehung nur für Repository-Admins | gut (nötig, um Tags anzulegen) |
| CODEOWNERS | Datei vorhanden, Code-Owner-Review im Ruleset **nicht** verlangt | richtig so: mit einem einzigen Maintainer würde die Pflicht jeden Merge blockieren |
| Environment `release` | Freigabe durch den Maintainer nötig, Selbstfreigabe erlaubt; **keine** Beschränkung auf Tags/Branches | offen, siehe unten |
| Actions-Einstellungen | alle Actions erlaubt, SHA-Pinning nicht erzwungen, Token „read“, Actions dürfen keine Reviews freigeben | offen, siehe unten |
| Secrets | Repository: `GEMINI_API_KEY` (für den OpenCode-Versuch #176, von keinem Workflow auf `main` benutzt); Environment `release`: keine | offen, siehe unten |

## Offene Punkte

Reihenfolge nach Nutzen; jeder Punkt ist eine Einstellung oder ein eigener kleiner Pull Request.

1. **Environment `release` auf Tags `v*` beschränken** (Einstellung „Deployment branches and
   tags“). Heute kann ein manueller Lauf von jedem Branch die Freigabe anfragen (#186).
2. **`GEMINI_API_KEY` aus den Repository-Secrets entfernen**, solange #176 nicht entschieden ist;
   bei Bedarf später als Environment-Secret mit Freigabe anlegen. Ein Repository-Secret ist für
   jeden Workflow auf jedem Branch lesbar, den ein Schreibberechtigter anlegt (#183).
3. **SHA-Pinning in den Actions-Einstellungen erzwingen** („Require actions to be pinned to a
   full-length commit SHA“). Die Workflows erfüllen das bereits (#181).
4. **`Workflow-Prüfung / workflow policy` nicht als Pflichtprüfung eintragen:** der Workflow läuft
   wegen des Pfadfilters nur bei Workflow-Änderungen; eine Pflichtprüfung, die nicht startet,
   blockiert jeden anderen Pull Request.
5. **Release-Reihenfolge:** `publish` legt den Release-**Entwurf** an, bevor `verify` Manifest,
   Prüfsummen, Attestierungen und Signaturen geprüft hat. Der Entwurf ist nicht öffentlich und wird
   von Hand veröffentlicht – also erst nach grünem `verify` veröffentlichen (steht so in
   [RELEASE.md](../RELEASE.md)). Ein Umbau (erst prüfen, dann Entwurf) ist möglich, braucht aber
   einen eigenen Pull Request mit Probelauf (#186).
6. **Downloads zur Laufzeit:** `cargo install --locked` (cargo-deny, cargo-cyclonedx) und
   `go install` (actionlint) holen Quellcode mit festen Versionen und Prüfsummen aus Lockfile bzw.
   Go-Prüfsummendatenbank, bauen ihn aber auf dem Runner. Kein Secret ist in diesen Jobs erreichbar;
   Restrisiko: manipulierte Prüfergebnisse (#185).
7. **Ausgehender Netzverkehr** der Runner ist nicht beschränkt. Harden-Runner im Beobachtungsmodus
   für den Job `publish` ist eine Option, wenn dort je ein langlebiges Secret nötig wird (#185).
8. **Externe Überwachung** (#187) gibt es nicht. Für ein Ein-Personen-Projekt genügen vorerst die
   GitHub-Benachrichtigungen zu Workflow-Läufen, Releases und Sicherheitswarnungen; ein eigener
   Überwachungsdienst wäre mehr Angriffsfläche als Nutzen.

Nicht Teil von `main`: der OpenCode-Workflow (#176, #184). Er wird erst bewertet, wenn entschieden
ist, ob er kommt.

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

Inventory of PQKeep's GitHub Actions setup (#180–#187): what runs, with which permissions, what
is checked, what remains open. **As of 2026-11-14.** GitHub settings were read through the GitHub
API on that day (names and rules only, no secret values). Settings can change – check again before
a release.

### Workflows and permissions

Every workflow sets top-level `permissions: contents: read`; the repository's default token
permission is "read" as well. All actions are pinned to full commit SHAs.

| Workflow | Trigger | Extra permissions | Secrets |
|---|---|---|---|
| `ci.yml` | push to `main`, pull request | none | none |
| `codeql.yml` | push, pull request, weekly, manual | job: `security-events: write`, `actions: read` | none |
| `fuzz.yml` | weekly, manual, pull request (path filter) | none | none |
| `audit.yml` | weekly, manual | none | none |
| `security-policy.yml` | push/pull request on workflow changes, manual | none | none |
| `release.yml` | tag `v*`, manual, pull request (path filter, without `publish`) | job `publish` only: `contents: write`, `id-token: write`, `attestations: write`; `verify`: `attestations: read` | none (keyless signing via OIDC) |

Pull requests from forks run with a read token and without secrets. Code from a pull request
(build scripts, tests) is untrusted; hence no `pull_request_target` or `workflow_run` triggers.

### Automatic checks

| Check | Where | Purpose |
|---|---|---|
| Own rules (`scripts/check_actions_policy.py`) | `security-policy.yml` | explicit permissions, SHA pinning, no dangerous triggers, no secrets/write permissions in PR workflows, no `curl \| sh` |
| actionlint, zizmor (offline) | `security-policy.yml` | syntax, shell errors, injection via `${{ }}`, permissions |
| CodeQL (Rust, Python, Actions) | `codeql.yml` | static analysis |
| gitleaks (archive verified by SHA-256) | `ci.yml` | secrets in history |
| cargo-deny, weekly advisory audit | `ci.yml`, `audit.yml` | licences, sources, known vulnerabilities |
| Dependabot (weekly, 7-day cooldown), security updates | `.github/dependabot.yml` | current crates and actions |
| Secret scanning with push protection | GitHub setting | reject secrets on push |

Deliberately **not** used (reasons in #180/#181/#185): Trivy, GitGuardian, SonarCloud, Semgrep,
Checkov/KICS, ZAP, Renovate – they duplicate existing checks or do not fit a CLI project without
containers, infrastructure code or a web service.

### GitHub settings (read on 2026-11-14)

| Area | Current | Assessment |
|---|---|---|
| Ruleset `main` | no deletion, no force push, linear history, signed commits, pull request with squash only, all review threads resolved, 9 required checks (CI on Linux/Windows, MSRV, limits, binary hardening, cargo-deny, gitleaks); **no** bypass actors | good |
| Ruleset tags `v*` | no deletion, update, force push; bypass for repository admins only | good (needed to create tags) |
| CODEOWNERS | file present, code owner review **not** required by the ruleset | correct: with a single maintainer the requirement would block every merge |
| Environment `release` | maintainer approval required, self-approval allowed; **no** restriction to tags/branches | open, see below |
| Actions settings | all actions allowed, SHA pinning not enforced, token "read", Actions cannot approve reviews | open, see below |
| Secrets | repository: `GEMINI_API_KEY` (for the OpenCode trial #176, used by no workflow on `main`); environment `release`: none | open, see below |

### Open items

Ordered by benefit; each item is a setting or its own small pull request.

1. **Restrict environment `release` to tags `v*`** (setting "Deployment branches and tags").
   Today a manual run from any branch can request approval (#186).
2. **Remove `GEMINI_API_KEY` from the repository secrets** until #176 is decided; if needed, add
   it later as an environment secret with approval. A repository secret is readable by any
   workflow on any branch created by someone with write access (#183).
3. **Enforce SHA pinning in the Actions settings** ("Require actions to be pinned to a full-length
   commit SHA"). The workflows already comply (#181).
4. **Do not make `Workflow-Prüfung / workflow policy` a required check:** because of its path
   filter the workflow only runs on workflow changes; a required check that never starts blocks
   every other pull request.
5. **Release order:** `publish` creates the release **draft** before `verify` has checked the
   manifest, checksums, attestations and signatures. The draft is not public and is published by
   hand – so publish only after `verify` is green (as stated in [RELEASE.md](../RELEASE.md)).
   Reordering (verify first, then draft) is possible but needs its own pull request with a trial
   run (#186).
6. **Runtime downloads:** `cargo install --locked` (cargo-deny, cargo-cyclonedx) and `go install`
   (actionlint) fetch source code at fixed versions with checksums from the lockfile or the Go
   checksum database, but build it on the runner. No secret is reachable in these jobs; residual
   risk: manipulated check results (#185).
7. **Outbound network traffic** of the runners is unrestricted. Harden-Runner in audit mode for
   the `publish` job is an option should a long-lived secret ever be needed there (#185).
8. **External monitoring** (#187) does not exist. For a one-person project, GitHub's notifications
   for workflow runs, releases and security alerts are enough for now; a separate monitoring
   service would add more attack surface than benefit.

Not part of `main`: the OpenCode workflow (#176, #184). It will be assessed once it is decided
whether it comes at all.

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
