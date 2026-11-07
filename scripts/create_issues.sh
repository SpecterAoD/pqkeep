#!/usr/bin/env bash
# DE: Legt Labels und Issues für den Fahrplan an. Einmalig ausführen, nachdem das Repo existiert und `gh auth login` erledigt ist.
# EN: Creates labels and issues for the roadmap. Run once after the repo exists and `gh auth login` is done.
# Usage: ./scripts/create_issues.sh [owner/repo]
set -euo pipefail
REPO="${1:-SpecterAoD/pqkeep}"

gh label create roadmap  -R "$REPO" -c 0E8A16 -d "Roadmap step" 2>/dev/null || true
gh label create security -R "$REPO" -c B60205 -d "Security relevant" 2>/dev/null || true
gh label create release  -R "$REPO" -c 5319E7 -d "Release / signing" 2>/dev/null || true
gh label create chore    -R "$REPO" -c C5DEF5 -d "Repo / organisation" 2>/dev/null || true

issue() { # title, labels, body
  gh issue create -R "$REPO" --title "$1" --label "$2" --body "$3"
}

issue "Schritt 0: Projekt-Grundgerüst" "roadmap" "Cargo-Projekt, Lints (forbid(unsafe_code)), error.rs, CI-Rumpf, Zeilenlimit-Check. Siehe docs/SPEC.md Abschnitt 7.
- [ ] Plan freigegeben
- [ ] Build und Lint grün auf Linux und Windows
- [ ] Definition of Done (docs/CHECKLIST.md)"
issue "Schritt 1: Core-Krypto (ML-KEM, ML-DSA, Argon2id, AES-256-GCM)" "roadmap,security" "Roundtrip-, Manipulations-, KAT-, Zeroize- und KDF-Grenzwerttests. Siehe docs/SPEC.md.
- [ ] Plan freigegeben
- [ ] Crate-Auswahl begründet
- [ ] Tests in eigenen Dateien
- [ ] Definition of Done"
issue "Schritt 2: Passphrase-Prüfung und Generator" "roadmap,security" "security.rs: Stärkeprüfung, Entropie, Generator ohne Modulo-Bias, NFKC-Normalisierung.
- [ ] Plan freigegeben
- [ ] Tests schwach/stark/Entropie/Unicode
- [ ] Definition of Done"
issue "Schritt 3: JSON-Container (envelope.rs)" "roadmap,security" "Format, Metadaten, Parser-Härtung, Downgrade-Schutz, Pfadkonventionen Windows/Linux, Fuzz/Property-Tests.
- [ ] Plan freigegeben
- [ ] docs/FORMAT.md
- [ ] Definition of Done"
issue "Schritt 4: CLI mit integrierter zweisprachiger Hilfe" "roadmap" "Menü, Subcommands, help <thema>, Manpage, Completions, Hilfetests DE/EN.
- [ ] Plan freigegeben
- [ ] Hilfetests in beiden Sprachen
- [ ] Definition of Done"
issue "Schritt 5: REST-API (Axum)" "roadmap,security" "Endpunkte /v1/generate, /v1/validate, /v1/health. Bind 127.0.0.1, Token-Auth, Limits, DoS-Schutz.
- [ ] Plan freigegeben
- [ ] HTTP-Integrationstests inkl. Auth/Limits
- [ ] Definition of Done"
issue "Schritt 6: CI/CD, Release-Workflow und Dokumentation" "roadmap,release" "ci.yml, release.yml (Attestation, Sigstore, SBOM, Prüfsummen), zweisprachige README, THREAT_MODEL.md.
- [ ] Plan freigegeben
- [ ] Beta-Trockenlauf mit automatischer Verifikation
- [ ] Definition of Done"
issue "Schritt 7: Abschluss-Review und erste signierte Beta" "roadmap,release,security" "Selbstreview nach Abschnitt 5b, cargo audit/deny sauber, v0.1.0-beta.1 veröffentlichen und Verifikation nachvollziehen.
- [ ] Release-Checkliste in docs/CHECKLIST.md"
issue "Repo öffentlich schalten und SignPath-Bewerbung" "chore,release" "Voraussetzung: öffentliches Repo, Apache-2.0, kein proprietärer Code, MFA. Danach Bewerbung bei der SignPath Foundation.
- [ ] Repo öffentlich
- [ ] Bewerbung gestellt
- [ ] SignPath-Variablen und Secret im Environment 'release' gesetzt"
issue "GitHub-Schutzeinstellungen" "chore,security" "- [ ] Branch Protection auf main (Review, Checks, signierte Commits, keine Force-Pushes)
- [ ] Secret Scanning und Push Protection
- [ ] Private Vulnerability Reporting
- [ ] Environment 'release' mit Reviewer
- [ ] Signing-Key für Git-Tags"
