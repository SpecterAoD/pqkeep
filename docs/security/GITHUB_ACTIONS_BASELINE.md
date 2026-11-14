# GitHub Actions Security Baseline — PQKeep

**Stand:** 2026-11-14 · **Issue:** #180 · **Status:** vorläufige, überprüfbare Bestandsaufnahme; kein vollständiger GitHub-Settings-Audit.

## 1. Scope und Nachweisgrenzen

Untersucht wurden die auf `main` direkt abgerufenen Dateien `.github/workflows/ci.yml`, `codeql.yml`, `release.yml`, `.github/CODEOWNERS` sowie auf `feature/176-opencode-gemini` die Dateien `.github/workflows/opencode.yml` und `scripts/oc_gate.py`. **Nicht nachgewiesen** ist, dass dies alle Workflows aller aktiven Branches sind. Die GitHub-Connector-Abfragen liefern keine vollständige Sicht auf Rulesets, Branch Protection, Environments, Secret-Metadaten, GitHub Apps oder Security-Log. Diese Punkte sind als **unverifiziert** markiert; Aussagen aus dem früheren Issue #10 sind Konfigurationsabsichten und kein aktueller API-Nachweis.

Das Repository ist öffentlich; Standardbranch `main`. Keine Secret-Werte wurden gelesen. Dieser PR verändert ausschließlich Dokumentation.

## 2. Verifizierte Workflow-/Job-Matrix

| Ref / Workflow | Trigger | Jobs / Runner | Tokenrechte | Secrets / Vertrauensgrenze | Artefakte / Risiken |
|---|---|---|---|---|---|
| main / CI | push main, pull_request | test (Ubuntu latest/22.04/ARM, Windows); msrv, limits, binary, deny, gitleaks (Ubuntu bzw. Matrix) | workflowweit `contents: read` | kein expliziter Secret-Verweis; PR-Code und Rust-Buildskripte sind untrusted | gitleaks mit `fetch-depth: 0`; Cargo-Dependencies und Installer beachten |
| main / CodeQL | push main, pull_request, wöchentlicher schedule, dispatch | analyze (Rust/Python/Actions; Ubuntu) | `contents: read`; Job zusätzlich `security-events: write`, `actions: read` | kein expliziter Repository-Secret-Verweis; PR-Kontext prüfen | CodeQL-Actions per SHA gepinnt |
| main / Release | v*-Tag push, dispatch, eingeschränkte pull_request-Pfade | prepare; build (Linux/Windows/ARM); debian; manifest; publish; verify | workflowweit `contents: read`; publish: `contents: write`, `id-token: write`, `attestations: write`; verify: `attestations: read` | publish nutzt `environment: release`; tatsächliche Reviewer-/Ref-Regeln **unverifiziert** | Build-/Debian-/Lifecycle-Artefakte; Herkunft und Digests bis Publish verifizieren |
| feature/176-opencode-gemini / OpenCode (nicht main) | pull_request (Pfadfilter), issue_comment created, dispatch | preflight, authorize, gemini-pr-smoke (Ubuntu) | workflowweit `contents: read`; gemini-pr-smoke: `permissions: {}` | authorize prüft Owner-ID und Live-Kommentar; authorize und gemini-pr-smoke verwenden `GEMINI_API_KEY` in nachgelagerten CLI-Schritten | npm installiert `@opencode/cli@2.2.7` dynamisch; Supply-Chain-/Egress-Risiko; kein Checkout im Secret-PR-Smoke |

**Hinweise:** Für `release.yml` wurden Jobnamen, explizite Rechte und Trigger verifiziert; eine vollständige Zeilen-für-Zeilen-Datenflussprüfung sämtlicher Build-/Publish-Schritte ist noch offen. Auf dem Feature-Branch sind nur die oben genannten Dateien geprüft. `CODEOWNERS` enthält `* @SpecterAoD` und `/.github/ @SpecterAoD`; die tatsächliche Erzwingung ist nicht verifiziert.

## 3. Trust Boundaries und Bedrohungsmodell

| Angriffsweg | Mögliches Schadensbild | Bestehende beobachtete Kontrolle | Offener Nachweis / Folge-Issue |
|---|---|---|---|
| Fremder PR mit manipuliertem Code | Ausführung bösartiger Build-Skripte, Cache-/Artefaktvergiftung | CI read-only, kein explizites CI-Secret, Checkout ohne persistierte Credentials | PR-Tokenrechte/Runner-Isolation prüfen; #181, #183 |
| Fremder Issue-Kommentar oder zitierter `/oc`-Befehl | Agent wird unautorisiert gestartet | Owner-ID, `created`, Top-Level-Befehl, Live-Abgleich in `oc_gate.py` | Negativtests inkl. HTML, Unicode, Replay, Re-Check direkt vor Secret-Nutzung; #184 |
| Prompt Injection in Issue-/PR-Text | Modell übernimmt fremde Anweisungen | Read-only-Prompt und bisher kein Publish | Modellantwort ist nicht vertrauenswürdig; Tool-Allowlist und getrennte Freigabe; #184 |
| Kompromittiertes npm-/Cargo-Paket oder Action | Secret-Exfiltration, manipulierte Binaries | SHA-gepinnte GitHub-Actions; gitleaks/cargo-deny | CLI-Version ist keine Integritätsgarantie; Prüfsummen, Lockfiles, Egress; #185 |
| Manipulierter Workflow / gestohlene GitHub-Sitzung | Neue Secret-lesende Jobs, Rechteausweitung | CODEOWNERS vorhanden; Issue #10 dokumentiert Branch-Schutz | Rulesets/Bypass, Reviews und Settings unabhängig verifizieren; #182 |
| Untrusted Build-Artefakt im Release | Trojanisierte Veröffentlichung | Separater Publish-Job, signierte Tags, Attestations-Konfiguration | Build→Manifest→Publish-Digestkette vollständig nachweisen; #186 |
| Kurzlebiger Schadworkflow und gelöschte Runs | Spurenverlust | kein externer Monitor nachgewiesen | Unabhängige Speicherung und Alarmierung; #187 |
| Secrets via HTTP/DNS/Logs/Artefakte | API-Key-/Token-Abfluss | kein expliziter Secret-Verweis in CI; Secrets auf bestimmte OpenCode-Jobs begrenzt | Ausgehende Netzwerkverbindungen sind nicht automatisch blockiert; #183, #185 |

**Schutzgrenze:** Passwort und aktivierter zweiter Faktor sind vorhandene Kontoschutzmaßnahmen laut Maintainer. Es werden **keine** verpflichtenden Passkeys, Hardware-Sicherheitsschlüssel oder pauschalen PAT-Umstellungen gefordert. Eine vollständige Kontoübernahme bleibt ein Restrisiko, das Repository-interne Regeln nicht allein beseitigen.

## 4. Konkrete Feststellungen und Prioritäten

- **P0 / #183, #184:** `authorize` führt nach erfolgreicher Autorisierung einen dynamisch installierten npm-CLI-Prozess mit `GEMINI_API_KEY` aus. Bei Kompromittierung des CLI-Pakets kann der Prozess den Schlüssel lesen. Vor privilegierten Schritten muss der Autorisierungsnachweis erneut gebunden/überprüft werden.
- **P0 / #181:** `actionlint` und `zizmor` sind in den geprüften main-Workflows nicht als eigene Policy-Gates ersichtlich; vollständige Repository-Suche steht aus.
- **P0 / #182:** `CODEOWNERS` ist vorhanden; seine Durchsetzung über Branch-/Ruleset-Einstellungen ist nicht verifiziert. Solo-Maintainer darf nicht ausgesperrt werden.
- **P1 / #185:** `cargo install --locked` und `npm install --global` laden externe Pakete zur Laufzeit. Gitleaks-Archiv wird bereits mit SHA-256 geprüft. Zusätzliche Supply-Chain-Prüfung ist nötig.
- **P1 / #186:** Publish ist isoliert und erhält die für Release benötigten erhöhten Rechte; die genaue Provenance-/Artefakt-Verifikation ist noch nachzuweisen.
- **P1 / #187:** Externes, manipulationserschwerendes Monitoring ist nicht nachgewiesen. Fehlende Run-Nummern sind kein Beweis einer Kompromittierung.

## 5. Noch offene GitHub-Settings-Prüfungen

- [ ] Vollständige Liste sämtlicher Workflows/aktiver Branches und Job-Rechte gegen GitHub-API verifizieren
- [ ] Branch Protection/Rulesets inkl. Bypass, Force-Push, Required Checks und CODEOWNERS-Durchsetzung prüfen
- [ ] Environment `release`: Required Reviewers, Deployment Branches/Tags, Wait Timer, Self-Approval und Admin-Bypass prüfen
- [ ] Secret-Namen und Sichtbarkeitsbereiche **ohne Werte**; Repository-/Environment-/Organisationsebene, OIDC, PAT-/App-Berechtigungen inventarisieren
- [ ] Actions-Settings: erlaubte Actions, Default-Tokenrechte, Fork-PR-Workflow-Berechtigungen prüfen
- [ ] Externe Audit-Log-/Monitor-Möglichkeiten und GitHub-Planlimits dokumentieren
- [ ] Release-Artefakte, Caches, Upload/Download-Schritte und Digest-Validierung vollständig bis zum Publish nachverfolgen
- [ ] Negativtestmatrix aus #181–#187 gegen tatsächliche Workflows finalisieren

## 6. Abdeckung des Maßnahmenplans

| Ursprünglicher Abschnitt | Umsetzungs-Issue |
|---|---|
| 1: Manipulationsschutz, Secret-Isolation, Egress, OpenCode, Monitoring, Release | #181–#187 |
| 2a Workflow-Manipulationsschutz | #181, #182 |
| 2b Secret-Isolation | #183, #184 |
| 2c Netzwerk-/Egress-Kontrolle | #185 |
| 2d automatische Manipulationserkennung | #181, #187 |
| 2e Release-Isolation | #186 |
| 3 externe Überwachung und Incident-Runbook | #187 |

## 7. Abnahme und Rollback

**Definition of Done für #180:** Alle oben offenen Prüfungen mit überprüfbaren Quellen/Datum abgeschlossen, vollständige Workflow-/Job-Matrix, dokumentierte Negativszenarien, Restrisiken und Prioritäten; Review bestätigt Abdeckung. Bis dahin **Issue offen lassen**.

**Tests:** Dokumentationsdiff muss ausschließlich `docs/security/GITHUB_ACTIONS_BASELINE.md` enthalten; keine Secrets, keine Workflow-/Runtime-Änderung. **Rollback:** Dokumentations-Commit revertieren.

**Quellen im Repository:** [CI](../../.github/workflows/ci.yml), [CodeQL](../../.github/workflows/codeql.yml), [Release](../../.github/workflows/release.yml), [CODEOWNERS](../../.github/CODEOWNERS), [Issue #10](https://github.com/SpecterAoD/pqkeep/issues/10), [Issue #176](https://github.com/SpecterAoD/pqkeep/issues/176), [Issue #180](https://github.com/SpecterAoD/pqkeep/issues/180). OpenCode-Beobachtungen beziehen sich auf den separaten Branch `feature/176-opencode-gemini`.
