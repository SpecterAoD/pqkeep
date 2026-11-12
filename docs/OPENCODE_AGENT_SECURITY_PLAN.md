# OpenCode Issue Agent – Sicherheitskonzept (Entwurf)

Status: **Design / keine Aktivierung**. Die vorhandene Action bleibt unverändert, bis alle Sicherheitsgates implementiert und getestet sind.

## Ziel

Ein exakt `/oc` lautender neuer Kommentar auf einem regulären Issue in `SpecterAoD/pqkeep` darf ausschließlich durch die fest hinterlegte GitHub-User-ID des Maintainers einen einmaligen Gemini-basierten Änderungsvorschlag auslösen. Ergebnis ist ausschließlich ein **Draft-Pull-Request**. Automatisches Mergen ist verboten. Die bestehende PR-CI prüft Rust-Code.

## Bedrohungsmodell

Unvertrauenswürdig sind Issue-Titel/-Text, Kommentare, Repository-Dateien, Abhängigkeiten, Modellantworten, generierte Patches und Artifacts. Auch ein berechtigter Issue-Autor schützt nicht vor später editierten Issue-Inhalten. Prompt Injection und schädliche Codeänderungen sind trotz Systemprompt möglich.

## Verbindliche technische Gates

1. **Authentifizierung vor Secret-Zugriff:** `issue_comment.created`, reguläres Issue, festes Repository, exakter Kommentar `/oc`, `sender.type == User`, numerische `sender.id` gegen fest konfigurierte Maintainer-ID. Nicht allein `login` prüfen. Erneute Autorisierung und Prüfung der Issue-Metadaten über die GitHub API im Read-only-Kontext. Fail closed bei Abweichung.
2. **Issue-Snapshot:** Issue-Nummer, Titel, Beschreibung, Autor-ID, `updated_at` und Base-Commit-SHA erfassen. Keine fremden Kommentare, URLs oder Anhänge als Instruktionen übernehmen. Bei relevanter Änderung vor Veröffentlichung abbrechen.
3. **Agenten-Isolation:** Kein GitHub-Schreibtoken, keine persistierten Checkout-Credentials, keine Host-Mounts, keine Privilegieneskalation. Agent im unprivilegierten Container mit CPU-/RAM-/Zeitlimit; ausgehendes Netzwerk nur für den zwingend erforderlichen Gemini-Endpunkt, nach expliziter technischer Prüfung. Google-API-Key bleibt für den Agentenprozess erreichbar; ein Prompt kann seine Exfiltration versuchen. Deshalb sind Egress-Regeln Pflicht.
4. **Konfiguration:** Versionen und Actions auf überprüfte unveränderliche Digests/SHAs pinnen. CI-spezifische OpenCode-Konfiguration außerhalb des bearbeitbaren Arbeitsverzeichnisses; tatsächliche Berechtigungssyntax gegen die gepinnte Version prüfen. Kein kostenpflichtiger Modell-Fallback.
5. **Keine Befehlsausführung durch Modell:** Shell-, Web-, externe Verzeichnis- und Subagent-Tools im Agenten sperren. Nur notwendige Lese-/Editierwerkzeuge freigeben. Keine Ausführung von Projekt-Buildskripten im Agentenjob.
6. **Patch-Validierung:** Im separaten vertrauenswürdigen Job Patch strikt parsen (inkl. Renames, Copies, Mode-Änderungen, Symlinks, Binärdaten, Submodule, Pfad-Traversal, Case-Folding, Unicode-Sonderfälle), Größen- und Dateianzahllimits. Denylist allein reicht nicht: Nur explizit freigegebene Pfade zulassen. Besonders `.github/**`, `opencode.json*`, `.opencode/**`, `Cargo.toml`, `Cargo.lock`, `build.rs`, `scripts/**`, `docs/SPEC.md`, `SECURITY.md`, `src/**` zunächst **nicht** automatisch freigeben. Kryptografie/Schlüsselverwaltung nur manuell.
7. **PR-Erstellung:** Ein frischer Runner ohne Gemini-Key, fester Base-SHA, kein Checkout/Run untrusted code, Patch erneut validieren, separater kurzlebiger minimal berechtigter Schreib-Credential. Ausschließlich `refs/heads/opencode/...` pushen. Draft-PR öffnen. Kein Merge-API-Aufruf, kein Auto-Merge.
8. **CI-Auslösung:** PRs, die mit `GITHUB_TOKEN` angelegt werden, lösen gewöhnlich keine neuen `pull_request`-Workflows aus. Für die bestehende CI daher bewusst einen geeigneten, minimal berechtigten GitHub-App-Token oder einen gesondert abgesicherten Prüfmechanismus planen. Keine Umgehung von Branch-Protection.
9. **Schutz des Default-Branches:** GitHub Ruleset: verpflichtende Statuschecks, mindestens eine manuelle Freigabe, kein Bypass für Bot, kein Force-Push, kein automatischer Merge. CODEOWNERS allein ist kein wirksames Gate ohne aktivierte Review-Regel.
10. **Audit:** Run-ID, Issue-ID, User-ID, Base-SHA, Modell-ID, Dateiliste, Patch-Hash und PR-URL protokollieren; keine API-Keys, Prompt-Inhalte mit Secrets oder vollständigen sensitiven Modellantworten loggen.

## Testplan vor Aktivierung

- Unberechtigter Benutzer, Bot, umbenannter Account, PR-Kommentar, `/oc foo`, `/oc\n...`, editierter Kommentar und fremdes Repository dürfen keinen Agenten starten.
- Manipulierte Issue-Texte/README mit Prompt-Injection dürfen keine zusätzlichen Tools, Secrets oder Netzwerkziele freischalten.
- Patch mit Workflow-Änderung, Krypto-Datei, Symlink, Rename, Traversal, Binärdatei, übergroßem Inhalt oder manipuliertem Artifact muss blockiert werden.
- API-Quota-Fehler, fehlender Key, ungültiges Modell, Agent-Timeout, geändertes Base-SHA und fehlgeschlagener Push müssen fail closed enden.
- Test-PR muss die bestehende `CI` tatsächlich auslösen; kein automatischer Merge.
- Freigabe erst nach dokumentiertem Testlauf und manueller Review.

## Repository-Befund

- `.github/workflows/opencode.yml` reagiert bisher nur auf PR-Kommentare, erlaubt Schreibrechte im Agentenjob und verwendet OpenRouter/Qwen.
- `opencode.json` verwendet noch OpenRouter/Qwen und `bash: ask`.
- `.github/workflows/ci.yml` führt bereits Rust fmt, Clippy, Tests, MSRV, Binary Hardening, cargo-deny und gitleaks bei Pull Requests aus.
- `.github/CODEOWNERS` nennt den Maintainer, ersetzt aber keine GitHub-Ruleset-Einstellungen.

## Rollback

Die bestehende Action wird in dieser Planungsphase nicht verändert. Spätere Aktivierung in eigenem PR, nach Tests und manueller Freigabe. Rollback durch Revert der Action-/Konfigurationsänderung und Deaktivierung des Workflows. API-Key bei Verdacht sofort rotieren.
