# PR #171 – Merge-Checkliste (Sicherheitsgrundlage)

Stand: 2026-11-13. **Keine Merge- oder Aktivierungsfreigabe.**

## Ziel des Merges

**Kein Zwischen-Merge.** PR #171 wird erst nach vollständiger Implementierung,
Sicherheitsprüfung und kontrolliertem End-to-End-Test des testfähigen
`/oc`-Assistenten für die Freigabe vorgeschlagen. Vorher bleibt
`main` unverändert und der produktive Agent deaktiviert.

Die spätere Freigabe erlaubt ausschließlich das Erstellen neuer Feature-Branches
und **Draft-PRs**; niemals automatische Merges oder Änderungen direkt an `main`.

## Pflichtprüfungen vor dem Merge

- [ ] `main`-Änderungen in den Feature-Branch integrieren; Konflikte manuell prüfen.
- [ ] Neuen Head-SHA ermitteln; CI, CodeQL und OpenCode-Gate für **genau diesen SHA** erfolgreich.
- [ ] `.github/workflows/opencode.yml` bleibt Authorization-only, ohne Gemini-Secret,
      Agent-Ausführung, Artifact-Publishing und GitHub-Schreibberechtigungen.
- [ ] GitHub-Workflow-Berechtigungen und Branch-Protection/Review-Regeln prüfen.
- [ ] Unabhängiges Review des Workflows und der Sicherheitsmodule durchführen;
      vorhandene offene Blocker aus `OPENCODE_AGENT_SECURITY_REVIEW.md` bestätigen.
- [ ] Sicherstellen, dass Publisher-/Patch-Module durch keinen produktiven Workflow
      aufgerufen werden; insbesondere untrusted Patch-Header vor `git apply`
      noch nicht ausreichend vorvalidiert.
- [ ] Keine ungewollten Änderungen außerhalb des OpenCode-Bereichs.
- [ ] Repository-Eigentümer erteilt **ausdrückliche** Merge-Freigabe.

## Zusätzlich zwingend vor dem Merge

- [ ] Separater isolierter Agentenlauf ohne Schreibtoken und ohne Secret-Exposition.
- [ ] Verifizierte Event-Bindung, Artefaktherkunft und Publisher-Trennung.
- [ ] Laufzeitnachweis der Netzwerkisolation sowie überprüftes Container-Image.
- [ ] Publisher ausschließlich für neue Branches und Draft-PRs; kein Auto-Merge.
- [ ] Explizite Aktivierungsfreigabe nach End-to-End- und Negativtests.

**Hinweis:** Ein erfolgreicher Merge allein ist keine automatische Freigabe
des KI-Agenten. Die Aktivierung benötigt eine gesonderte ausdrückliche Freigabe.
Bis dahin darf der produktive Workflow keine KI-Ausführung starten.
