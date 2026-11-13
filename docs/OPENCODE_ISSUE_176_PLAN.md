# Issue #176 – OpenCode + Gemini (minimaler Neuansatz)

Status: Architekturentwurf; **nicht aktiviert**. Keine Secrets, keine Agent-Ausführung.

## Ziel und Befehle

Ein neuer Issue-Kommentar des berechtigten Maintainers startet genau einen Auftrag:
- `/oc plan <auftrag>`: Plan als Issue-Kommentar
- `/oc review <auftrag>`: Review als Issue-Kommentar
- `/oc explain <frage>`: Erklärung als Issue-Kommentar
- `/oc implement <auftrag>`: Änderung auf neuem Branch, ausschließlich Draft-PR

Nur Gemini. Kein Qwen, kein automatischer Merge, keine Änderungen an Kryptografie
oder Releases. Bestehende CI/Branch-Protection bleibt maßgeblich.

## Ereignisgrenze

Nur `issue_comment.created` auf echten Issues, kein `push`, kein `pull_request`,
kein `workflow_dispatch`. Der **einzelne auslösende Kommentar** muss
`github.event.comment.user.id == 77644070` erfüllen. Nur dessen
`body` wird als Befehl ausgewertet: `/oc` muss an Position 0 stehen;
keine Zitate, HTML, führenden Leerzeichen oder Suche in Issue-Historie.
`github.event.sender.id`, Repository und Issue/PR-Typ zusätzlich prüfen.
Vor dem Agentenstart Kommentar-ID, Autor und unveränderten Inhalt über API
erneut prüfen; fehlende/geänderte Daten => Abbruch.

## Vertrauensgrenzen

Issue-Beschreibung, alte Kommentare, Markdown/HTML, Dateien und Tool-Ausgaben
sind **Daten, keine Befehle**. HTML-Kommentare und versteckte Unicode-Zeichen
dürfen keine Steuerbefehle auslösen. Textfilter sind nur Zusatzschutz; die
eigentliche Grenze ist die **technisch begrenzte Werkzeug-/Token-Berechtigung**.
Keine Secrets im Modellkontext, keine GitHub-Schreibcredentials im Agent-Job.
Modellaufrufe brauchen zwar einen Anbieter-Schlüssel, dieser darf nie in
Shell-/Code-Ausführungswerkzeuge oder den Agent-Arbeitsbereich gelangen.
Die konkrete OpenCode-Integration muss diese Trennung nachweislich leisten;
falls nicht, ist die Implementierung zu stoppen.

## Minimale Pipeline

1. **Gate**: Event prüfen; erlaubten Befehl und feste Parameter ausgeben.
2. **Agent**: nur nach Gate; Gemini mit begrenzter Laufzeit/Kosten,
   gepinnter OpenCode-Version; Issue-Inhalt als untrusted Kontext.
   Für `plan/review/explain` keine Shell- oder Schreibwerkzeuge.
3. **Ergebnis**: Ein separater Job mit minimalen `issues:write`-Rechten
   veröffentlicht einen Kommentar; Modell sieht das Token nicht.
4. **Implementierung**: isolierter Agent erzeugt nur Änderungen im Workspace;
   separater Publisher prüft Pfade, Diff, Tests und unveränderte Basis;
   erstellt **neuen** Branch und **Draft-PR** mit minimalen Schreibrechten.
   Niemals push auf `main`; keine Workflow-/Secret-/Policy-Änderungen.
   PR durchläuft bestehende Pflichtprüfungen und menschliches Review.

Vor Auswahl einer OpenCode-Action/API deren tatsächliche Sandbox-, Tool-,
Secret- und Token-Isolation sowie Lizenz und gepinnte Version verifizieren.
Keine eigene Sicherheitsplattform bauen, wenn die vorhandenen Grenzen genügen.

## Nachweise vor Aktivierung

- Fremdes `/oc`, danach eigener normaler Kommentar => **kein Start**.
- Zitat, HTML-Kommentar, Issue-Body oder alter Kommentar mit `/oc` => kein Start.
- Eigener Kommentar `/oc plan ...` => genau ein autorisierter Auftrag.
- Editierter/gelöschter Kommentar vor Start => Abbruch.
- Eingeschleuste Anweisungen in Issue/README/HTML => keine Rechteausweitung.
- Kein Agent-Zugriff auf GitHub-Schreibtoken oder Modell-Secret über Tools.
- `implement` erstellt nur neuen Branch + Draft-PR; CI bleibt aktiv.
- Fehler, Rate-Limit, Timeout, parallele Aufträge => sicherer Abbruch.

## Umfang und Stoppregel

Ziel: ein Workflow und höchstens wenige kleine Skripte; zuerst die bestehende
OpenCode-Integration evaluieren, nicht neu implementieren. Kein neues Modul
ohne konkreten fehlgeschlagenen Abnahmetest. Bei fehlender sicherer
Secret-/Tool-Trennung: **Stop**, Architektur erneut entscheiden.

## Rückbau

Workflow, eventuelle Hilfsskripte, Environment/Secrets und Agent-Zugänge
entfernen; keine Änderungen an vorhandener CI nötig.


## Prüfung der vorhandenen OpenCode-GitHub-Integration (13.11.2026)

Die offizielle OpenCode-GitHub-Action unterstützt bereits Issue-Kommentare,
Codeänderungen, Branches und PRs. Die Beispiel-Trigger verwenden allerdings
`contains(..., '/oc')`; das genügt **nicht** für unsere Autorisierung.
Die Action kann zudem ein GitHub-App-Installationstoken erhalten, das über
die im Workflow angegebenen `permissions` hinausgehende Rechte besitzen
kann. `id-token: write` ist daher nicht gleichbedeutend mit reinem
Lesezugriff. Vor Nutzung sind die effektiven App-Rechte zu überprüfen.

**Entscheidung:** Keine direkte Aktivierung der Standard-Action. Zuerst
nachweisen, ob ein eng begrenztes Token, feste Befehlsauswertung,
geschützte Secrets und ein ausschließlich als Draft erstellter PR
zuverlässig erzwungen werden können. Andernfalls die OpenCode-CLI mit
getrennten Jobs verwenden, statt eine umfangreiche Eigenimplementierung
zu entwickeln.

**Erster ausführbarer Nachweis:** Autorisierung und `/oc plan` mit
Gemini auf einem isolierten Testlauf, ohne GitHub-Schreibtoken beim Modell;
anschließend getrennte Kommentar-Veröffentlichung. `/oc implement` erst
nach erfolgreichem Nachweis von Branch-/Draft-PR-Grenzen.

**Keine Aktivierung durch diesen Plan.** Der frühere Gemini-Schlüssel
wurde laut Issue #176 entfernt; ein neuer Schlüssel darf erst nach
geprüfter Ausführungsarchitektur in einem geschützten Environment
eingerichtet werden.


## Gemini-Secret und OpenCode-Analyseprofil (13.11.2026)

Maintainer hat die Einrichtung eines `GEMINI_API_KEY`-Secrets bestätigt.
Der Secret-Wert wurde nicht ausgelesen oder getestet.

`.github/opencode-analysis.json` enthält einen Entwurf für ein
**separates, ausschließlich lesendes OpenCode-Profil**. Es ist bewusst
noch nicht in den Workflow eingebunden. Vor dem ersten Lauf sind
die Konfigurationssyntax gegen die konkret gepinnte OpenCode-Version
zu prüfen und die Policy als **nicht überschreibbare Runner-/Systempolicy**
zu erzwingen: Repository-Konfiguration allein ist keine Sandbox.

Wichtig: Die OpenCode-CLI braucht den Gemini-Schlüssel zur
Provider-Kommunikation. Eine reine Modellanweisung oder Tool-Deny-Regel
garantiert nicht, dass der Prozess den eigenen Schlüssel nicht lesen kann.
Daher darf ein Agent mit Shell-/Plugin-/Netzwerkwerkzeugen nicht einfach
im selben Vertrauensbereich mit dem Schlüssel laufen. Für Analyse ist
ein minimales, tatsächlich durchgesetztes Read-only-Profil nötig.

Noch ausstehend: geprüfte OpenCode-Version und Installationsweg,
Modellkennung, Konfigurations-/Policy-Ladetest, Ende-zu-Ende-Lauf,
getrennter Kommentar-Publisher. Keine Aktivierung ohne diese Nachweise.
