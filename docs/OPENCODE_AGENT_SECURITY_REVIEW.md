# OpenCode Agent – Sicherheitsreview (vor Aktivierung)

Status: **BLOCKIERT**. Dieses Dokument erteilt keine Freigabe für Gemini,
GitHub-Schreibrechte, automatische Branch-Erstellung oder PR-Erstellung.

## Behobener Befund: Issue-Snapshot nicht an erwartetes Issue gebunden

Die gemeinsame Publisher-Prüfung verwendete zuvor den Snapshot nur innerhalb
des Artefaktvergleichs. Ein zum Artefakt passender, aber falscher Snapshot
konnte damit die erwartete Issue-Nummer umgehen. Die gemeinsame Prüfung
verlangt jetzt vor dem Patch-Review eine echte Integer-Issue-Nummer, die exakt
dem unabhängig erwarteten Issue entspricht. Regressionstest ergänzt.

## Offene Blocker

1. **Issue-/Kommentar-Vertrauen:** Der Publisher vergleicht den vollständigen
   Issue-Snapshot inzwischen mit einer frischen GitHub-API-Antwort und verwirft
   nachträgliche Änderungen. **Offen:** Die ursprüngliche `/oc`-Kommentar-ID
   und deren Autorisierung müssen aus unabhängig vertrauenswürdigen Run-Daten
   abgeleitet und unmittelbar vor Veröffentlichung erneut geprüft werden.
   **Wichtig:** Die Actions-Run-API liefert die auslösende Kommentar-ID
   nicht als eigenständigen vertrauenswürdigen Beleg. Ein vom Agenten
   geliefertes Manifest oder eine frei gesetzte Umgebungsvariable reicht
   nicht aus. Erforderlich ist eine separat attestierte Bindung
   `repository + run_id + issue_id + comment_id + base_sha`, erzeugt
   im autorisierten Preflight und vom Publisher unabhängig überprüft.
   Bis dahin bleibt jede Veröffentlichung gesperrt.
2. **Actions-Lauf/Artefakt:** Die Herkunftsprüfung muss auf einen echten
   erfolgreichen Agent-Lauf zugeschnitten werden. Der derzeit aktive
   `opencode.yml` ist absichtlich nur ein Autorisierungs-Hold und erzeugt
   kein Agent-Artefakt. Kein Workflow darf deshalb aktuell publizieren.
3. **Download-Protokoll:** Die äußere GitHub-ZIP-Verpackung und die innere
   Manifest-/Patch-ZIP-Struktur müssen mit echten GitHub-Actions-Artefakten
   getestet werden. Die Download-Host-Allowlist muss gegen das tatsächliche
   GitHub-Redirect-Verhalten geprüft werden.
4. **Race Condition:** Branch-Nichtexistenz und `main`-SHA können sich nach
   dem read-only Preflight ändern. Der Publisher benötigt eine atomare
   Branch-Neuanlage (niemals Update/Force-Push), erneute SHA-Prüfung und
   sicheren Abbruch bei Konkurrenz.
5. **GitHub-Berechtigungen:** Kein Agent darf ein schreibfähiges GitHub-Token
   erhalten. Publisher-Identität, Berechtigungsumfang, Branch-Protection,
   PR-Review und mögliche Bypass-Rechte sind unabhängig zu prüfen.
6. **Sandbox/Netzwerk:** Docker-Inspect-Metadaten allein belegen keine
   tatsächliche Egress-Sperre. Gemini-Schlüssel dürfen niemals in der
   untrusted Patch- oder Code-Ausführungsumgebung vorhanden sein.
7. **Testabdeckung:** Ein echter End-to-End-Test ohne Schreibrechte und
   negative Tests für beschädigte ZIPs, untrusted Redirects, API-Fehler,
   Snapshot-Replay und parallele Läufe fehlen noch.

## Freigabekriterien

- Alle offenen Blocker durch Tests und Review geschlossen.
- Separater Publisher ohne Zugang zu Gemini-Secrets.
- Nur neue, eindeutig benannte Branches; ausschließlich Draft-PR.
- Geschützte `main`-Branch-Regeln und erforderliche menschliche Reviews.
- Bewusste Freigabe durch Repository-Eigentümer vor Aktivierung.
