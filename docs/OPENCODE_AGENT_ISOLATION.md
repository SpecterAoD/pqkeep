# OpenCode Agent – Isolation und Freigabegates

Status: **Spezifikation, nicht implementierte Sandbox**. Der read-only
Autorisierungsworkflow darf vor Erfüllung aller Gates weder Gemini-Secrets
lesen noch OpenCode starten.

## Sicherheitsgrenze

Der Modellprozess ist nicht vertrauenswürdig. Ein Systemprompt, die
OpenCode-Toolberechtigungen und ein Container allein verhindern weder
Prompt-Injection noch die Exfiltration eines im Prozess vorhandenen Secrets.
Insbesondere sind frei aufrufbare Shell-, HTTP-, Git- und Subagent-Tools
auszuschließen. Selbst reine Dateiedits können bösartige Inhalte erzeugen.

## Vorgesehene Job-Trennung

1. **Preflight (ohne Modell-Secret):** Event auf dem vertrauenswürdigen
   Default-Branch prüfen; Kommentar und Issue über die GitHub-API neu
   abrufen; Issue-Snapshot und Base-SHA festhalten. GitHub-Token nur lesend.
2. **Agent (ohne GitHub-Token):** Vertrauenswürdiges, unveränderliches
   Container-Image mit geprüftem Digest, nicht-root, keine zusätzlichen
   Linux-Capabilities, no-new-privileges, readonly root filesystem,
   Ressourcen-/Zeitlimits, separates beschreibbares Arbeitsverzeichnis.
   Agent darf nur erlaubte Markdown-Dateien ändern. Keine
   Repository-Credentials, keine Docker-Socket-Mounts, kein Host-Netzwerk.
3. **Validator (ohne Secrets):** Frischer Runner; vorgeschlagenes Artifact
   ausschließlich als Daten behandeln; gegen festen Base-SHA rekonstruieren;
   Pfade, Modi, Größe, Inhaltstyp, Commitanzahl und unveränderte Basis prüfen.
   Keine Ausführung von Code aus dem Artifact.
4. **Publisher (ohne Gemini-Secret):** Frischer Runner, erneut gegen GitHub
   revalidieren, unveränderten Base-SHA bestätigen und denselben Patch
   erneut prüfen. Nur ein kurzlebiges Schreib-Credential; nur neuer
   `opencode/...`-Branch und Draft-PR. Kein Merge.

## Netzwerkmodell – Freigabevoraussetzung

Ein generischer GitHub-hosted Runner bietet **keine automatisch garantierte
Egress-Allowlist** für einen Kindprozess. DNS-Namensfilter allein sind wegen
DNS-Rebinding, Proxies, IPv6, direkter IP-Adressen und TLS-Tunneln nicht
ausreichend. Der Gemini-API-Key darf erst nach einem nachweisbaren,
durchgesetzten Netzwerkmodell in den Agentenjob gelangen.

**Bevorzugte Architektur:** Ein separater, gehärteter Modell-Gateway außerhalb
der Agenten-Sandbox. Der Gateway besitzt den Gemini-Key; der Agent bekommt
nur ein auf den einzelnen Lauf beschränktes Authentisierungstoken. Der
Gateway akzeptiert ausschließlich definierte Gemini-API-Methoden und
Modell-IDs, begrenzt Anfragegrößen, Requests und Kosten und protokolliert
keine Secrets. Der Agent darf ausgehend ausschließlich den Gateway erreichen.
Auch dann kann der Agent sensible Repository-Inhalte im erlaubten
Modell-Request übertragen; dies ist eine explizite Datenflussfreigabe.

**Alternative:** Verifizierter Netzwerk-Namespace mit Default-Deny-Egress
und einem dedizierten TLS-Proxy, der Zielhost, Port, SNI und TLS-Zertifikat
prüft. Nicht bloß `iptables` im selben manipulierbaren Container. Für
IPv4 und IPv6 muss das Verhalten nachweisbar sein.

**Fail closed:** Kein erreichbarer Gateway/Proxy, nicht nachgewiesene
Egress-Sperre, unerwartete Modell-ID, API-Fehler, Quota, Timeout oder
fehlender Secret -> Jobabbruch ohne PR.

## Vor produktiver Aktivierung nachzuweisen

- Gepinnte OpenCode-Version und tatsächliche CLI-/Konfigurationssyntax
  anhand offizieller Dokumentation und Testlauf überprüft.
- Shell, Web, Fetch, Subagents und unkontrollierte Dateizugriffe in der
  tatsächlich gepinnten Version deaktiviert und negativ getestet.
- Direkte HTTP(S)-Verbindungen zu beliebigen Hosts, IP-Adressen, IPv6
  und DNS-Tunnel scheitern im Agentencontainer; nur Gateway ist erreichbar.
- Agent kann weder GitHub-Token lesen noch Branches pushen.
- Gateway-Token ist kurzlebig, auf einen Lauf begrenzt und kann keinen
  anderen Dienst ansprechen.
- Manipulierte Issue-Inhalte und Modellantworten können keine Workflow-,
  Skript-, Cargo-, Sicherheits- oder Krypto-Dateien in einen PR bringen.
- Publisher prüft frisch Issue, Base-SHA, Patch und Artifact-Digest.
- Ein Test-Draft-PR löst die vorhandenen PR-CI-Checks aus; Branch-Ruleset
  verhindert automatischen Merge.

## Bis dahin

Die Workflow-Datei `.github/workflows/opencode.yml` bleibt auf
**read-only authorization hold**. Keine `GEMINI_API_KEY`-Weitergabe, kein
Agentenlauf, kein automatisches Publishing. Änderungen an dieser Grenze
bedürfen einer eigenen Review.

## Artefaktidentität und Vertrauensanker

Der Publisher darf den `run_id` und den `base_sha` **nicht** aus dem
Agenten-Artifact oder dessen Manifest übernehmen. Er muss beide Werte aus
einer vertrauenswürdigen GitHub-Actions-Ausführung beziehungsweise einem
vorher autorisierten Preflight-Kontext beziehen. Die CLI-Prüfung
`scripts/verify_opencode_artifact.py` verlangt deshalb die expliziten
Umgebungswerte `OPENCODE_EXPECTED_RUN_ID` und
`OPENCODE_EXPECTED_BASE_SHA`. Ein Angreifer, der sowohl Artifact als
auch Manifest austauscht, kann diese erwarteten Werte nicht durch das
Manifest selbst verändern. Ein SHA-256-Vergleich schützt dennoch **nicht**
gegen einen Angreifer, der auch die vertrauenswürdigen Erwartungswerte
kontrolliert. Vor produktivem Einsatz muss die Herkunft der Erwartungswerte
und der GitHub-Artifact-Download über vertrauenswürdige Run-ID/Artifact-ID
verifiziert werden.
