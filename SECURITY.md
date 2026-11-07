# Security policy

[English](#english) | [Deutsch](#deutsch)

## English

### Reporting a vulnerability

Please **do not** open a public issue. Use GitHub's private reporting:
**Security → Report a vulnerability** in this repository. Helpful details:

- affected version or commit, platform (Windows/Linux) and how PQKeep was used;
- steps to reproduce or a proof of concept (no real secrets, please);
- your assessment of the impact.

### What to expect

PQKeep is maintained by a single person in their spare time. Targets, not guarantees:

| Step | Target |
|---|---|
| Acknowledgement | within 7 days |
| Initial assessment | within 30 days |
| Fix and coordinated disclosure | within 90 days, earlier for critical issues |

Reporters are credited in the advisory unless they prefer otherwise.

### Scope

In scope: cryptographic misuse, weaknesses in the key container or `.pqkf` file format, parser
issues (crashes, resource exhaustion), passphrase handling, REST API authentication and limits,
sandbox escapes, supply-chain issues in this repository.

Out of scope: a compromised host (malware, keyloggers), hardware side channels, vulnerabilities in
upstream crates without a PQKeep-specific impact (please report those upstream), findings that
require deliberately disabling protections (e.g. `--no-sandbox`).

### Supported versions

Before 1.0 only the latest release (and `main`) receives fixes.

### Status

No external security audit has been performed yet. The cryptographic libraries implement FIPS 203
and FIPS 204 but are not FIPS 140 validated. `zeroize` and memory locking are best effort. See
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## Deutsch

**Sicherheitslücken bitte nicht als öffentliches Issue melden**, sondern über **Security → Report
a vulnerability** in diesem Repository (private Meldung). Hilfreich: betroffene Version/Commit,
Plattform, Schritte zur Reproduktion (ohne echte Geheimnisse), Einschätzung der Auswirkung.

Ziele (keine Garantie, ein Maintainer in der Freizeit): Eingangsbestätigung innerhalb von 7 Tagen,
erste Bewertung innerhalb von 30 Tagen, Behebung und abgestimmte Veröffentlichung innerhalb von 90
Tagen, bei kritischen Lücken früher. Meldende werden auf Wunsch genannt.

Im Rahmen: Krypto-Fehlanwendung, Schwächen im Container- oder `.pqkf`-Format, Parser-Fehler,
Passphrase-Verarbeitung, Anmeldung und Grenzen der REST-API, Ausbruch aus der Sandbox,
Lieferkette dieses Repositorys. Außerhalb: kompromittierter Rechner, Hardware-Seitenkanäle,
Lücken in fremden Crates ohne PQKeep-spezifische Auswirkung, Befunde nur mit abgeschaltetem Schutz
(z. B. `--no-sandbox`).

Vor 1.0 wird nur die jeweils neueste Version unterstützt. Kein externes Audit; Bibliotheken nicht
FIPS-140-validiert; `zeroize` und Speichersperre sind Best Effort.
