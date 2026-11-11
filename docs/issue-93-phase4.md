# Issue #93 – Phase 4: Debian ARM64

Stand: 11.11.2026. Phase 4 ausdrücklich freigegeben. Basis: `main` nach den übernommenen
Phasen 2 ([#158](https://github.com/SpecterAoD/pqkeep/pull/158)) und 3
([#159](https://github.com/SpecterAoD/pqkeep/pull/159)). Kein Release oder Tag erstellt.
Status: umgesetzt; die native Abnahme erfolgt in der CI dieses PRs (siehe „Prüfungen“).

## Änderungen

- `scripts/release_deb_check.py`: `aarch64-unknown-linux-gnu` → `arm64` freigeschaltet.
  Paketierer, Prüfer und Installationstest lesen die Zuordnung aus derselben Tabelle;
  es gibt keine Skriptkopie und kein architekturspezifisches Control-Template.
- `scripts/release_deb.py`: nur die Beschreibung angepasst. Die Paketlogik war bereits
  zielparametrisiert und baut weiterhin ausschließlich nativ (dpkg-Architektur und
  ELF-Ziel müssen zum Runner passen).
- `scripts/test_release_deb.py`: Inhalts-, Architektur- und Prüfsummenfälle laufen für
  beide Ziele. Neu: Ein Paket mit dem Lizenzinventar des jeweils anderen Ziels wird
  abgewiesen. Der Fall „falsches Binary“ prüft jetzt in beide Richtungen
  (AMD64-Binary im ARM64-Paket und umgekehrt).
- `.github/workflows/release.yml`: Der native ARM64-Build erzeugt das Paket zweimal,
  vergleicht beide Läufe bytegenau und lädt `candidate-debian-arm64` getrennt hoch.
  Die Installationsjobs bilden eine Matrix aus Architektur (amd64, arm64) und
  Distribution (Debian 12, Ubuntu 22.04); ARM64 läuft auf `ubuntu-22.04-arm`.
  Die Image-Digests sind unverändert die Index-Digests aus Phase 3 und enthalten
  Manifeste für beide Architekturen. `publish`/`verify` und alle Rechte bleiben unverändert.
- `docs/INSTALL.md`, `docs/RELEASE.md`: beide Architekturen DE/EN beschrieben.

## Paketvertrag

Unverändert gegenüber Phase 3 (siehe [Phase-3-Bericht](issue-93-phase3.md)): gleiche
Dateiliste, Rechte, Eigentümer, keine Maintainerskripte oder Conffiles, Abhängigkeiten
aus `dpkg-shlibdeps`, Lizenzinventar je Ziel. Das ARM64-Paket ist eigenständig und
benötigt kein AMD64-Paket. 32-Bit-ARM (`armhf`) ist nicht Teil von #93.

## Prüfungen

Lokal (AMD64-Arbeitsrechner, nichts installiert):

- `python3 -m unittest discover -s scripts -p 'test_release_*.py'`: 20 Tests bestanden,
  darunter die Paketfälle für beide Architekturen.
- `scripts/check_limits.sh` und `git diff --check` ohne Befund.
- Ein lokaler ARM64-Paketbau ist auf AMD64 bewusst nicht möglich: Der Paketierer weist
  Cross-Paketierung ab. Maßgeblich ist deshalb die native CI.

Native CI dieses PRs (Ergebnisse stehen im PR):

- Build `aarch64-unknown-linux-gnu` auf `ubuntu-22.04-arm` mit ELF-/ABI-Prüfung, Härtung,
  Rauchtest, zweifachem bytegleichem Paketbau.
- Lintian ohne Overrides sowie Installation, Nutzung als unprivilegierter Benutzer,
  Entfernung und Purge auf Debian 12 und Ubuntu 22.04, jeweils nativ für amd64 und arm64.
  Vor der Installation angelegte Testschlüssel und Dateien müssen unverändert bleiben.

## Sicherheit, Grenzen und Rückweg

Keine Änderungen an Produktions-Rustcode, Kryptografie, Formaten, CLI, Schlüsseln,
Cargo-Abhängigkeiten oder GitHub-Berechtigungen. Kein privilegierter Container, kein QEMU.
Die Container teilen den Kernel des GitHub-Hosts (4-KiB-Seiten); ein nativer
64-KiB-Kernel bleibt für Phase 5 offen. Der ARM64-Kandidat wird nicht signiert und nicht
veröffentlicht; das folgt erst nach gesonderter Freigabe in Phase 6.

Offen: breite Installations-/Upgrade-/Fehlermatrix (Phase 5) und Aufnahme aller neuen
Artefakte in Signatur, Attestation, SBOM und Veröffentlichung (Phase 6).

Rückweg: PR nicht übernehmen; nach einem Merge eigener Revert-PR. Die Phase-3-Logik und
die AMD64-Nachweise bleiben dabei erhalten. Es sind keine Benutzerdateien, Schlüssel oder
Dienste betroffen.
