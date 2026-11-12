# Issue #93 – Phase 5: Installations- und Regressionstests

Stand: 12.11.2026. Phase 5 ausdrücklich freigegeben. Basis: `main` nach Phase 4
([#162](https://github.com/SpecterAoD/pqkeep/pull/162)).
PR: [#164](https://github.com/SpecterAoD/pqkeep/pull/164). Kein Release oder Tag erstellt.
Status: umgesetzt und in der CI abgenommen; bewusst offene Fälle siehe unten.

## Änderungen

- `scripts/release_deb_lifecycle.py`: Lebenszyklus-Test, läuft ausschließlich im kurzlebigen
  GitHub-Testcontainer (gleiche Sperre wie der bisherige Installationstest). Fälle und
  geforderte Aussagen stehen in der [Testmatrix](issue-93-testmatrix.md).
- `scripts/release_deb_fixtures.py`: erzeugt abgeschnittene und verfälschte Paketkopien, ein
  Paket mit unerfüllbarer Abhängigkeit und ein fremdes Paket, das `/usr/bin/pqkeep` besitzt.
  Installiert nichts; Unit-Tests in `scripts/test_release_deb_lifecycle.py`.
- `scripts/release_deb_smoke.py`: Dateiprüfung und Container-Sperre als Funktionen
  ausgelagert und wiederverwendet; Verhalten unverändert.
- `.github/workflows/release.yml`: Der Build erzeugt je Architektur ein Nachfolger-Testpaket
  (gleiches Binary, eine Sekunde spätere Version; Artefakt `lifecycle-debian-<arch>` außerhalb
  `dist-*`, wird nie veröffentlicht). Installationsmatrix: Debian 12/13 und Ubuntu
  22.04/24.04/26.04, jeweils amd64 und arm64; Images per Index-Digest festgelegt.
  `publish`/`verify` und alle Rechte unverändert.
- `docs/issue-93-testmatrix.md`, `docs/INSTALL.md`: Umfang, Grenzen und nicht nachgewiesene
  Fälle DE/EN.

Abweichung vom Implementierungsplan: Das Skript heißt `release_deb_lifecycle.py` statt
`test_deb_lifecycle.py`, damit Pfadfilter und Testsuche des Workflows es ohne Sonderfall
erfassen; es ist ein Containertest, kein Unit-Test.

## Prüfungen

Lokal (AMD64-Arbeitsrechner, nichts installiert): 26 Skripttests bestanden, davon sechs neue
für Zustandsauswertung und Testpakete; `scripts/check_limits.sh` und `git diff --check` ohne
Befund. Die Nutzerschritte (Schlüssel, Verschlüsseln, Entschlüsseln) wurden mit einem lokalen
Binary in einem temporären Ordner durchgespielt.

CI (Lauf [43162069073](https://github.com/SpecterAoD/pqkeep/actions/runs/43162069073),
Commit `2ae1e52`): alle Prüfungen bestanden.

- Zehn Installationsjobs (fünf Distributionen × amd64/arm64), nativ, Kernel der Runner
  `6.8.0-1070-azure`: jeweils Lintian ohne Overrides, bisheriger Installationstest und
  Lebenszyklus mit 7 erwarteten Abweisungen und 14 bestandenen Zustandsprüfungen.
- Beobachtung: Beschädigte Pakete und der Dateikonflikt hinterließen auf keinem System einen
  Paketzustand; die vorgesehene Bereinigung per `dpkg --purge` wurde nie benötigt.
- Auf Debian 13 und Ubuntu 24.04/26.04 ergaben sich keine Lintian- oder Abhängigkeitsbefunde.
- Übrige CI (fmt/clippy/test auf vier Runnern, MSRV, cargo-deny, CodeQL, gitleaks,
  Zeilenlimits, Binär-Härtung) bestanden; `publish`/`verify` bei PRs übersprungen.

## Offene Fälle, Sicherheit und Rückweg

Nicht nachgewiesen und nach Entscheidung des Maintainers auf
[#163](https://github.com/SpecterAoD/pqkeep/issues/163) verschoben: Platzmangel, echter
Abbruch mitten im dpkg-Lauf, Kernel der Zieldistributionen (Seccomp, Landlock, memlock) und
ARM64 mit 64-KiB-Seiten. Phase 6 darf dazu keine Aussage machen. Upgrade/Downgrade ist nur
zwischen zwei Testrevisionen desselben Builds gezeigt, nicht von einer veröffentlichten Version.

Keine Änderungen an Produktions-Rustcode, Kryptografie, Formaten, CLI, Cargo-Abhängigkeiten
oder GitHub-Berechtigungen. Kein privilegierter Container, kein `--force-…`, kein QEMU.
Testschlüssel und Passphrasen entstehen zur Laufzeit und werden nicht protokolliert.

Rückweg: PR nicht übernehmen; nach einem Merge eigener Revert-PR. Es werden nur Tests,
Testartefakte und Dokumentation zurückgenommen; die Pakete aus Phase 3/4 bleiben unverändert.
