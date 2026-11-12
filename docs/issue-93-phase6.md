# Issue #93 – Phase 6: Release-Integration

Stand: 12.11.2026. Phase 6 ausdrücklich freigegeben. Basis: `main` nach Phase 5
([#164](https://github.com/SpecterAoD/pqkeep/pull/164)). Kein Tag, kein Signierlauf, kein
Release-Entwurf erstellt – das bleibt einem eigenen Auftrag vorbehalten.

## Änderungen

- `.github/workflows/release.yml`:
  - Das ARM64-Archiv heißt jetzt `dist-aarch64-unknown-linux-gnu` und gehört zum Release.
  - Der Build legt das Debian-Paket zusätzlich als `pqkeep-<Version>-<Architektur>.deb` samt
    eigener SBOM in `dist/` ab (bytegleich mit dem getesteten `candidate-debian-*`).
  - Bei einem signierten Tag trägt das Paket die Release-Version (`0.1.0~beta.2-1`), sonst
    die CI-Version. Ohne Tag trägt das Nachfolger-Testpaket die Release-Version, sodass
    Paketbau, Lintian und Upgrade/Downgrade dieses Schema in jedem Lauf prüfen.
  - Neuer Job „Artefaktmanifest“ ohne Rechte (auch in PRs): gleicht `dist-*` mit dem Manifest
    ab und stellt `release-input` bereit. `publish` hängt davon und damit von allen
    Installations- und Lebenszyklusjobs ab.
  - `publish`: Build-Provenance und CycloneDX-Attestation für alle fünf Artefakte,
    `SHA256SUMS` und Sigstore-Bundles einschließlich `.deb`. `verify`: Manifestabgleich des
    Bündels, Prüfsummen, Attestationen und Sigstore-Prüfung für alle fünf.
  - Rechte, Environment `release` und Auslöser unverändert; PR-Läufe signieren nichts.
- `scripts/release_manifest.py` (neu): festes Manifest und Prüfer (`collect`, `verify`).
- `scripts/release_sbom.py`: Paket-SBOM mit eigener `serialNumber` und Paketidentität.
- `scripts/release_deb.py`: `--release` (Version ohne CI-Suffix, Changelog `unstable`) und
  `--successor` (höher sortierendes Testpaket `+test1`, ersetzt den Zeitversatz um eine Sekunde).
- Tests: `scripts/test_release_manifest.py` (neu), `scripts/test_release_deb.py` ergänzt.
- Doku DE/EN: `README.md`, `docs/RELEASE.md`, `docs/INSTALL.md`, `docs/CHECKLIST.md`,
  `docs/issue-93-testmatrix.md` (Kopfzeile).

Abweichung vom Plan: Die Release-Datei heißt `pqkeep-<Version>-<Architektur>.deb` statt
`pqkeep_<Debian-Version>_<Architektur>.deb`, weil GitHub die Tilde in Asset-Namen ersetzt und
Prüfsummen- und Bundle-Namen sonst nicht mehr zur heruntergeladenen Datei passen würden. Die
Paketversion im Paket selbst ist unverändert die Debian-Version.

## Was der Manifestabgleich abweist

Fehlendes oder zusätzliches Build-Artefakt, fehlende oder zusätzliche Datei, leere Datei,
Link, doppelter Inhalt, Paket der falschen Architektur, Paket mit anderem Programm als im
Archiv derselben Architektur, vertauschte SBOM oder Paket-SBOM, SBOM eines anderen Commits,
Archiv ohne Programm. Im fertigen Bündel zusätzlich: fehlendes Sigstore-Bundle, fehlende,
zusätzliche oder doppelte Zeile in `SHA256SUMS`, abweichende Prüfsumme. Jeder Fall ist ein
Unit-Test.

## Prüfungen

Lokal (AMD64-Arbeitsrechner, nichts installiert): 35 Skripttests bestanden, davon neun neue;
`scripts/check_limits.sh` und `git diff --check` ohne Befund.

CI (PR [#165](https://github.com/SpecterAoD/pqkeep/pull/165), Lauf
[43172198199](https://github.com/SpecterAoD/pqkeep/actions/runs/43172198199), Commit `502a74a`):
alle 29 Prüfungen bestanden; `publish` und `verify` wie vorgesehen übersprungen.

- Job „Artefaktmanifest“: zehn Dateien aus drei Build-Artefakten angenommen (fünf
  Nutzartefakte, fünf SBOMs), einschließlich der Zuordnungsprüfung beider Pakete mit `dpkg-deb`.
- Beide Builds: Kandidat zweimal bytegleich gebaut; die Release-Datei in `dist/` hat dieselbe
  SHA-256 wie der getestete Kandidat. Das Nachfolgerpaket trägt die Release-Version
  (`0.1.0~beta.1-1`) und sortiert nach dem Kandidaten.
- Zehn Installationsjobs (fünf Distributionen × amd64/arm64): Lintian ohne Fehler für
  Kandidat und Paket mit Release-Version; Upgrade auf die Release-Version und Downgrade bestanden.

## Nicht nachgewiesen

- `publish` und `verify` laufen in PRs nicht. Die geänderten Schritte (Attestationen,
  Prüfsummen, Sigstore für `.deb` und ARM64) werden erstmals bei einem Probelauf auf `main`
  oder einem Tag ausgeführt; beides braucht einen eigenen Auftrag und die
  Environment-Freigabe.
- Der Tag-Zweig des Paketbaus (Kandidat mit Release-Version, Nachfolger `+test1`) läuft erst
  bei einem Tag. Die Release-Version selbst wird in jedem Lauf über das Nachfolgerpaket gebaut,
  mit Lintian geprüft und installiert.
- Die in Phase 5 offenen Fälle (Platzmangel, Abbruch von dpkg, Distributionskernel,
  64-KiB-Seiten) bleiben offen: [#163](https://github.com/SpecterAoD/pqkeep/issues/163).
