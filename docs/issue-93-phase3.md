# Issue #93 – Phase 3: Debian AMD64

Stand: 10.11.2026. Phase 3 ausdrücklich freigegeben. Der zuvor freigegebene Phase-2-PR
[#158](https://github.com/SpecterAoD/pqkeep/pull/158) wurde per Squash übernommen,
weil das Repository keine Merge-Commits erlaubt. Basis dieser Phase:
`ea8efef0fa067758bdecb5a120ddcc67a5e4014d`. Kein Release oder Tag erstellt.

Der Nutzer bestätigte den öffentlichen Maintainer-Kontakt:
`SpecterAoD <77644070+SpecterAoD@users.noreply.github.com>`.
Status: lokal umgesetzt; native Installation und Lintian werden im eigenen PR nachgewiesen.

## Änderungen

- `scripts/release_deb.py`: gemeinsamer, unprivilegierter Debian-Adapter; zunächst nur
  `x86_64-unknown-linux-gnu` → `amd64` freigeschaltet. Staging ist temporär, Ausgaben werden
  nach vollständiger Prüfung atomar bereitgestellt und nicht überschrieben.
- `scripts/release_deb_check.py`: ohne Extraktion Paketpfade, Dateitypen, Rechte, Eigentümer,
  vollständige Dateiprüfsummen, ELF-Ziel und Identität zum getesteten Binary prüfen.
  Fremde Steuerdateien, Maintainerskripte und Conffiles werden abgewiesen.
- `scripts/release_deb_licenses.py`: normales und Build-Abhängigkeitsinventar aus
  `cargo tree`/`cargo metadata --offline --locked`; vollständige Original-Lizenztexte und
  Copyright-Hinweise, einschließlich der tatsächlich benutzten Rust-Standardbibliothek.
  Die Featureangaben sind die Cargo-Metadaten-Vereinigung, keine Linker-Beweisliste.
- `scripts/test_release_deb.py`: positive/negative Tests für Versionen, Reihenfolge,
  fehlende Dateien, Architektur, Schreibrechte, Symlinks, Traversal, Paketsteuerdateien,
  Prüfsummen und fehlende Lizenztexte.
- `scripts/release_deb_smoke.py`: echte Installation über APT, unprivilegierte Nutzung mit
  dem vorhandenen Smoke-Test, Prüfung installierter Dateien/Rechte und Entfernung samt
  Purge. Vor Installation angelegte verschlüsselte Testschlüssel, deren Export und
  Dateirechte müssen unverändert bleiben. Ausführung nur im GitHub-Testcontainer möglich.
- `packaging/debian/`: bestätigte Metadaten, Copyright-Grundlage und vollständiger CC-BY-4.0-
  Text. Die vorhandenen Wortlistenhinweise bleiben erhalten; keine Lizenz-Ausnahme.
- `.github/workflows/release.yml`: zweimaliger AMD64-Paketbau im bestehenden nativen Build,
  separater `candidate-debian-amd64`-Upload, Lintian und Installationsjobs in Debian-12-
  und Ubuntu-22.04-AMD64-Containern. Vorhandene Build-/Härtungs-/Smoke-/SBOM-Schritte bleiben.
- `docs/INSTALL.md`, `docs/RELEASE.md`, Plan und dieser Bericht: Anleitung DE/EN und Nachweise.

## Paketvertrag

Das bereits mit `cargo build --release --locked --target x86_64-unknown-linux-gnu` gebaute,
gehärtete und ausgeführte Binary wird unverändert unter `/usr/bin/pqkeep` (0755) installiert.
Manpages DE/EN, Bash-/Zsh-/Fish-Completions, Lizenztexte, Copyright, Lizenzinventar und
Änderungsnotizen liegen unter `/usr/share` (Dateien 0644, Verzeichnisse 0755), root:root
im Paket. `dpkg-deb --root-owner-group` benötigt dafür keine Root-Rechte beim Bauen.
Keine Capabilities, SUID/SGID, Symlinks, Dienste, Nutzeranlage, Profiländerung, Conffiles,
Maintainerskripte oder automatischen Kontextmenü-Aktionen.

Metadaten verwenden `dpkg-shlibdeps` mit der nativen Paketdatenbank; Bibliotheksabhängigkeiten
werden nicht geraten. Versionsbeispiel: `0.1.0~beta.1-1~ci.<Commitzeit-UTC>.<SHA>`; Prereleases
sortieren vor finalen Upstream-Versionen, CI vor der entsprechenden Paketrevision.
Einzelne Commits mit gleicher UTC-Sekunde haben keine zugesicherte zeitliche Reihenfolge.
Unbekannte Versionen/Buildmetadaten werden abgelehnt. Die Upstream-/CLI-Version bleibt gleich.

Bis Phase 6 ausschließlich CI-Kandidat, keine Signaturen/Attestationen für `.deb` und keine
Releaseaufnahme. Das Linux-SBOM-Artefakt bleibt erhalten; die spätere explizite Zuordnung zum
Debian-Artefakt gehört zu Phase 6. Das Lizenzinventar ersetzt keine SBOM oder Signatur.

## Bisherige Prüfungen

Lokal, ohne Systeminstallation:

```sh
python3 -m unittest discover -s scripts -p 'test_release_deb*.py' -v
SOURCE_DATE_EPOCH=1794301920 python3 scripts/release_deb.py /home/codex-agent/projects/pqkeep/analysis/issue-93-phase3/pqkeep x86_64-unknown-linux-gnu /home/codex-agent/projects/pqkeep/analysis/issue-93-phase3/package-b --ci-sha ea8efef0fa067758bdecb5a120ddcc67a5e4014d
SOURCE_DATE_EPOCH=1794301920 python3 scripts/release_deb.py /home/codex-agent/projects/pqkeep/analysis/issue-93-phase3/pqkeep x86_64-unknown-linux-gnu /home/codex-agent/projects/pqkeep/analysis/issue-93-phase3/package-c --ci-sha ea8efef0fa067758bdecb5a120ddcc67a5e4014d
```

Neun Testfälle bestanden. Die zwei lokalen Pakete wurden byteweise verglichen;
`dpkg-deb --info` und `--field ... Depends` wurden ausgeführt. Beide Paketläufe prüfen
ELF/ABI/Härtung, erzeugen Manpages/Completions durch echte Binary-Ausführung und prüfen
Paketinhalt/Prüfsummen. Eingabe war das nativ geprüfte AMD64-Artefakt aus Phase 2,
nach Prüfung seines GitHub-ZIP-Digests und Binaryhashes. Keine ARM64- oder Debian-System-
Installation lokal; native Debian-/Ubuntu-Containerprüfungen werden anschließend ergänzt.

## Sicherheit, Grenzen und Rückweg

Keine Änderungen an Produktions-Rustcode, Kryptografie, Formaten, CLI, Schlüsseln,
Cargo-Abhängigkeiten oder GitHub-Berechtigungen. `publish`/`verify`, manuelle Freigaben
und der Release-Entwurfsprozess bleiben unverändert. Lintian läuft ohne Overrides;
Fehler brechen ab, verbleibende Warnungen werden einzeln bewertet und dokumentiert.
Container verwenden die Standard-Sicherheitsfilter; kein privilegierter Modus, QEMU oder
Abschalten der Sandbox. Die Container prüfen native ISA und Distribution, teilen aber
den Kernel des GitHub-Hosts. Das ist kein Nachweis eigenständiger Distributionskernel.

Offen für spätere Freigaben: Debian ARM64 (Phase 4), breite Installations-/Upgrade-/Fehlermatrix
und 64-KiB-Kernel (Phase 5), Artefaktsignaturen/Attestationen/Veröffentlichung (Phase 6).
Die Paket-Reproduzierbarkeit betrifft identische Eingaben und Werkzeuge; Runner-Images und
Rust `stable` sind weiterhin beweglich. Kein Paket für das offizielle Debian-Archiv beantragt.

Vor Änderungen verifizierte Sicherung:
`/home/codex-agent/projects/pqkeep/backups/issue-93-phase3-20261110T091549Z`.
Bestehende betroffene Dateien und `PROJECT.md` mit Rechten/Hashes gesichert;
neue Pfade im Manifest dokumentiert. Unbeteiligte Worktrees unverändert.

Vor Merge: PR nicht übernehmen; nur Phase-3-Dateien im isolierten Worktree anhand des
Manifests zurücknehmen, vorhandene Dateien aus der Sicherung wiederherstellen.
Nach Merge: eigener Revert-PR für diese Phase, normale CI wiederholen. Testcontainer nach
Jobende verwerfen; auf dem Arbeitsrechner ist keine Paketdeinstallation erforderlich.
Keine Benutzerdateien, Schlüssel, Tags oder Releases löschen.

Phase 4 beginnt erst nach ausdrücklicher Nutzerfreigabe. Issue #93 bleibt offen.
