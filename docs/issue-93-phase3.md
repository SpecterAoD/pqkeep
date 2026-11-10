# Issue #93 – Phase 3: Debian AMD64

Stand: 10.11.2026. Phase 3 ausdrücklich freigegeben. Der zuvor freigegebene Phase-2-PR
[#158](https://github.com/SpecterAoD/pqkeep/pull/158) wurde per Squash übernommen,
weil das Repository keine Merge-Commits erlaubt. Basis dieser Phase:
`ea8efef0fa067758bdecb5a120ddcc67a5e4014d`. Kein Release oder Tag erstellt.

Der Nutzer bestätigte den öffentlichen Maintainer-Kontakt:
`SpecterAoD <77644070+SpecterAoD@users.noreply.github.com>`.
Status: umgesetzt und nativ abgenommen; keine produktive Installation oder Veröffentlichung.
Eigener PR: [#159](https://github.com/SpecterAoD/pqkeep/pull/159).

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
  Standard-Apache-Klauseln verweisen nach geprüftem Textvergleich auf die gemeinsame
  Debian-Lizenzdatei; Ausnahmen und sonstige Texte bleiben in `copyright` erhalten.
  `licenses.tar.gz` erhält zusätzlich alle unveränderten Cargo-Originaltexte, deren
  Vollständigkeit und SHA-256 gegen das Inventar geprüft werden.
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

## Prüfungen und behobene Befunde

Lokal, ohne Systeminstallation:

```sh
python3 -m unittest discover -s scripts -p 'test_release_deb*.py' -v
SOURCE_DATE_EPOCH=1794301920 python3 scripts/release_deb.py /home/codex-agent/projects/pqkeep/analysis/issue-93-phase3/pqkeep x86_64-unknown-linux-gnu /home/codex-agent/projects/pqkeep/analysis/issue-93-phase3/package-b --ci-sha ea8efef0fa067758bdecb5a120ddcc67a5e4014d
SOURCE_DATE_EPOCH=1794301920 python3 scripts/release_deb.py /home/codex-agent/projects/pqkeep/analysis/issue-93-phase3/pqkeep x86_64-unknown-linux-gnu /home/codex-agent/projects/pqkeep/analysis/issue-93-phase3/package-c --ci-sha ea8efef0fa067758bdecb5a120ddcc67a5e4014d
```

Anfangs neun, nach Ergänzung der Archiv-, Lizenz- und Container-Regressionsfälle zwölf
Testfälle bestanden.
Die zwei lokalen Pakete wurden byteweise verglichen;
`dpkg-deb --info` und `--field ... Depends` wurden ausgeführt. Beide Paketläufe prüfen
ELF/ABI/Härtung, erzeugen Manpages/Completions durch echte Binary-Ausführung und prüfen
Paketinhalt/Prüfsummen. Eingabe war das nativ geprüfte AMD64-Artefakt aus Phase 2,
nach Prüfung seines GitHub-ZIP-Digests und Binaryhashes. Keine ARM64- oder Debian-System-
Installation lokal; native Debian-/Ubuntu-Containerprüfungen siehe unten.

Erste CI-Prüfrunde (`bf94bb442208ee713e2fe95f199569da320bdd09`): alle drei nativen Builds
einschließlich Debian-Paket und bytegleichem Wiederholungsbau erfolgreich. Lintian meldete
auf beiden Distributionen `copyright-file-contains-full-apache-2-license`; Installation
wurde deshalb nicht ausgeführt. Der Fehler wird durch Debian-konforme Verweise behoben,
ohne Originaltexte wegzulassen oder eine Prüfung zu unterdrücken. Zusätzlich wird jetzt
das vorhandene `CHANGELOG.md` als Upstream-Changelog verwendet. Neue lokale Paketläufe
`package-d`/`package-e` verwenden denselben oben angegebenen festen Testzeitstempel.

In der zweiten Runde bestand Lintian auf beiden Distributionen ohne Fehler/Warnungen.
Die Installation gelang, aber `dpkg --verify pqkeep` meldete fehlende Dateien: minimale
Container filtern Dokumentation. Der Test schließt deshalb ausschließlich die geprüften
Paketdateien und ihre Eltern über `Dpkg::Options::=--path-include=/<Pfad>` ein.
Debian Slim benötigt ausdrücklich auch die Elternverzeichnisse der deutschen Manpage.
Ein Regressionstest sichert diese Auswahl ab. Die Prüfung aller installierten Dateien
bleibt strikt; weder fehlende Dokumentation noch falsche Prüfsummen werden toleriert.
Die zusätzlichen APT-Optionen gelten nur für diese Testinstallation; das Paket verändert
keine dpkg-Konfiguration. Hintergrund: [dpkg-Pfadfilter](https://manpages.debian.org/bookworm/dpkg/dpkg.1.en.html).

Ein weiterer Lauf nach dem Berichts-Commit deckte einen sporadischen Testdatenfehler auf:
`secrets.token_urlsafe` garantiert keine Sonderzeichen, die vorhandene Passphrasenprüfung
lehnte einen solchen Testwert korrekt ab. Der Installationshelfer verwendet nun wie der
bestehende Release-Smoke-Test den CLI-Befehl `pqkeep passphrase`. Dessen Ausgabe bleibt
ausschließlich im Speicher. Keine Änderung oder Umgehung der Passphrasenregeln.

Prüfkommandos im nativen Release-Runner bzw. den kurzlebigen AMD64-Testcontainern:

```sh
cargo build --release --locked --target x86_64-unknown-linux-gnu
python3 scripts/check_binary.py target/x86_64-unknown-linux-gnu/release/pqkeep
python3 scripts/release_smoke.py target/x86_64-unknown-linux-gnu/release/pqkeep
python3 scripts/release_deb.py target/x86_64-unknown-linux-gnu/release/pqkeep x86_64-unknown-linux-gnu deb-dist --ci-sha "$GITHUB_SHA"
python3 scripts/release_deb.py target/x86_64-unknown-linux-gnu/release/pqkeep x86_64-unknown-linux-gnu deb-repeat --ci-sha "$GITHUB_SHA"
cmp deb-dist/*.deb deb-repeat/*.deb
dpkg-deb --info deb-dist/*.deb
dpkg-deb --contents deb-dist/*.deb
sha256sum deb-dist/*.deb
lintian --allow-root --fail-on error candidate/*.deb
python3 scripts/release_deb_smoke.py candidate/*.deb --arch amd64
```

`SOURCE_DATE_EPOCH` stammt in der CI aus dem Commit. Bei Pull Requests bezeichnet
`GITHUB_SHA` den von GitHub getesteten Merge-Commit; dieser steht deshalb im Paketnamen.
Der Installationshelfer führt APT-Installation, `dpkg-query`, `dpkg --verify pqkeep`,
Byte-/Rechtevergleich sämtlicher Dateien, den vorhandenen Smoke-Test als `nobody` und
`apt-get remove --yes --purge pqkeep` aus. Vorher erzeugte verschlüsselte Testschlüssel,
öffentlicher Export und eine bestehende Testdatei müssen samt Rechten/Eigentümern erhalten
bleiben. Die Passphrase wird zufällig erzeugt und nicht protokolliert.

Die vorhandene CI prüft zusätzlich `cargo fmt --all --check`, beide Clippy-Varianten
mit `--locked -- -D warnings`, `cargo test --locked`, MSRV, `cargo deny check`,
Gitleaks, CodeQL und die vorhandenen Härtungs-/Release-/ELF-/Limitprüfungen.
Native Release-Builds, Smoke-Tests und SBOM-Erzeugung laufen weiterhin für Linux AMD64,
Linux ARM64 und Windows AMD64. Keine Emulation eingesetzt.

Geprüfter Kandidat aus [Release-Testlauf 42871519247](https://github.com/SpecterAoD/pqkeep/actions/runs/42871519247),
Implementierungsstand `47cebcdd316a7da0563fd7c27525e2271208e8ab`:

- Paket: `pqkeep_0.1.0~beta.1-1~ci.20261110180500.d24fd9609956_amd64.deb`.
- SHA-256: `f904eb055afaf939b5b750d1acd6dc6223201af3128f40e32af2d0cf77246d12`.
- 29 Dateien; `Depends: libc6 (>= 2.34), libgcc-s1 (>= 4.2)`.
- Zweimaliger CI-Paketbau bytegleich; heruntergeladenes Actions-Artefakt gegen GitHub-Digest
  geprüft und danach Paketinhalt, Lizenzinventar und Binary-Identität unabhängig nachgeprüft.
- Binary-SHA-256: `9d24166d17f8760470e19c7dd4269e991b68e4244342fde5a543674e9bd8c0fb`.

Abnahme dieses Implementierungsstands am 10.11.2026:

| Prüfung | Ergebnis | Nachweis |
| --- | --- | --- |
| Debian 12, natives AMD64-Userspace, glibc 2.36 | Lintian ohne Meldungen; Installation, unprivilegierter Smoke, Dateirechte/-inhalte, Entfernung und unveränderte Testschlüssel bestanden | [Job](https://github.com/SpecterAoD/pqkeep/actions/runs/42871519247/job/130026524805) |
| Ubuntu 22.04, natives AMD64-Userspace, glibc 2.35 | Gleicher vollständiger Ablauf bestanden; Lintian ohne Meldungen | [Job](https://github.com/SpecterAoD/pqkeep/actions/runs/42871519247/job/130026524769) |
| Drei native Release-Ziele, Härtung, Smoke, Archive und SBOM | Erfolgreich; AMD64-Debian-Paket zweimal bytegleich | [Release-Testlauf](https://github.com/SpecterAoD/pqkeep/actions/runs/42871519247) |
| Bestehende Rust-/Sicherheits-/Kompatibilitätsprüfungen | Alle Jobs erfolgreich | [CI](https://github.com/SpecterAoD/pqkeep/actions/runs/42871519310) |
| CodeQL: Rust, Python, Actions | Erfolgreich | [CodeQL](https://github.com/SpecterAoD/pqkeep/actions/runs/42871519626) |

`cargo deny check` lief online auf einem frischen CI-Runner: Advisories, Bans, Lizenzen und
Quellen bestanden. Die bekannte Warnung zu den beiden `syn`-Versionen bleibt bestehen;
keine neue Ausnahme hinzugefügt. Beide Installationscontainer verwenden 4096-Byte-Seiten
und den Ubuntu-Hostkernel, keine Emulation. Die zusätzliche lokale Downloadprüfung war
statisch; lokal wurde nichts installiert. Logs, Digests und der geprüfte Kandidat liegen
geschützt unter `/home/codex-agent/projects/pqkeep/analysis/issue-93-phase3/`.

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

Empfehlung: PR #159 prüfen und übernehmen; anschließend Phase 4 mit Wiederverwendung
derselben Paketierungslogik und nativer ARM64-Installation ausdrücklich freigeben.
Phase 4 beginnt erst nach dieser Nutzerfreigabe. Issue #93 bleibt bis zum Abschluss
aller sechs Phasen offen. Keine Veröffentlichung ohne gesonderte Zustimmung.
