# Installation / Installation

## Deutsch

### Debian-Paket als Testkandidat

Issue #93, Phase 3 ergänzt ein **AMD64-CI-Paket**, noch kein veröffentlichtes oder
signiertes Debian-Release. Das Actions-Artefakt `candidate-debian-amd64` im Release-Workflow
enthält `pqkeep_<Debian-Version>_amd64.deb` und ist 14 Tage verfügbar. Verwende für einen
Test nur den eigenen geprüften Workflowlauf und vergleiche dessen SHA-256 mit dem Download.
Eine Prüfsumme allein bestätigt keine Herkunft; signierte Releases folgen erst in Phase 6.

Das Paket benötigt Linux AMD64 und die im Paket ausgewiesenen Bibliotheken. Der Build
verwendet Ubuntu 22.04; `dpkg-shlibdeps` bestimmt die konkreten Abhängigkeiten. Die erste
Installationsprüfung umfasst Debian 12 und Ubuntu 22.04 in nativen AMD64-Testcontainern.
Die vollständige Distributions-/Upgrade-Matrix folgt in Phase 5. ARM64-Pakete sind erst
für Phase 4 vorgesehen. Ein AMD64-Paket lässt sich nicht als ARM64-Paket verwenden.

Nach eigener Freigabe in einem geeigneten Testsystem (Dateiname entsprechend ersetzen):

```sh
dpkg --print-architecture
dpkg-deb --info "./pqkeep_<Debian-Version>_amd64.deb"
sudo apt install "./pqkeep_<Debian-Version>_amd64.deb"
pqkeep --version
pqkeep --lang de --help
man pqkeep
```

`apt` löst die deklarierten Paketabhängigkeiten auf. Das Programm liegt unter
`/usr/bin/pqkeep`. Deutsche und englische Manpages sowie Completions für Bash, Zsh und
Fish werden in den jeweiligen Standardpfaden unter `/usr/share` installiert.
Lizenztexte, Copyright, Lizenzinventar und Änderungsnotizen liegen unter
`/usr/share/doc/pqkeep`. Es werden keine Hintergrunddienste gestartet, Konten angelegt
oder Desktop-/Shell-Profile geändert. Vorhandene CLI-Befehle und das Standardfeature
`api` bleiben erhalten; ein Server startet nur durch einen ausdrücklichen CLI-Aufruf.

Entfernung im Testsystem:

```sh
sudo apt remove pqkeep
```

Auch `sudo apt purge pqkeep` entfernt keine selbst angelegten Schlüssel oder Dateien im
Benutzerverzeichnis. Das Paket enthält keine Maintainerskripte oder Conffiles. Manuell
mit `pqkeep integrate` erzeugte Kontextmenüs gehören weiterhin dem Benutzer und können
nach der Deinstallation verwaisen; bei Bedarf vorher ausdrücklich über die bestehende
CLI entfernen. Das Paket führt diesen Befehl niemals automatisch aus.

CI-Versionen verwenden beispielsweise `0.1.0~beta.1-1~ci.<UTC-Zeit>.<Commit>` und sortieren
vor der entsprechenden Paketrevision ohne CI-Suffix. `pqkeep --version` zeigt weiterhin
die Upstream-Version aus Cargo an. Paket- und Programmversion haben unterschiedliche Zwecke.

### Paket lokal bauen

Voraussetzungen: passendes natives GNU-Release-Binary mit glibc-Anforderungen bis 2.35,
Python ab 3.10, Rust/Cargo und die bereits geladenen Lockfile-Abhängigkeiten, `binutils`,
`dpkg-dev` und `dpkg`. Der Paketbau läuft ohne Root-Rechte und installiert nichts.

```sh
cargo build --release --locked --target x86_64-unknown-linux-gnu
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
python3 scripts/release_deb.py target/x86_64-unknown-linux-gnu/release/pqkeep \
  x86_64-unknown-linux-gnu deb-dist --ci-sha "$(git rev-parse HEAD)"
```

Auf einer neueren Builddistribution kann die ABI-Prüfung bewusst abbrechen, falls das
Binary neuere glibc-Symbole benötigt. Bestehende `.deb`-Dateien werden nicht überschrieben.
Der Installations-Testhelfer ist ausschließlich für die vorgesehenen kurzlebigen
GitHub-Actions-Container bestimmt, niemals für einen produktiven Rechner.

## English

### Debian test candidate

Issue #93 phase 3 adds an **AMD64 CI package**, not a published or signed Debian release.
The Release workflow's `candidate-debian-amd64` artifact contains
`pqkeep_<Debian-version>_amd64.deb` and is retained for 14 days. Use your reviewed workflow
run and compare its SHA-256 with the download. A checksum alone does not authenticate a
package; signed releases require phase 6 approval.

The package requires Linux AMD64 and the libraries declared in its metadata. Builds use
Ubuntu 22.04; `dpkg-shlibdeps` calculates the actual dependencies. Initial installation
checks cover Debian 12 and Ubuntu 22.04 in native AMD64 test containers. The full
distribution/upgrade matrix follows in phase 5; ARM64 packages follow in phase 4.

After approving installation in a suitable test system, substitute the actual file name:

```sh
dpkg --print-architecture
dpkg-deb --info "./pqkeep_<Debian-version>_amd64.deb"
sudo apt install "./pqkeep_<Debian-version>_amd64.deb"
pqkeep --version
pqkeep --lang en --help
man pqkeep
```

APT resolves the declared dependencies. The executable is `/usr/bin/pqkeep`; German and
English manuals and Bash/Zsh/Fish completions use standard `/usr/share` locations.
Licenses, copyright, dependency license inventory and change logs are in
`/usr/share/doc/pqkeep`. No service starts, account is created or user profile is modified.
Existing commands and the default `api` feature remain available; the server requires
an explicit CLI invocation.

Remove the package with `sudo apt remove pqkeep`. Even `sudo apt purge pqkeep` leaves
user-created keys and files untouched: there are no maintainer scripts or conffiles.
Context menus created manually with `pqkeep integrate` remain user data and can become
stale; remove them explicitly with the existing CLI beforehand if desired. Packaging
never invokes integration commands automatically.

CI versions such as `0.1.0~beta.1-1~ci.<UTC-time>.<commit>` sort before the corresponding
package revision without the CI suffix. `pqkeep --version` still reports Cargo's upstream
version. To build locally, use the commands above on a matching native GNU system with
glibc requirements at most 2.35, Python 3.10+, Rust/Cargo, cached locked dependencies,
`binutils`, `dpkg-dev` and `dpkg`. Packaging is unprivileged and installs nothing. Newer
build distributions can produce binaries that the ABI check correctly rejects.
Existing output packages are never overwritten. The installation test helper is for
the designated disposable GitHub containers only, never a production machine.
