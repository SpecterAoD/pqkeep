# Installation / Installation

## Deutsch

### Debian-Paket als Testkandidat

Issue #93, Phasen 3 und 4 ergänzen **CI-Pakete für AMD64 und ARM64**, noch kein
veröffentlichtes oder signiertes Debian-Release. Die Actions-Artefakte
`candidate-debian-amd64` und `candidate-debian-arm64` im Release-Workflow enthalten
`pqkeep_<Debian-Version>_amd64.deb` bzw. `pqkeep_<Debian-Version>_arm64.deb` und sind
14 Tage verfügbar. Verwende für einen Test nur den eigenen geprüften Workflowlauf und
vergleiche dessen SHA-256 mit dem Download. Eine Prüfsumme allein bestätigt keine Herkunft;
signierte Releases folgen erst in Phase 6.

Jedes Paket benötigt die passende Architektur (Linux AMD64 bzw. ARM64, 64 Bit) und die im
Paket ausgewiesenen Bibliotheken. Beide Builds laufen nativ auf Ubuntu 22.04;
`dpkg-shlibdeps` bestimmt die konkreten Abhängigkeiten. Geprüft werden Debian 12 und 13
sowie Ubuntu 22.04, 24.04 und 26.04 in nativen Testcontainern beider Architekturen:
Installation, Reinstall, Upgrade, Downgrade, Entfernung, Purge und abgewiesene Pakete.
Umfang, Grenzen und nicht nachgewiesene Fälle stehen in der
[Testmatrix](issue-93-testmatrix.md). Andere Distributionen (z. B. Linux Mint,
Raspberry Pi OS, Kali) sind nicht geprüft. Die Pakete sind
eigenständig: Ein AMD64-Paket lässt sich nicht als ARM64-Paket verwenden und umgekehrt;
32-Bit-ARM (`armhf`) wird nicht unterstützt.

Nach eigener Freigabe in einem geeigneten Testsystem (Dateiname und Architektur – `amd64`
oder `arm64`, siehe erste Zeile – entsprechend ersetzen):

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

Auf ARM64 entsprechend mit `aarch64-unknown-linux-gnu`. Der Paketbau ist nur nativ möglich:
Ein Paket für die jeweils andere Architektur (Cross-Paketierung) wird abgewiesen.

Auf einer neueren Builddistribution kann die ABI-Prüfung bewusst abbrechen, falls das
Binary neuere glibc-Symbole benötigt. Bestehende `.deb`-Dateien werden nicht überschrieben.
Der Installations-Testhelfer ist ausschließlich für die vorgesehenen kurzlebigen
GitHub-Actions-Container bestimmt, niemals für einen produktiven Rechner.

## English

### Debian test candidate

Issue #93 phases 3 and 4 add **CI packages for AMD64 and ARM64**, not a published or
signed Debian release. The Release workflow's `candidate-debian-amd64` and
`candidate-debian-arm64` artifacts contain `pqkeep_<Debian-version>_amd64.deb` and
`pqkeep_<Debian-version>_arm64.deb` and are retained for 14 days. Use your reviewed workflow
run and compare its SHA-256 with the download. A checksum alone does not authenticate a
package; signed releases require phase 6 approval.

Each package requires the matching architecture (64-bit Linux AMD64 or ARM64) and the
libraries declared in its metadata. Both builds run natively on Ubuntu 22.04;
`dpkg-shlibdeps` calculates the actual dependencies. Checks cover Debian 12 and 13 and
Ubuntu 22.04, 24.04 and 26.04 in native test containers of both architectures: install,
reinstall, upgrade, downgrade, removal, purge and rejected packages. Scope, limits and
cases without evidence are listed in the [test matrix](issue-93-testmatrix.md). Other
distributions (e.g. Linux Mint, Raspberry Pi OS, Kali) are not tested. The packages are
independent: an AMD64
package cannot be used as an ARM64 package or vice versa; 32-bit ARM (`armhf`) is not
supported.

After approving installation in a suitable test system, substitute the actual file name
and architecture (`amd64` or `arm64`, see the first line):

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
version. To build locally, use the commands above (on ARM64 with
`aarch64-unknown-linux-gnu`; packaging is native only, cross-packaging for the other
architecture is rejected) on a matching native GNU system with
glibc requirements at most 2.35, Python 3.10+, Rust/Cargo, cached locked dependencies,
`binutils`, `dpkg-dev` and `dpkg`. Packaging is unprivileged and installs nothing. Newer
build distributions can produce binaries that the ABI check correctly rejects.
Existing output packages are never overwritten. The installation test helper is for
the designated disposable GitHub containers only, never a production machine.
