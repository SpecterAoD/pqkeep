# Debian-Paket-Tests / Debian package tests

**DE** | [EN](#english)

Stand: 18.11.2026. Geprüft
werden die CI-Kandidaten `pqkeep_<Version>_amd64.deb` und `pqkeep_<Version>_arm64.deb`; die
Release-Pakete `pqkeep-<Version>-<Architektur>.deb` sind dieselben Dateien unter anderem Namen.

## Deutsch

### Zielsysteme

| Distribution | amd64 | arm64 | Art des Nachweises |
|---|---|---|---|
| Debian 12 (bookworm) | geprüft | geprüft | nativer Container |
| Debian 13 (trixie) | geprüft | geprüft | nativer Container |
| Ubuntu 22.04 LTS | geprüft | geprüft | nativer Container |
| Ubuntu 24.04 LTS | geprüft | geprüft | nativer Container |
| Ubuntu 26.04 LTS | geprüft | geprüft | nativer Container |

„Nativer Container“ heißt: offizielles Image (per Digest festgelegt) auf einem GitHub-Runner
derselben Architektur (`ubuntu-22.04` bzw. `ubuntu-22.04-arm`), ohne Emulation und ohne
privilegierte Optionen. Benutzerraum, Paketverwaltung und Bibliotheken stammen aus der
Zieldistribution; der **Kernel ist der des Runners** (Ubuntu 22.04, 4-KiB-Seiten). Die
vollständigen Rust-Tests einschließlich Sandbox- und memlock-Tests laufen nativ auf beiden
Runner-Architekturen (reguläre CI), nicht in jedem Container. Vollsystememulation und rein
statische Prüfung werden nicht als Nachweis verwendet.

### Geprüfte Fälle je Zielsystem

Jeder Job führt `scripts/release_deb_smoke.py` und `scripts/release_deb_lifecycle.py` aus.
PQKeep läuft als unprivilegierter Benutzer; Paketverwaltung nur im Wegwerfcontainer. Nirgends
wird `--force-…` verwendet. Befehle, Versionen und Exit-Codes stehen im jeweiligen Jobprotokoll.

| Fall | Geforderte Aussage |
|---|---|
| Lintian | ohne Overrides, kein Fehler |
| Erstinstallation | Abhängigkeiten auflösbar; Dateien, Rechte (root:root, 0755/0644) und Inhalt wie im Paket; `dpkg --verify` ohne Befund; Hilfe DE/EN; Rauchtest mit aktiver Seccomp-Sandbox |
| Reinstall | gleiche Version erneut; Zustand und Dateien korrekt |
| Upgrade | Kandidat → Nachfolger-Testpaket (gleiches Binary, spätere Version) |
| Downgrade | Nachfolger → Kandidat, ausdrücklich mit `--allow-downgrades` |
| Unterbrochene Konfiguration | nur entpackt (`dpkg --unpack`), dann `dpkg --configure`; danach vollständig installiert |
| Entfernung / Purge | nur Paketdateien entfernt, kein Paketrest |
| Falsche Architektur | Paket der anderen Architektur wird abgewiesen, kein Paketzustand |
| Beschädigtes Paket | abgeschnittene und verfälschte Datei werden abgewiesen; kein Paketrest |
| Fehlende Abhängigkeit | apt lehnt ab und ändert nichts; dpkg lässt das Paket unkonfiguriert, Konfiguration scheitert, `dpkg --remove` stellt den Ausgangszustand her |
| Dateikonflikt | Datei eines fremden Pakets unter `/usr/bin/pqkeep` wird nicht überschrieben |
| Datenbestand | Schlüssel, öffentlicher Schlüssel, Klartext und zwei verschlüsselte Dateien (Passphrase, Empfänger) entstehen **vor** der ersten Installation; nach jedem Schritt sind Hash, Rechte und Eigentümer unverändert und beide Dateien werden korrekt entschlüsselt |

Upgrade und Downgrade verwenden zwei gekennzeichnete Testrevisionen desselben Builds. Das ist
**kein** Nachweis für ein Upgrade von einer veröffentlichten Vorgängerversion; den gibt es erst,
wenn ein veröffentlichtes `.deb` existiert.

### In echten VMs geprüft (18.11.2026, #163)

Kandidat `pqkeep_0.1.0~beta.2-1~ci.20261115150230.73b6556ba289_amd64.deb` in VMs mit dem
**Kernel der jeweiligen Distribution** (offizielle Cloud-Images, KVM, je 1,5 GB RAM; vor jedem
Fall frischer Snapshot). Nutzerdaten (Schlüssel, öffentlicher Schlüssel, Klartext, je eine mit
Passphrase und für einen Empfänger verschlüsselte Datei) entstanden **vor** der Installation;
nach jedem Schritt wurden Hashes geprüft und beide Dateien entschlüsselt. Werkzeug:
Testumgebung des Maintainers (`pkgtest.py`), Ergebnisse je Lauf protokolliert.

| Fall | Debian 12 (6.1) | Debian 13 (6.12) | Ubuntu 24.04 (6.8) |
|---|---|---|---|
| Installation, `dpkg --verify`, Ver-/Entschlüsseln, `check` | ✓ | ✓ | ✓ |
| Sandbox auf dem Distributionskernel | `landlock=partial seccomp=full` | `landlock=full seccomp=full` | `landlock=partial seccomp=full` |
| Platz voll (auch root-Vorrat) | dpkg bricht ab, Paket nicht installiert | dpkg bricht ab, Paket nicht installiert | dpkg bricht ab (auch Statusdatenbank nicht schreibbar), Paket nicht installiert |
| Echter Abbruch (VM hart aus nach 0,4 / 1,5 / 3 s) | 3× nicht installiert | 1× nicht installiert, 2× „half-installed“ | 3× nicht installiert |

- **Nutzerdaten:** in allen 17 Läufen unverändert (Hashes gleich, beide Dateien entschlüsselbar).
- **Wiederherstellung:** nach Platz schaffen bzw. Neustart immer mit
  `sudo dpkg --configure -a` und erneutem `sudo dpkg -i <paket>`; danach installiert,
  `dpkg --audit` und `dpkg --verify` ohne Befund.
- `landlock=partial` ist bei Kerneln vor 6.12 erwartet (Signal-/Socket-Bereiche erst ab 6.12,
  siehe [SANDBOX.md](SANDBOX.md)).
- Die Abbruch-Zeitpunkte treffen den dpkg-Lauf nicht gezielt; ein Abbruch im Schreiben der
  Statusdatenbank selbst ist damit wahrscheinlich, aber nicht sicher abgedeckt.

### Nicht nachgewiesen

- **ARM64 mit 64-KiB-Seiten**: keine Testumgebung vorhanden.
- **memlock** auf den Distributionskerneln: Die Sandbox ist geprüft, die Zahl gesperrter Seiten
  wurde in den VMs nicht gemessen (nur in der CI auf dem Runner-Kernel).
- Ubuntu 22.04 und 26.04 nur in Containern (Kernel des Runners), nicht in VMs.
- Andere Distributionen (Linux Mint, Raspberry Pi OS, Kali u. a.) und 32-Bit-ARM (`armhf`).

## English

As of 2026-11-18. Tested are the CI candidates `pqkeep_<version>_amd64.deb` and
`pqkeep_<version>_arm64.deb`; the release packages `pqkeep-<version>-<architecture>.deb` are the
same files under a different name.

### Target systems

Debian 12 and 13 and Ubuntu 22.04, 24.04 and 26.04 LTS are tested for amd64 and arm64 in
**native containers**: the official image (pinned by digest) on a GitHub runner of the same
architecture, without emulation or privileged options. Userspace, package management and
libraries come from the target distribution; the **kernel is the runner's** (Ubuntu 22.04,
4 KiB pages). The full Rust tests including sandbox and memlock tests run natively on both
runner architectures (regular CI), not inside every container. Full-system emulation and purely
static checks are not used as evidence.

### Cases per target system

Every job runs `scripts/release_deb_smoke.py` and `scripts/release_deb_lifecycle.py`. PQKeep
runs as an unprivileged user; package management happens only in the disposable container.
`--force-…` is never used. Commands, versions and exit codes are in the job logs.

| Case | Required statement |
|---|---|
| Lintian | no overrides, no error |
| First install | dependencies resolvable; files, permissions (root:root, 0755/0644) and content as packaged; clean `dpkg --verify`; help DE/EN; smoke test with active seccomp sandbox |
| Reinstall | same version again; state and files correct |
| Upgrade | candidate → successor test package (same binary, later version) |
| Downgrade | successor → candidate, explicitly with `--allow-downgrades` |
| Interrupted configuration | unpacked only (`dpkg --unpack`), then `dpkg --configure`; fully installed afterwards |
| Removal / purge | only package files removed, nothing left behind |
| Wrong architecture | the other architecture's package is rejected, no package state |
| Damaged package | truncated and corrupted files are rejected; nothing left behind |
| Missing dependency | apt refuses and changes nothing; dpkg leaves the package unconfigured, configuration fails, `dpkg --remove` restores the initial state |
| File conflict | a foreign package's file at `/usr/bin/pqkeep` is not overwritten |
| User data | key, public key, plaintext and two encrypted files (passphrase, recipient) are created **before** the first installation; after every step hash, permissions and owner are unchanged and both files decrypt correctly |

Upgrade and downgrade use two marked test revisions of the same build. This is **not** evidence
for upgrading from a published predecessor; that requires a published `.deb`.

### Checked in real VMs (2026-11-18, #163)

Candidate `pqkeep_0.1.0~beta.2-1~ci.20261115150230.73b6556ba289_amd64.deb` in VMs running **each
distribution's own kernel** (official cloud images, KVM, 1.5 GB RAM each; fresh snapshot before
every case). User data (key, public key, plaintext, one file encrypted with a passphrase and one
for a recipient) was created **before** installation; after every step hashes were checked and
both files decrypted. Tool: the maintainer's test environment (`pkgtest.py`), results logged per
run.

| Case | Debian 12 (6.1) | Debian 13 (6.12) | Ubuntu 24.04 (6.8) |
|---|---|---|---|
| Install, `dpkg --verify`, encrypt/decrypt, `check` | ✓ | ✓ | ✓ |
| Sandbox on the distribution kernel | `landlock=partial seccomp=full` | `landlock=full seccomp=full` | `landlock=partial seccomp=full` |
| Disk full (incl. root reserve) | dpkg aborts, package not installed | dpkg aborts, package not installed | dpkg aborts (status database not writable either), package not installed |
| Real abort (VM powered off after 0.4 / 1.5 / 3 s) | 3× not installed | 1× not installed, 2× "half-installed" | 3× not installed |

- **User data:** unchanged in all 17 runs (same hashes, both files decryptable).
- **Recovery:** after freeing space or rebooting, always with `sudo dpkg --configure -a` and
  `sudo dpkg -i <package>` again; afterwards installed, `dpkg --audit` and `dpkg --verify` clean.
- `landlock=partial` is expected on kernels before 6.12 (signal/socket scopes only from 6.12, see
  [SANDBOX.md](SANDBOX.md)).
- The abort times do not target the dpkg run precisely; an abort while writing the status
  database itself is likely but not certainly covered.

### Without evidence

- **ARM64 with 64 KiB pages**: no test environment available.
- **memlock** on the distribution kernels: the sandbox is checked, the number of locked pages was
  not measured in the VMs (only in CI on the runner kernel).
- Ubuntu 22.04 and 26.04 only in containers (runner kernel), not in VMs.
- Other distributions (Linux Mint, Raspberry Pi OS, Kali and others) and 32-bit ARM (`armhf`).
