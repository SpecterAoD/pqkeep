# Issue #93 – Testmatrix der Debian-Pakete / Debian package test matrix

Stand: 12.11.2026 (Phase 5). Gilt für die CI-Kandidaten `pqkeep_<Version>_amd64.deb` und
`pqkeep_<Version>_arm64.deb`. Es ist weiterhin nichts veröffentlicht oder signiert.

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

### Nicht nachgewiesen

Diese Punkte aus dem Implementierungsplan (Abschnitt 6) sind bewusst offen und werden später
mit eigenen Test-VMs nachgeholt. Bis dahin macht PQKeep dazu keine Aussage:

- **Platzmangel** während der Installation und ein **echter Abbruch** mitten im dpkg-Lauf
  (z. B. Prozessende, Stromausfall). Geprüft ist nur der definierte Zwischenzustand
  „entpackt, nicht konfiguriert“.
- **Kernel der Zieldistribution**: Seccomp, Landlock und memlock sind nur mit dem Kernel der
  GitHub-Runner (Ubuntu 22.04) nativ geprüft, nicht mit den Kerneln von Debian 12/13 und
  Ubuntu 24.04/26.04.
- **ARM64 mit 64-KiB-Seiten**: keine Testumgebung vorhanden.
- Andere Distributionen (Linux Mint, Raspberry Pi OS, Kali u. a.) und 32-Bit-ARM (`armhf`).

## English

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

### Without evidence

These items from the implementation plan (section 6) are deliberately open and will be covered
later with dedicated test VMs. Until then PQKeep makes no statement about them:

- **Out of disk space** during installation and a **real abort** in the middle of a dpkg run
  (e.g. process kill, power loss). Only the defined intermediate state "unpacked, not
  configured" is tested.
- **Target distribution kernels**: seccomp, Landlock and memlock are natively tested only with
  the GitHub runners' kernel (Ubuntu 22.04), not with the kernels of Debian 12/13 and
  Ubuntu 24.04/26.04.
- **ARM64 with 64 KiB pages**: no test environment available.
- Other distributions (Linux Mint, Raspberry Pi OS, Kali and others) and 32-bit ARM (`armhf`).
