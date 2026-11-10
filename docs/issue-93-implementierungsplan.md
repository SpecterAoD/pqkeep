# Issue #93: Analyse, Architektur und Implementierungsplan

**Stand der Analyse:** 10.11.2026. Phase 1 ist abgeschlossen; der Nutzer hat Phase 2
am 10.11.2026 ausdrücklich freigegeben. Umsetzung und Nachweise stehen im
[Phase-2-Bericht](issue-93-phase2.md). Die folgende Bestandsaufnahme beschreibt weiterhin
die unveränderte Ausgangsbasis. Phase 2 wurde über PR #158 übernommen; Phase 3 ist
ausdrücklich freigegeben und wird im [Phase-3-Bericht](issue-93-phase3.md) dokumentiert.
Phasen 4–6 benötigen jeweils eine neue Freigabe.
Auftrag: [#93](https://github.com/SpecterAoD/pqkeep/issues/93).
Analysierte Basis: `569c233afadb2b2b20553e0832c555023d35f055` auf `main`.
Alle Aussagen zum Repository beziehen sich auf diesen Commit, nicht auf ältere lokale Branches.

## 1. Entscheidungsvorschlag und Grenzen

1. Linux ARM64 nativ auf `ubuntu-22.04-arm` für `aarch64-unknown-linux-gnu` bauen und ausführen.
   Ubuntu 22.04 bleibt die Buildbasis für glibc 2.35. Die bestehenden Linux-AMD64- und
   Windows-MSVC-Zeilen einschließlich `pqkeepw.exe` und CFG bleiben erhalten.
2. Ein gemeinsamer Debian-Paketierer verarbeitet das bereits geprüfte Release-Binary;
   Architektur ist ein validierter Parameter. Keine zweite Build- oder Kryptologik.
3. Die vorhandenen Skripte für Archive, Smoke-Test und SBOM weiterverwenden.
   Die vorhandene CLI erzeugt Manpages und Completions bereits selbst.
4. Neue Artefakte bis Phase 6 ausschließlich als CI-Kandidaten bereitstellen, getrennt von
   den vom Signierjob eingesammelten `dist-*`-Artefakten. Keine teilgesicherten Releases.
5. musl ist eine sinnvolle spätere Option für portable Archive, aber **nicht Teil der sechs
   Implementierungsphasen**. Zunächst GNU/glibc und Debian abschließen.

Keine Änderung an Kryptografie, KDF-Parametern, Schlüsselverwaltung, `.pqkf`-/Schlüssel-/
Signaturformaten oder CLI-Semantik. Default-Feature `api` bleibt wie bei bisherigen Releases
aktiv; das Paket startet dennoch keinen Server. Kein Daemon, Dienst, GUI-Paket, RPM, APT-Repository,
Updater, neuer Signierschlüssel oder zusätzlicher GitHub-Berechtigungsumfang.
Jede Phase benötigt eine ausdrückliche Freigabe; jeder Implementierungsschritt einen eigenen PR.
Ein genehmigter Plan ersetzt keine Freigabe zur Veröffentlichung oder produktiven Installation.

## 2. Istzustand und untersuchte Quellen

Gelesen: `README.md`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.cargo/config.toml`,
`.github/workflows/{ci,release,audit,codeql}.yml`, alle vorhandenen `scripts/release_*.py`,
`scripts/check_binary.py`, deren Tests und `scripts/check_limits.sh`.
Zusätzlich: `CONTRIBUTING.md`, `CLAUDE.md`, `docs/SPEC.md` (relevante Vorgaben),
`docs/CHECKLIST.md`, `SECURITY.md`, `CODE_SIGNING_POLICY.md`,
`docs/{RELEASE,CRYPTO,SANDBOX,MEMORY_HARDENING,THREAT_MODEL,SECURITY_REVIEW,KEY_MANAGEMENT,SERVER}.md`,
`NOTICE`, `data/wordlists/LICENSES.md`,
CLI-Hilfegenerator, Seccomp-/Speichersperrcode und relevante bestehende Tests.
Die übrigen Testdateien wurden nach Zuständigkeit und Plattformbedingungen inventarisiert.

### 2.1 Ziele, Toolchain und CI

| Bereich | Nachgewiesener Stand im Quelltext |
|---|---|
| Paketversion | `0.1.0-beta.1`, Edition 2024, MSRV 1.88, `publish = false` |
| Toolchain | `stable`, minimal, mit rustfmt/clippy; keine feste Compiler-Version |
| Linux-Release | `ubuntu-22.04`, `x86_64-unknown-linux-gnu`, `pqkeep`, `.tar.gz` |
| Windows-Release | `windows-latest`, `x86_64-pc-windows-msvc`, `pqkeep.exe` und verpflichtend `pqkeepw.exe`, `.zip` |
| Reguläre CI | Ubuntu latest, Ubuntu 22.04, Windows latest: fmt, Clippy mit/ohne API, Rust-Tests, v2-Referenztests |
| Weitere CI | MSRV-Check 1.88; Limits, Härtung Linux/Windows, cargo-deny, Gitleaks; separat CodeQL und wöchentliches Audit/Fuzzing |
| ARM64/Debian/musl | Keine Buildmatrix-Zeile bzw. Paketimplementierung vorhanden |

Releaseprofil: `overflow-checks=true`, LTO, ein Codegen-Unit, Strip, `panic="abort"`.
Windows-CFG wird sowohl in `.cargo/config.toml` als auch ausdrücklich in Release-RUSTFLAGS gesetzt,
weil die Umgebungsvariable die Konfiguration übersteuert. Diese Absicherung muss erhalten bleiben.

### 2.2 Artefakte und Release-Vertrauen

Die GitHub-Release-Abfrage ergab eine veröffentlichte Vorabversion:
[v0.1.0-beta.1](https://github.com/SpecterAoD/pqkeep/releases/tag/v0.1.0-beta.1), acht Assets:
je Ziel ein Archiv, eine `.cdx.json` und ein Archiv-`.sigstore.json`, dazu `SHA256SUMS`
und `SHA256SUMS.sigstore.json`. Keine `.deb`- oder ARM64-Assets.
Die Asset-Liste wurde gelesen; die veröffentlichten Dateien wurden hier nicht heruntergeladen
oder kryptografisch neu verifiziert. Der aktuelle Windows-Paketierer enthält Änderungen nach
diesem Release; dessen heutigen Inhalt nicht rückwirkend für das veröffentlichte ZIP behaupten.

Der Workflow hat drei Auslöser: signierter `v*`-Tag, `workflow_dispatch`, ausgewählte PR-Pfade.
`prepare` prüft Tag-Signatur gegen `.github/allowed_signers`, Übereinstimmung mit Cargo-Version
und Existenz der Release-Notizen. Nicht-Tag-Builds erhalten `<Cargo-Version>-dev.<Kurz-SHA>`.
Die im Binary angezeigte Cargo-Version enthält diesen CI-Suffix nicht.

- Build, Härtung, Smoke, Archiv und CycloneDX 1.5 erfolgen im Buildjob mit Leserechten.
- Der Release-Workflow führt nicht selbst die komplette Rust-/Security-CI erneut aus;
  die Freigabe muss deren erfolgreiche Läufe für exakt den ausgewählten Commit belegen.
- `cargo-cyclonedx` ist auf 0.5.9, Cosign auf v3.1.4, Actions sind auf Commit-SHAs festgelegt.
- `release_sbom.py` setzt UUIDv5 aus Repository/Version/Ziel/Commit und den Zeitstempel aus
  `SOURCE_DATE_EPOCH`. Die zwei SBOM-Attestationen sind derzeit hart auf x86_64-Ziele festgelegt.
  Der CycloneDX-Aufruf enthält selbst kein `--locked`; bei Erweiterung Lockfile-Hash und
  tatsächlich aufgelösten Ziel-/Featuregraphen gegen den Build prüfen, Änderungen ablehnen.
- Build-Provenance erfasst nur `.tar.gz` und `.zip`; Prüfsummen zusätzlich `.cdx.json`.
  Sigstore signiert Archive und Prüfsummen. Der Verifyjob prüft Prüfsummen, Build- und
  CycloneDX-Attestationen sowie Sigstore-Identität und OIDC-Issuer.
- Schreibrechte `contents`, `id-token`, `attestations` liegen nur im Job `publish` hinter
  `environment: release`; PRs erreichen ihn nicht. `verify` hat lesende Attestationsrechte.
- Tags erzeugen einen **Entwurf vor dem Verifyjob**. Manuelle Veröffentlichung bleibt erst
  nach erfolgreicher Verifikation zulässig. Dispatch signiert ebenfalls, erzeugt aber keinen
  Release-Entwurf. Attestationen/Transparenzlog-Einträge sind trotzdem dauerhaft öffentlich.
- Das YAML und die Doku verlangen eine manuelle Environment-Freigabe. Die tatsächliche
  GitHub-Environment-/Reviewer-Konfiguration wurde in Phase 1 nicht administrativ verifiziert;
  sie ist vor einem späteren Signierlauf zu bestätigen, ohne Rechte still zu erweitern.
- Authenticode/SignPath ist noch nicht eingerichtet; #93 übernimmt diese separate Aufgabe nicht.

### 2.3 Härtung und Smoke-Tests

`check_binary.py` erkennt ELF/PE anhand der Bytes. Für ELF liest es mit `readelf` unter
`LC_ALL=C` PIE (`DYN` und PIE-Flag), GNU_RELRO, NOW/BIND_NOW und nicht ausführbaren GNU_STACK.
Für PE prüft es High-Entropy-ASLR, DYNAMIC_BASE, NX_COMPAT und GUARD_CF.
Der ELF-Pfad ist grundsätzlich architekturunabhängig, prüft aber **weder ELF-Machine noch ABI,
Interpreter oder benötigte glibc-Symbolversionen**. Eine erfolgreiche Härtungsprüfung beweist
deshalb weder ARM64-Architektur noch Lauffähigkeit auf dem ältesten Zielsystem.
`--dry-run` ist ausdrücklich kein Abnahmenachweis: fehlende Härtung führt dabei nicht zu Exit 1.

`release_smoke.py` startet das übergebene Binary tatsächlich: Version, Passphrase, Schlüssel/
Public-Key-Export, 200.000-Byte-Datei mit Passphrase und Empfänger verschlüsseln/entschlüsseln,
Bytevergleich; unter Linux muss stderr `seccomp=full` enthalten. Laufzeit-Passphrasen bleiben
im Testprozess; temporäre Dateien werden automatisch aufgeräumt. Timeout je Aufruf: 600 Sekunden.
Der Test benötigt passende CPU, Loader, libc und Kernel. Er besitzt keinen Cross-Runner-Adapter.
Er prüft weder API noch Signaturen, sämtliche Parametersätze oder verpflichtend Landlock.

Die Skripttests verwenden künstliche Binärdateien: Sie belegen Archivinhalt, wiederholbares
Verpacken, SBOM-Normalisierung und die Trockenlauf-Schnittstelle, **keine Binary-Ausführung**.
Rust-Tests ergänzen KATs, Manipulations-/Parser-/Dateitests, API, CLI, Signaturen, Prozesshärtung
und Sandbox-Negativfälle. `sandbox_cli`/`sandbox_api` können Landlock-Prüfungen bei fehlender
Kernelunterstützung auslassen; interne memlock-Tests haben ebenfalls bedingte Prüfpfade.
Solche Pfade müssen im späteren Abnahmebericht ausgewiesen werden, nicht als Schutzbeweis gelten.

**Konkreter Portabilitätsbefund:** `tests/hardening_memlock.rs` setzt `size = 3 * 4096` und
verlangt mindestens drei gesperrte Seiten. Das passt nicht zu ARM64-Kerneln mit 16/64-KiB-Seiten.
Produktionscode nutzt bereits `region::page::size()`. Phase 2 soll den Test auf die echte
Seitengröße beziehen und die gleich starke Aussage „mindestens drei Seiten“ erhalten;
keine Testabschaltung und keine Änderung am Speichersperrverhalten.

### 2.4 Rust- und Kryptografie-Abhängigkeiten

Versionen aus dem Lockfile; Architekturprüfung zusätzlich an den lokal vorhandenen Crate-Quellen:

| Abhängigkeit | ARM64-Bewertung / erforderlicher Nachweis |
|---|---|
| `ml-kem 0.3.4`, `ml-dsa 0.1.2` | Reine Rust-Implementierungen, MSRV 1.87, keine x86-only-Sperre in den untersuchten Quellen. Native NIST-/Wycheproof-KATs und alle Parametersätze bleiben Pflicht. |
| `aes-gcm 0.11.1` → `aes 0.9.2` | ARMv8-AES mit Laufzeiterkennung und portablem Softwarepfad; keine erzwungenen CPU-Instruktionen. |
| `ghash 0.6.0` → `polyval 0.7.3` | aarch64-PMULL mit Laufzeiterkennung und portablem Rückfall. Timing-Eigenschaften des Softwarepfades hängen u. a. von der Multiplikation der CPU ab. |
| `argon2 0.6.0`, Feature `parallel` | Portabler 64-Bit-Pfad; AVX2-Code nur unter x86 cfg. Rayon/Threads, Speicherbudget und Laufzeit auf ARM prüfen; Parameter keinesfalls reduzieren. |
| `getrandom 0.4.3`, `sha3 0.12.0`, `hkdf 0.13.0`, `zeroize 1.9.1` | Vorhandene RNG-, Hash-, Ableitungs- und Zeroize-Wege beibehalten; Referenzvektoren und Fehlerpfade nativ ausführen. |
| `seccompiler 0.5.0`, `libc 0.2.191` | aarch64 little endian unterstützt; Architekturauswahl anhand `std::env::consts::ARCH`. Syscallnummern aus libc; x86-Legacy-Aufrufe bereits cfg-begrenzt. |
| `landlock 0.4.7`, `rustix 1.1.6`, `region 4.0.1` | Kernel-/Seiten-/Limitabhängigkeiten nativ prüfen; kleine Test-VMs können memlock oder Argon2 begrenzen. |

Die geprüften PQ-/AEAD-/KDF-Crates haben keinen eigenen C-Buildschritt; aus dieser Untersuchung
ergibt sich kein Bedarf an OpenSSL/liboqs oder einer anderen Kryptobibliothek.
Dies ist eine statische Kompatibilitätsbewertung, kein ARM64-Build-, Audit- oder Timingnachweis.
Ergänzende Primärquellen: [AES-Backends](https://docs.rs/aes/0.9.2/aes/),
[POLYVAL-Backends und Grenzen](https://docs.rs/polyval/0.7.3/polyval/).
Die Webabrufe der konkreten ML-KEM-/ML-DSA-Dokumentationsseiten waren nicht verfügbar;
deren Bewertung stützt sich auf Lockfile, lokale versionierte Crate-Quellen und Projekt-KATs.

## 3. Überschneidungen mit Issues und PRs

Am 10.11.2026 #93 einschließlich Kommentaren gelesen (offen, keine Kommentare).
Repositoryweite Suche: 100 zuletzt aktualisierte Issues, 44 PR-Treffer über alle Zustände;
zusätzlich Suche nach offenen PRs: **keine Treffer**. Relevante Inhalte einzeln abgeglichen.
Die Issue-Liste ist mengenbegrenzt; kein Anspruch auf eine vollständig gelesene historische
Issue-Datenbank. Vor jedem Implementierungs-PR erneut auf neue parallele Arbeit prüfen.

| Vorgang | Beziehung und Abgrenzung |
|---|---|
| [#82](https://github.com/SpecterAoD/pqkeep/issues/82), [#84](https://github.com/SpecterAoD/pqkeep/issues/84), PR [#91](https://github.com/SpecterAoD/pqkeep/pull/91) | Serverdoku und Batch-/Datei-Passphrase bereits in main, Issues geschlossen. Wiederverwenden, keine systemd-Installation aus den Dokumentationsbeispielen ableiten. |
| PR [#36](https://github.com/SpecterAoD/pqkeep/pull/36), [#38](https://github.com/SpecterAoD/pqkeep/pull/38) | Bestehende Release- und SBOM-Implementierung; keine zweite Signierpipeline. |
| PR [#24](https://github.com/SpecterAoD/pqkeep/pull/24) | Manpage und Completions bereits implementiert; CLI als Generator nutzen. |
| PR [#75](https://github.com/SpecterAoD/pqkeep/pull/75), [#78](https://github.com/SpecterAoD/pqkeep/pull/78) | Windows-Integration und Launcher bereits enthalten; ZIP-Inhalt und Härtung beider EXEs erhalten. |
| [#60](https://github.com/SpecterAoD/pqkeep/issues/60), [#65](https://github.com/SpecterAoD/pqkeep/issues/65), [#95](https://github.com/SpecterAoD/pqkeep/issues/95), [#100](https://github.com/SpecterAoD/pqkeep/issues/100) | Offene GUI-/Daemon-Vorhaben. CLI-Paket unabhängig halten, keinen Dienst vorwegnehmen. |
| [#97](https://github.com/SpecterAoD/pqkeep/issues/97), [#154](https://github.com/SpecterAoD/pqkeep/issues/154) | Offene Baseline-/Reproduzierbarkeitsarbeiten. #93 liefert architektur- und paketbezogene Nachweise; kein zweites allgemeines QA-Framework oder vorweggenommenes v1-Audit. |
| [#143](https://github.com/SpecterAoD/pqkeep/issues/143), [#144](https://github.com/SpecterAoD/pqkeep/issues/144) | TUF-/Update-Vertrauen und separate Release-Metadaten. #93 erweitert bestehende Sigstore-/Attestationszuordnung; keine neuen Vertrauensrollen oder Schlüssel. |
| [#88](https://github.com/SpecterAoD/pqkeep/issues/88), PR [#76](https://github.com/SpecterAoD/pqkeep/pull/76) | SignPath bleibt separater Freigabeprozess. |
| [#39](https://github.com/SpecterAoD/pqkeep/issues/39), [#45](https://github.com/SpecterAoD/pqkeep/issues/45), PR [#79](https://github.com/SpecterAoD/pqkeep/pull/79) | v2-Formatentwurf ist vorhanden, aber nicht implementiert; keine Datenmigration durch Packaging. |

## 4. Buildarchitektur: nativ, Cross und musl

| Verfahren | Bewertung |
|---|---|
| Nativ `ubuntu-22.04-arm` | Empfehlung: dieselbe libc-Basis wie AMD64, reales ARM64-Programm, echte Syscalls und Crypto-CPU-Erkennung; kein Cross-Linker oder QEMU erforderlich. |
| Cross auf x86_64 | Möglich mit Rust-Target, aarch64-Linker und festem Sysroot. Zusätzliche Toolchain-/Supply-Chain-Komplexität. Nachgelagerte native Ausführung des exakt gehashten Binaries zwingend; Build allein reicht nicht. |
| QEMU-User-Emulation | Für zusätzliche funktionale Vorprüfungen denkbar, aber kein Ersatz für native Seccomp-/Landlock-/CPU-/Timingtests. Keine Schutzmechanismen abschalten, um Tests unter QEMU grün zu bekommen. |
| Vollsystem-VM auf ARM64 | Geeignet für Distributionskernel und native Installationsabnahme. VM/Container und Host-ISA im Bericht unterscheiden. |

GitHub listet `ubuntu-22.04-arm` und weitere native ARM64-Runner; ihre tatsächliche Verfügbarkeit
im Repository bleibt vor Phase 2 zu prüfen. `aarch64-unknown-linux-gnu` ist ein Rust-Tier-1-Ziel
mit Hostwerkzeugen. Quellen: [GitHub-Runner](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
[Rust-Plattformunterstützung](https://doc.rust-lang.org/rustc/platform-support.html).
Keinen privaten Rechner/kalipi aus #93 als Runner einbinden oder per SSH kontaktieren.
Falls 22.04-ARM nicht nutzbar ist: Phase anhalten und gleichwertige Basis vorschlagen; nicht
stillschweigend auf eine neuere glibc wechseln oder einen Cross-Build als Laufzeitnachweis melden.

Build immer `cargo build --release --locked --target <triple>`; Standard-CPU-Basis beibehalten,
kein `target-cpu=native`, kein pauschales `+aes/+crypto`. Das erzeugte Binary vor und nach dem
Verpacken hashen. Compiler, Linker, Runner-Image-Version, Kernel, Seitengröße, libc,
Lockfile-Hash, Features und RUSTFLAGS protokollieren.

**musl-Bewertung:** statische Archive könnten die glibc-Untergrenze vermeiden und ältere
Distributionen erreichen. Rust und die untersuchten AES/POLYVAL-Backends unterstützen aarch64-musl.
Das beseitigt weder Kernel-/Sandboxanforderungen noch RAM-Bedarf. Hinzu kommen libc-/Thread-/
Syscallunterschiede, eigener Security-Updatebedarf eingebundener Bibliotheken und eine weitere
Testmatrix. Statische PIE-Binaries können andere Dynamic-Tags besitzen: Der heutige Prüfer darf
dafür nicht pauschal gelockert werden. Vor einer eigenen musl-Freigabe wären vergleichbare
Härtungsnachweise, ABI-/Loaderkontrolle und native Positiv-/Negativtests nötig.
Für Debian wird dynamisches GNU/glibc bevorzugt; musl weder voraussetzen noch jetzt bauen.

## 5. Debian-Paketvertrag

### 5.1 Ein Paketierer, zwei Architekturen

Vorschlag: `scripts/release_deb.py` als kleiner Debian-Adapter mit Tests in
`scripts/test_release_deb.py`; statische Metadaten/Lizenzinventar unter `packaging/debian/`.
Vorhandene `release_package.EXTRA_FILES`, Zeitstempelkonventionen und SBOM-Helfer übernehmen,
statt Archivlogik zu kopieren. Kein `cargo-deb`/fpm als zusätzliche Toolabhängigkeit nötig.
`dpkg-deb` erzeugt das Debian-Format; nicht selbst ar/control.tar/data.tar implementieren.
Ein- und Ausgabepfade, Version und Ziel strikt validieren; keine Shell-Auswertung von Metadaten,
keine Symlinks/Traversal aus Staging-Eingaben, kein unkontrolliertes Überschreiben vorhandener Pakete.

| Rust-Ziel | Debian `Architecture` | ELF `Machine` | Paketname |
|---|---|---|---|
| `x86_64-unknown-linux-gnu` | `amd64` | AMD x86-64 | `pqkeep_<Debian-Version>_amd64.deb` |
| `aarch64-unknown-linux-gnu` | `arm64` | AArch64 | `pqkeep_<Debian-Version>_arm64.deb` |

Mapping explizit erlauben und gegen Binary **und** native Testumgebung prüfen; keine Ableitung
allein aus dem Dateinamen oder `uname`. Nicht `all`, `aarch64` oder `armhf` ins Control-Feld schreiben.
Beide Pakete heißen `pqkeep`; keine parallele Installation beider Architekturen in denselben
`/usr/bin/pqkeep`-Pfad versprechen. `Multi-Arch: same` ist dafür ungeeignet und bleibt weg.

### 5.2 Inhalt und Rechte

| Installierter Pfad | Herkunft / Modus |
|---|---|
| `/usr/bin/pqkeep` | exakt geprüftes GNU-Release-Binary, 0755 |
| `/usr/share/man/man1/pqkeep.1.gz` | `pqkeep --lang en man`, deterministisch komprimiert, 0644 |
| `/usr/share/man/de/man1/pqkeep.1.gz` | `pqkeep --lang de man`, ebenso 0644 |
| `/usr/share/bash-completion/completions/pqkeep` | `pqkeep --lang en completions bash`, 0644 |
| `/usr/share/zsh/vendor-completions/_pqkeep` | vorhandener zsh-Generator, 0644 |
| `/usr/share/fish/vendor_completions.d/pqkeep.fish` | vorhandener fish-Generator, 0644 |
| `/usr/share/doc/pqkeep/copyright` | unkomprimiert, DEP-5-artiges vollständiges Lizenz-/Copyrightinventar, 0644 |
| `/usr/share/doc/pqkeep/LICENSE`, `NOTICE`, `LICENSES-wordlists.md` | vorhandene Projekt-/Wortlistentexte, 0644 |
| `/usr/share/doc/pqkeep/README.md.gz`, `changelog.gz`, `changelog.Debian.gz` | DE/EN-Anleitung und Upstream-/Paketrevision nachvollziehbar, 0644 |

Verzeichnisse 0755, alle Einträge root:root **im Paket**, kein setuid/setgid und keine Capabilities.
Staging und Paketbau unprivilegiert mit `dpkg-deb --root-owner-group --build`; keine chown-/sudo-
Aktion auf dem Entwicklungsrechner. XZ mit festgelegten Parametern für breite dpkg-Kompatibilität,
gzip ohne Originalname/Zeitstempel für Manpages; `SOURCE_DATE_EPOCH` auf alle Metadaten anwenden.
Manpages/Completions auf dem passenden nativen Runner aus genau dem zu verpackenden Binary
erzeugen; dadurch gibt es keinen zweiten CLI-Parser und kein Ausführen fremder ISA beim Packen.

Keine Maintainerskripte, systemd-Units, Cronjobs, Benutzeranlage, Netzwerkaufrufe, Integration
ins Benutzerprofil, Conffiles, Schlüssel oder Token im Paket. Keine automatischen Aufrufe von
`pqkeep integrate install/remove`. Bereits vom Nutzer erzeugte Kontextmenüs bleiben Benutzerdaten;
ein eventuell verwaister Menüeintrag nach Deinstallation ist zu dokumentieren.
Shells, Desktop und API-Dienst sind keine Pflichtinstallation. CLI bleibt ohne diese nutzbar.
`DEBIAN/md5sums` für die installierten regulären Dateien ermöglicht Paketbestandsprüfungen;
dies ersetzt ausdrücklich nicht SHA-256/Sigstore zur Authentizitätsprüfung.

### 5.3 Metadaten, Abhängigkeiten und Lizenzen

Control: `Package`, `Version`, `Architecture`, `Maintainer`, `Description`, `Section: utils`,
`Priority: optional`, `Homepage`, `Installed-Size`, berechnete `Depends`; kein erfundener
Maintainer-Kontakt. Vor Phase 3 öffentlich vorgesehene Maintainer-Identität bestätigen.
Englische Control-Beschreibung nach Debian-Konvention; Anleitung und Manpage Deutsch/Englisch.

`dpkg-shlibdeps -O -e<staging>/usr/bin/pqkeep` in der passenden Architektur-/Distributionsumgebung
mit deren symbols/shlibs-Daten ausführen, Ergebnis validieren und ins Control übernehmen.
Nicht bloß `libc6 (>= 2.35)` raten: tatsächliche `DT_NEEDED`-/Symbolanforderungen prüfen,
einschließlich z. B. `libgcc-s1`, falls benötigt. Keine Abhängigkeiten unterdrücken.
Ubuntu-Paketversionen nicht blind für Debian übernehmen: Auf allen vorgesehenen Systemen
Paketauflösung prüfen; bei inkompatiblen Ergebnissen explizite Distributionsvarianten planen.
Die vorhandene glibc-2.35-Aussage ist am konkreten Binary nachzuweisen.

Cargo-SBOM ersetzt keine Lizenztexte: statisch eingebundene Rust-Crates und Wortlisten anhand
Lockfile/Features inventarisieren; erforderliche Hinweise vollständig mitliefern. Bestehende
`NOTICE`- und MIT/BSD/CC-BY-Wortlistentexte erhalten; keine Lizenz-Ausnahme still erweitern.
Lintian ohne pauschale Overrides, Control-/Pfad-/Rechteprüfung und Review des Lizenzinventars
sind Abnahmebedingungen. Ein auf GitHub angebotenes `.deb` ist keine Aufnahme ins Debian-Archiv;
Debian-Sourcepakete und deren vollständige Distributionsintegration sind nicht beauftragt.

Referenzen: [Control und Version](https://www.debian.org/doc/debian-policy/ch-controlfields.html),
[Dateien und Rechte](https://www.debian.org/doc/debian-policy/ch-files.html),
[Manpages und Copyright](https://www.debian.org/doc/debian-policy/ch-docs.html),
[dpkg-shlibdeps](https://manpages.debian.org/bookworm/dpkg-dev/dpkg-shlibdeps.1.en.html),
[dpkg-deb](https://manpages.debian.org/bookworm/dpkg/dpkg-deb.1.en.html).

### 5.4 Versionen und Reproduzierbarkeit

Upstream-Version bleibt in `Cargo.toml`, Lockfile synchron; signierter Tag muss weiter passen.
Debian-Revision wird separat versioniert. Beispiele des vorgeschlagenen Mappings:

| Upstream / Zweck | Debian-Version |
|---|---|
| `0.1.0-beta.1`, Paketrevision 1 | `0.1.0~beta.1-1` |
| gleiche Upstream-Version, Packagingkorrektur | `0.1.0~beta.1-2` |
| finale `0.1.0` | `0.1.0-1` |
| PR-/Testkandidat der Beta | z. B. `0.1.0~beta.1-1~ci.<UTC-Zeit>.<SHA>` |

Prerelease-`~` stellt die Sortierung vor der finalen Version sicher. Versionsgrammatik
und Reihenfolge mit `dpkg --compare-versions` testen; unerwartete SemVer-/Build-Metadaten
ablehnen oder erst ausdrücklich definieren. Ein Git-Hash allein ist keine zeitliche Sortierung.
Die UTC-Zeit im CI-Versionssuffix wird aus der Commitzeit abgeleitet, nicht aus der Laufzeit
des Packagingjobs; identische Eingaben behalten dadurch identische Versionsmetadaten.
Für CI keine existierende Release-Version als neu freigegebenes Paket ausgeben.

Bereits vorhanden: Cargo.lock, `--locked`, Pfadremapping, Commitzeit als Epoch, feste
Archivreihenfolge/-rechte/-besitzer sowie deterministische SBOM-UUID/Zeit.
Noch nicht bewiesen: bitgleiche Rust-Binaries über unabhängige Builds, vollständige SBOM-
Deterministik, Debian-Pakete. Bewegliches `stable`, Runner-Updates, Linker, Buildpfade und
Kompressorversionen bleiben Einflussgrößen; `--locked` fixiert nicht die Toolchain.

In Abstimmung mit #154: für einen Release exakte Rust-/Linker-/Packagingversionen und
Buildumgebung erfassen und verbindlich festlegen. Ein Toolchain-Pin wird separat im passenden
PR geprüft, nicht in Phase 1 vorgenommen. Zwei frische Build-/Staging-Verzeichnisse mit
gleichem Commit/Lockfile/Features/Werkzeugen/Epoch erzeugen; Hashes von Binary, Archiv, `.deb`
und SBOM separat vergleichen. Unterschiede untersuchen und dokumentieren, nicht als
„reproduzierbar“ abnehmen. Signaturen/Attestationen enthalten Laufzeitidentitäten und werden
nicht auf Bytegleichheit geprüft. Für `.deb` muss mindestens das erneute Verpacken identischer
Eingaben bitgleich sein; vollständige Buildreproduktion ist als eigener Nachweis auszuweisen.

## 6. Test- und Sicherheitsvertrag

### 6.1 Native Plattformabnahme

Vorgeschlagene verbindliche Paketmatrix: Debian 12 (LTS), Debian 13 sowie Ubuntu 22.04,
24.04 und 26.04 LTS, jeweils amd64/arm64. Buildbasis bleibt 22.04.
Das ist der zu genehmigende Testumfang, keine bereits erfüllte Kompatibilitätszusage.
Andere Distributionen, Mint, Raspberry Pi OS/Kali und armhf erhalten keinen neuen Nachweis
allein aufgrund einer ähnlichen libc. Quellen zum Distributionsstand:
[Debian 12](https://www.debian.org/releases/bookworm/),
[Debian 13](https://www.debian.org/releases/trixie/),
[Ubuntu-Releases](https://ubuntu.com/project/docs/release-team/list-of-releases/).

Jede Kombination: isoliertes Testsystem, frischer Paketstatus, normaler Benutzer für PQKeep,
Paketverwaltung nur im ausdrücklich freigegebenen Testsystem. Native Container prüfen reales
ISA-/Userspaceverhalten, teilen aber den Hostkernel; sie sind kein Nachweis für den Kernel der
Zieldistribution. Je Architektur zusätzlich native VM-/Hosttests mit passendem Distributionskernel
für Seccomp, Landlock und memlock. ARM64 mit 4-KiB-Seiten und mindestens eine 64-KiB-Umgebung
für Seitengrößenregression einplanen; fehlende Umgebung bleibt offene Abnahmebedingung.

| Testgruppe | Geforderte Aussage |
|---|---|
| Erstinstallation | Paketabhängigkeiten auflösbar; `/usr/bin/pqkeep` ausführbar; DE/EN-Hilfe, man und Completions vorhanden |
| Upgrade / Reinstall | Vorherige Paketrevision → Kandidat; gleiche Version erneut installieren; Dateien/Metadaten korrekt, CLI nutzbar |
| Remove / Purge | Nur paketverwaltete Dateien entfernen; keine Schlüssel, Container, Token, Kontexteinträge oder Benutzerkonfiguration löschen |
| Abhängigkeiten | Fehlende Abhängigkeit und falsche Architektur werden erkannt; kein `--force-depends`/`--force-architecture` |
| Rechte | root:root im Paket, 0755/0644, kein SUID/SGID/capability, keine gruppen-/weltbeschreibbaren Installationsdateien |
| CLI/Krypto | vorhandener Release-Smoke gegen **installiertes** Binary; KATs/Roundtrips/Manipulationen, Batch-/Fehlercodes und Signaturen aus vorhandenen Tests |
| Datenbestand | Synthetische Benutzerdaten vor/nach jeder Operation mit Hash, Modus und Eigentümer vergleichen; alte Schlüssel/Archive danach lesen/entschlüsseln |
| Abbruch/Fehler | Beschädigtes Paket, Dateikonflikt, Platzmangel und unterbrochener dpkg-Lauf in wegwerfbarer VM; Paketstatus und Daten prüfen, Wiederherstellung nachweisen |
| Downgrade | Nur explizit mit authentischem Vorgängerpaket, verfügbaren Abhängigkeiten und bestätigter Formatkompatibilität; Hash-/Datenvergleich danach |

Noch kein altes `.deb` veröffentlicht: Upgrade/Downgrade zunächst mit zwei gekennzeichneten
Testrevisionen derselben Upstream-Basis testen. Das ist kein historischer Release-Upgrade-Nachweis.
Später zusätzlich echte Vorgängerversionen verwenden. Rollback unsicherer/verwundbarer Versionen
ist keine pauschale Empfehlung; kompatibler Vorwärtsfix kann erforderlich sein.

### 6.2 Sicherheitsrisiken und Sperrkriterien

| Risiko | Maßnahme / Freigabesperre |
|---|---|
| Cross-Artefakt nur kompiliert | Ohne echte ARM64-Ausführung keine Phase-2/4-Abnahme |
| Andere libc/Syscalls/Seiten | Native Tests, ELF-ABIkontrolle, Seitengrößentest; kein `--no-sandbox`, keine gelockerten Filter |
| Erzwungene CPU-Erweiterungen | Generischer CPU-Target; Hardware-/Softwarepfade auf geeigneter ARM-Hardware bzw. getrennten Testbuilds prüfen |
| Argon2-OOM oder Timeouts | Ressourcen protokollieren, Testparallelität begrenzen statt Sicherheitsparameter senken |
| Verpackung verändert Binary | Hash vor/nach Extraktion identisch; Härtung erneut prüfen, kein nachträgliches Patchen/Strippen |
| Paket verändert Benutzerzustand | Keine Maintainerskripte/Dienste; Dateninvarianten einschließlich Purge-/Abbruchfällen |
| Unvollständige Artefaktabsicherung | Explizite erwartete Artefaktmenge, jede Nutzdatei mit Prüfsumme, Provenance, passender SBOM-Attestation und Sigstore-Bundle |
| SBOM falsch zugeordnet | Ziel, Features, Commit, Binaryhash und Paketabhängigkeiten abgleichen; negative Vertauschungstests |
| Privilegierter PR-Code | PRs weiter nur lesend; keine OIDC-/Schreibrechte oder neue Drittanbieteractions ohne begründete Freigabe |
| Fehlende Lizenztexte | Cargo-/Wortlisteninventar und Paketinhalt prüfen; SBOM allein genügt nicht |
| Veraltete Vertrauensbasis | Signaturen prüfen **vor** Installation; signierte Prüfsummen bieten allein keinen Schutz gegen das Wiederanbieten einer alten gültigen Version (#143) |

Keine neuen globalen Security-Claims: FIPS-140-Validierung, externes Audit, konstante Laufzeit
auf jeder ARM-CPU und vollständiger Geheimnisschutz sind weiterhin nicht nachgewiesen.
Neue benötigte System-/Kerneländerungen, Installationen oder Rechteausweitungen erfordern
konkrete Freigaben. Ein Testfehler wird untersucht, nicht durch Auslassen „behoben“.

## 7. Sechs Phasen und jeweilige Pull Requests

### Phase 1 – Analyse und Architektur (dieses Dokument)

- Änderung: ausschließlich Plan und lokaler Projektnachweis. Keine Implementierung oder CI-Änderung.
- Prüfung: vorhandene Skriptprüfungen, lokale Rust-Baseline, Quellen-/Issue-/PR-Abgleich;
  tatsächliche Ergebnisse in Abschnitt 9.
- Abnahme: Architekturentscheidungen, Paket-/Testumfang, Grenzen und Rückweg vom Nutzer geprüft.
- Rückbau: neue Plandatei nach Sicherung gezielt zurücknehmen; Projektnachweis aus Sicherung
  oder anhand seines isolierten Zusatzes zurücksetzen. Kein laufender Dienst betroffen.
- PR: noch keiner; ein Dokumentations-PR nur nach entsprechendem Auftrag.

### Phase 2 – Linux ARM64

- Eigener PR: native ARM64-Zeile in Release-Buildmatrix, reguläre ARM-CI für Tests/Clippy;
  `check_binary.py` unverändert verwenden, separate ELF-Architektur-/ABIprüfung ergänzen.
  Seitenannahme in `tests/hardening_memlock.rs` bei gleicher Prüfstärke korrigieren.
- Voraussichtliche Dateien: `.github/workflows/{release,ci}.yml`,
  `scripts/test_release_scripts.py`, ggf. kleiner gemeinsamer Artefaktprüfer mit Negativtests,
  `tests/hardening_memlock.rs`, Plattform-/Plan-Dokumentation.
- Vorhandene Archive/SBOM/Smoke wiederverwenden, ARM64-Namen/Inhalt/Determinismus testen.
  Upload des ARM-Kandidaten unter einem Namen **außerhalb `dist-*`**, damit Phase 6 nicht
  vorweggenommen wird. AMD64/Windows behalten ihre bisherigen Namen und Publishpfade.
- Tests: `cargo build --release --locked --target aarch64-unknown-linux-gnu`, Härtung,
  `readelf -h/-lW/-d/--version-info`, echter Smoke, vollständige native Rust-Tests,
  Crypto-KATs, Sandbox-Negativtests, Clippy mit/ohne API, bestehende Plattformen grün.
  Runner `uname -m`, ELF-Machine und Ausführungsprotokoll gemeinsam sichern.
- Abnahme: ARM64-Binary läuft und wird korrekt verpackt, SBOM vorhanden; keine Verschlechterung
  auf AMD64/Windows. Fehlende native Beweise verhindern die Freigabe zu Phase 3.
- Risiko/Rückbau: Runner-/Kernelabweichungen; nur diesen PR revertieren, Kandidaten nicht
  freigeben. Keine Benutzerdateien oder veröffentlichten Assets ändern.

### Phase 3 – Debian AMD64

- Eigener PR: gemeinsamer Debian-Adapter, Metadaten/Lizenzinventar, native Manpage-/
  Completion-Erzeugung, Architektur-/Versions-/Pfad-/Rechteprüfungen.
- Dateien: `scripts/release_deb.py`, `scripts/test_release_deb.py`, `packaging/debian/*`,
  minimaler Kandidaten-Build im bestehenden Workflow, `docs/INSTALL.md` DE/EN.
  Benötigte Build-/Testwerkzeuge und Installationsorte vor Nutzung konkret freigeben lassen.
- Tests: zweimaliges Packen, `dpkg-deb --info/--contents/--field`, Extraktion und Binaryhash,
  `readelf`, `dpkg-shlibdeps`, Lintian, native Installation/Smoke/Entfernung in Testsystem.
  Negative Tests für fehlende Dateien, falsche Architektur, unsichere Rechte und ungültige Version.
- Abnahme: installiert/nutzbar/entfernbar; Abhängigkeiten korrekt; Benutzerdaten unverändert.
- Risiko/Rückbau: falsche Metadaten/Dateirechte; PR revertieren, Test-VM auf Snapshot bzw.
  vorheriges Testpaket zurücksetzen. Keine Installation auf dem Arbeitsrechner.

### Phase 4 – Debian ARM64

- Eigener PR: dasselbe Skript mit `arm64` und nativem Phase-2-Binary aufrufen; nur Matrix,
  parametrisierte Tests und Plattformdoku erweitern. Keine Skriptkopie und kein getrenntes
  architekturspezifisches Control-Template.
- Tests: Paket-Control `arm64`, ELF AArch64, Binaryhash, abhängige Bibliotheken, Härtung,
  native ARM64-Installation/Smoke/Entfernung; falsches AMD64-Binary muss abgewiesen werden.
- Abnahme: ARM64-Paket funktioniert eigenständig auf ARM64 und benötigt kein AMD64-Paket.
- Risiko/Rückbau: falsch etikettierte Artefakte; Phase-4-PR revertieren, ARM-Kandidat bleibt
  unveröffentlicht. Phase-3-Logik und AMD64-Nachweise bleiben erhalten.

### Phase 5 – Installations- und Regressionstests

- Eigener PR: gemeinsame Paket-Lifecycle-Tests und Distributionsmatrix, kein neuer Paketierer.
  Vorgeschlagene Dateien: `scripts/test_deb_lifecycle.py`, passende CI-Testdefinition,
  `docs/issue-93-testmatrix.md` und aktualisierte Installationsdoku.
- Alle Fälle aus Abschnitt 6 pro Zielsystem; native Ausführung, native Container,
  Vollsystememulation und ausschließlich statische Prüfung ausdrücklich separat kennzeichnen.
- Bestehende fmt/Clippy/Rust/MSRV/deny/Gitleaks/CodeQL/Härtung unverändert erforderlich.
  Fixture-Schlüssel nur zur Laufzeit, keine echten Benutzerdaten in CI oder Artefakten.
- Abnahme: vollständige Matrix mit Befehlen, Versionen, Exit-Codes, Daten-/Rechtevergleich,
  dokumentierter Fehlerwiederherstellung; offene Pflichtfälle blockieren Phase 6.
- Risiko/Rückbau: unterbrochene Paketverwaltung nur in wegwerfbaren Testsystemen; Snapshot
  wiederherstellen oder freigegebenes Vorgängerpaket installieren. PR-Revert nimmt nur Tests zurück.

### Phase 6 – Release und Sicherheitsabschluss

- Eigener PR: neue Kandidaten kontrolliert in die bestehende Artefaktmenge übernehmen;
  `.deb` in Provenance, Checksummen, Sigstore und alle Verifikationsschleifen aufnehmen.
  ARM-Archiv sowie beide `.deb` erhalten explizite SBOM-Zuordnungen.
- Dateien: `.github/workflows/release.yml`, gezielte Erweiterung `release_sbom.py` plus Tests,
  bei Bedarf gemeinsames Artefaktmanifest mit Prüfer, `README.md`, `docs/{RELEASE,INSTALL,CHECKLIST}.md`,
  `docs/releases/v<freizugebende-Version>.md` DE/EN und Versions-/Changelogdateien.
- Paket-SBOM aus derselben target-/featurebezogenen Cargo-SBOM ableiten; Paketidentität,
  Debian-Version/-Architektur, Binary-Hash, paketierte Dokumentation und tatsächliche externe
  Laufzeitabhängigkeiten kennzeichnen. Keine Distrobibliotheken als mitgelieferte Dateien ausgeben.
  Eindeutige UUID/Referenz für Paket statt ungekennzeichnetem Kopieren der Archiv-SBOM.
- Erwartete fünf Nutzartefakte: Linux-AMD64-Archiv, Linux-ARM64-Archiv, Windows-ZIP,
  Debian-amd64 und Debian-arm64. Jedes mit SHA-256, Build-Provenance, zugehöriger
  CycloneDX-Attestation und Sigstore-Bundle; SBOM-Dateien ebenfalls in signierten SHA256SUMS.
  Manifest vollständig gegen erzeugte Dateien abgleichen; fehlende/zusätzliche/verdoppelte
  oder falsch zugeordnete Dateien lassen den Job scheitern.
- Bestehende GitHub-Actions verwenden; keine zusätzlichen Permissions. Trigger-Pfadfilter
  müssen neue Paketierungs-/Test-/Metadatendateien erfassen. PR-Läufe bleiben ohne Signieren.
  Kein Tagpush, Dispatch, Signieren oder Draft-Erstellen ohne dafür geltenden ausdrücklichen Auftrag.
- Tests: zwei unabhängige Builds gemäß Abschnitt 5.4; Artefakt- und Negativprüfungen;
  bei separat genehmigtem Signierlauf `sha256sum -c`, `gh attestation verify` (Build und
  CycloneDX, Repo/Workflow/Ref/Commit passend) sowie `cosign verify-blob` (exakte
  Workflowidentität, Issuer `https://token.actions.githubusercontent.com`) auf **alle** Nutzartefakte.
  Vertauschte SBOM, manipuliertes Paket, falscher Signer/Issuer und fehlende Signatur ablehnen.
- Abnahme: Review des gesamten Release-Bundles, unveränderte manuelle Environment-Freigabe,
  grüner Verifyjob, DE/EN-Plattformmatrix und Installationsanleitung.
  Ein grüner Workflow veröffentlicht nichts: Entwurf und abschließende Nutzerfreigabe bleiben Pflicht.
- Risiko/Rückbau: Signier-/Transparenznachweise sind nicht löschbar zurückzudrehen.
  Bei Fehlern nicht veröffentlichen; Workflow-PR revertieren bzw. Vorwärtsfix. Veröffentlichte
  Versionen/Tags niemals still ersetzen, sondern nach Freigabe korrigierte Version herausgeben.

## 8. Sicherung und allgemeiner Rückweg

Vor lokalen Dokumentationsänderungen gesichert:
`/home/codex-agent/projects/pqkeep/backups/issue-93-20261110T015437Z/`.
Das geschützte Verzeichnis (0700) liegt außerhalb aller Repository-Arbeitsbäume und enthält
`PROJECT.md` mit ursprünglichen Metadaten, ein vollständiges `git archive` der analysierten
Basis und `manifest.json` mit SHA-256 und dem vermerkten Nichtvorhandensein der neuen Plandatei.
Sicherung wurde geöffnet; zentrale Dateien byteweise mit der Basis verglichen.
Es handelt sich um eine lokale Arbeitssicherung, nicht um ein produktives Deploymentbackup.

Arbeitsbaum: `/home/codex-agent/projects/pqkeep/issue-93`, Branch `docs/issue-93-plan`.
Der ältere Arbeitsbaum `repo` mit uncommittierten U4-2-Änderungen und `issue-39` bleiben unberührt.
Nur `origin/main` wurde lesend von GitHub aktualisiert; kein Commit, Push, PR, Tag oder Release.

Rückweg Phase 1: zunächst Diff und Sicherungsmanifest prüfen; bei späteren Änderungen diese
separat sichern. Dann ausschließlich die neue Plan-Datei entfernen und den Issue-93-Zusatz
in `PROJECT.md` zurücknehmen; sofern seitdem keine anderen Änderungen vorliegen, kann dessen
gesicherte Fassung mit ursprünglichem Modus wiederhergestellt werden. Löschung erst auf Auftrag.
Keine pauschalen Reset-/Clean-Befehle. Branch/Worktree können als Nachweis bestehen bleiben.

Vor späteren freigegebenen Dateiänderungen: datierte Sicherung der konkret betroffenen Dateien
einschließlich Rechten und Hashmanifest außerhalb des Arbeitsbaums, Lesbarkeit und Restoreprobe.
Vor Testinstallationen VM-Snapshot und synthetischen Datenbestand sichern. Vor produktiven
Installationen separat Zielsystem, Paketversion/Hash, Dateien/Dienste, Backup und Rückweg freigeben.
Ein PR-Revert stellt Quelltext wieder her, deinstalliert aber kein bereits installiertes Paket.
Bei Paket-Rollback authentisches Vorgängerpaket verifizieren, Abhängigkeiten prüfen, expliziten
Downgrade ausführen und Daten/CLI prüfen; bei Unverträglichkeit stoppen statt Benutzerdateien
zurückzuschreiben. Bisherige Archive/Schlüssel bleiben unangetastet.

## 9. Phase-1-Prüfbericht und Freigabe

Lokale Umgebung: Linux Mint 22.1, x86_64, Rust/Cargo 1.99.1, LLVM 23.1.1.
Installierte Rust-Targets: x86_64 Linux GNU und x86_64 Windows GNU; kein ARM64-Target.
Vorhanden: Python 3, readelf, dpkg-deb, dpkg-shlibdeps, cargo-deny. Lintian nicht gefunden.
Keine Werkzeuge/Targets installiert, keine Dienste oder Systemkonfiguration verändert.

Bereits tatsächlich ausgeführt und bestanden:

- `python3 -B scripts/test_release_scripts.py`: fünf Testgruppen; darunter zweimaliges
  Verpacken pro vorhandener Architektur mit künstlichen Binaries, SBOM und Smoke-Trockenlauf.
- `python3 -B scripts/test_check_binary.py`: zwei Testgruppen mit synthetischen PE-/ELF-Daten.
- `bash scripts/check_limits.sh`: bestanden.
- `cargo fmt --all --check`: bestanden.
- `cargo metadata --offline --locked --no-deps --format-version 1`: bestanden.
- `cargo tree --offline --locked --target aarch64-unknown-linux-gnu --edges normal --depth 1`:
  aufgelöst; reine Abhängigkeitsanalyse, keine ARM-Kompilierung.

Weitere tatsächlich ausgeführte Prüfungen (alle im isolierten Arbeitsbaum, Linux x86_64):

| Befehl | Ergebnis / Protokoll |
|---|---|
| `cargo clippy --offline --all-targets --locked -- -D warnings` | Exit 0; `baseline-1.log` |
| `cargo clippy --offline --all-targets --no-default-features --locked -- -D warnings` | Exit 0; `baseline-2.log` |
| `cargo test --offline --locked` | Exit 0; 402 Tests einschließlich 3 Doc-Tests, 0 fehlgeschlagen, 0 vom Harness als ignoriert gezählt; `baseline-3.log` |
| `cargo deny --offline check` | Erster Versuch Exit 1: Sandbox verbot Cache-Sperrdatei. Nach Freigabe außerhalb der Sandbox wiederholt: Exit 0; Advisories, Bans, Lizenzen und Quellen bestanden, bekannte Warnung zu `syn` 2/3; `baseline-4.log`, `baseline-4-retry.log` |
| `bash scripts/test_check_limits.sh` | Exit 0; `baseline-5.log` |
| `python3 -B -m unittest discover -s scripts -p 'test_v2_*.py' -v` | Exit 0; 10 Tests, `baseline-6.log` |
| `dpkg --compare-versions '0.1.0~beta.1-1~ci.20261110.569c233' lt '0.1.0~beta.1-1'` | Exit 0 |
| `dpkg --compare-versions '0.1.0~beta.1-1' lt '0.1.0~beta.1-2'` | Exit 0 |
| `dpkg --compare-versions '0.1.0~beta.1-2' lt '0.1.0-1'` | Exit 0 |
| `git diff --check`, `git status --short`, `git diff --name-only` | Keine Änderungen an getrackten Repository-Dateien; allein die neue Plandatei ist unversioniert |

Zusätzliche lokale Dokumentprüfung per Python: sechs Phasen vorhanden, keine nachgestellten
Leerzeichen, ausschließlich erwartete neue Datei, alter `PROJECT.md`-Inhalt vollständig erhalten,
Hashmanifest der Sicherung stimmt. Die Versionsvergleiche prüfen Beispiele des Plans, noch
keine implementierte Versionsabbildung. Das Offline-Audit nutzt den vorhandenen Cache und belegt
keine aktuelle Online-Abfrage der Advisory-Datenbank. Die Rust-Harness-Zahl erfasst keine
internen bedingten Rücksprünge der Sandbox-/memlock-Tests als „ignored“; daraus keinen
vollständigen Landlock- oder ARM64-Nachweis ableiten.

Protokolle: `/home/codex-agent/projects/pqkeep/analysis/issue-93-20261110/`.
Kein ARM64-Build/-Smoke, keine Debian-Paketinstallation, kein musl-Build und kein Release-
Signierlauf in Phase 1. Ebenso kein neuer Release-Build und keine Prüfung eines echten
Release-Binaries, keine Windows-/MSRV-Ausführung und keine lokalen Gitleaks-/CodeQL-Läufe.
Die geplanten Befehle in den Phasen 2–6 sind noch nicht ausgeführt.

Ergebnis: Analyse und Dokumentation abgeschlossen; zwei Dokumentationsdateien betroffen
(dieser neue Plan und ein Zusatz in der lokalen `PROJECT.md`). Keine Implementierung,
kein PR-Link, weil kein PR beauftragt oder erstellt wurde. Sicherung/Rückweg siehe Abschnitt 8.

**Freigabeempfehlung:** Plan prüfen und anschließend ausschließlich Phase 2 freigeben:
native Ubuntu-22.04-ARM-Basis, unveränderte Crypto-/CLI-Semantik, gleich starke Härtungsprüfungen,
Seitenkorrektur im Test, CI-Kandidaten ohne Releaseaufnahme. Offene Voraussetzungen:
Runnerzugang und Ressourcen, native ARM64-/Seitengrößenabnahme. Für Phase 3 zusätzlich
Maintainer-Metadaten und freigegebene isolierte Installationstestumgebung klären.
Keine weitere Phase ohne neue ausdrückliche Freigabe beginnen.

## English: scope and approval summary

This is a planning document for issue #93, based on commit
`569c233afadb2b2b20553e0832c555023d35f055`. No implementation, system installation,
GitHub write, release dispatch, signing or publication has been performed.

The proposal uses a native Ubuntu 22.04 ARM64 runner, preserves the existing AMD64/Windows
builds, and reuses one Debian packaging implementation for both architectures. Existing CLI
commands generate English/German manpages and shell completions. Packages install
`/usr/bin/pqkeep` and documentation only; they do not start services or modify user keys/data.
Cross-compilation alone is not a runtime test. musl is evaluated but deferred to a separate plan.

The six phases are analysis, native Linux ARM64, Debian AMD64, Debian ARM64, installation and
regression tests, and release/security integration. Each implementation step requires its own PR
and explicit approval. New artifacts remain unsigned CI candidates until release integration.
Native, emulated and static results must be reported separately; reproducible packaging is not
proof of reproducible compilation. An existing memory-lock test assumes 4-KiB pages and needs
a semantics-preserving test correction for larger ARM64 pages.

The existing manual release environment and draft process remain mandatory. Every new archive
or Debian package must have checksums, matching SBOM attestation, build provenance and Sigstore
verification before approval for publication. No cryptographic algorithms, file formats, key
management or CLI semantics may change. User data must survive remove/purge, failure and rollback.
The next permitted action is review of this plan; phase 2 starts only after explicit approval.
