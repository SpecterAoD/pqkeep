# Issue #93 – Phase 2: natives Linux ARM64

Stand: 10.11.2026. Phase 2 ausdrücklich vom Nutzer freigegeben.
Basis: `569c233afadb2b2b20553e0832c555023d35f055`.
Plan: [Architektur und sechs Phasen](issue-93-implementierungsplan.md).
Umsetzung: [PR #158](https://github.com/SpecterAoD/pqkeep/pull/158), eigener Phase-2-PR.
Die folgenden Laufzeitnachweise gehören zum Implementierungscommit
`80c3c83b5e0bab3565f0af3e337a6e6e02263526` und seinem GitHub-PR-Mergecommit
`86eb574` (Buildversion `0.1.0-beta.1-dev.86eb574`). Nachfolgende Ergänzungen betreffen
Umgebungsprotokollierung und diesen Bericht; der aktuelle Checkstatus steht im PR.

## Änderungen und Grenzen

- `.github/workflows/ci.yml`: vollständige Testmatrix zusätzlich auf `ubuntu-22.04-arm`,
  mit Host-, Seitengrößen- und Toolchain-Nachweis; Tests des neuen ELF-Prüfers.
- `.github/workflows/release.yml`: native ARM64-Zeile, bestehender Release-Build mit
  `cargo build --release --locked --target`, unveränderte Härtungs- und echte Smoke-Tests,
  vorhandener Paketierer und CycloneDX-SBOM. Die Linux-Ziele prüfen zusätzlich ELF-Ziel,
  GNU-Loader, glibc-Anforderungen bis 2.35 und Identität des Archiv-Binaries.
  Eine Prüfsumme schützt `Cargo.lock` vor unbemerkter Änderung durch die SBOM-Erzeugung.
- `scripts/release_elf.py` und `scripts/test_release_elf.py`: gemeinsame ELF-/ABI- und
  Archivprüfung für beide Linux-Ziele, einschließlich negativer Tests. `readelf` wird aus
  dem bestehenden Härtungsskript wiederverwendet; keine neue Abhängigkeit.
- `scripts/test_release_scripts.py`: ARM64-Archiv, reproduzierbarer Paketinhalt und
  architekturabhängige SBOM-Identität in den bestehenden Tests.
- `tests/hardening_memlock.rs`: drei tatsächliche Speicherseiten statt fest angenommener
  4096-Byte-Seiten. Die geforderte Sperrmenge bleibt mindestens drei Seiten.
- `docs/RELEASE.md`: deutsche und englische Beschreibung des ARM64-CI-Kandidaten.
  Plan und dieser Bericht dokumentieren Umsetzung, Abnahme und Grenzen.

Keine Änderungen an Produktions-Rustcode, Kryptografie, Formaten, CLI, Schlüsseln,
Cargo-Abhängigkeiten oder bestehenden Berechtigungen. Linux AMD64 und beide Windows-Binaries
bleiben in der Matrix. Die neuen Prüfschritte ergänzen die vorhandenen Sicherheitsprüfungen.

`candidate-aarch64-unknown-linux-gnu` wird nicht vom bestehenden `dist-*`-Download des
Signierjobs aufgenommen. ARM64-Archiv und SBOM werden als CI-Artefakte geprüft, aber erst in
Phase 6 nach Freigabe in Attestationen, Signaturen und Release-Verifikation aufgenommen.
Der PR erzeugt keinen Release, keine Attestation und keinen Sigstore-Eintrag.

## Prüfungen

Lokal auf Linux x86_64 ausgeführt und bestanden:

```sh
python3 -m unittest discover -s scripts -p 'test_release_elf.py' -v
python3 scripts/test_release_scripts.py
python3 scripts/test_check_binary.py
bash scripts/check_limits.sh
cargo fmt --all --check
cargo clippy --offline --all-targets --locked -- -D warnings
cargo clippy --offline --all-targets --no-default-features --locked -- -D warnings
cargo test --offline --locked --test hardening_memlock
```

Der ELF-Prüfer hat acht Tests; der Paket-/SBOM-/Smoke-Skripttest fünf Testgruppen.
Der dortige Smoke-Dry-Run ist nur ein Skripttest und kein Nachweis einer Binary-Ausführung.
Negative Tests müssen erwartungsgemäß Fehler zurückgeben; diese werden von den Tests geprüft.
Der Memlock-Test bestand mit einem ausgeführten Test, ohne übersprungene Tests.

### Native GitHub-Läufe

[Release-Lauf 42778820928](https://github.com/SpecterAoD/pqkeep/actions/runs/42778820928):
alle drei Buildjobs erfolgreich; Signieren/Veröffentlichen und Release-Verifikation beim
PR bestimmungsgemäß übersprungen. Kein Release oder Tag erstellt.

| Ziel | Tatsächliche Prüfung | Ergebnis |
|---|---|---|
| ARM64, Ubuntu 22.04.5 | Release-Build, ELF/ABI, PIE/Full RELRO/NX, echter Smoke, Archividentität, SBOM, Lockfilekontrolle | bestanden |
| AMD64, Ubuntu 22.04.5 | dieselben Linux-Prüfungen | bestanden |
| Windows x64, Server 2025 | Release-Build, ASLR/DEP/CFG für `pqkeep.exe` und `pqkeepw.exe`, echter Smoke, ZIP, SBOM, Lockfilekontrolle | bestanden |

Native ARM64-Umgebung: `ubuntu-22.04-arm`, Image `20261101.179.1`, Kernel
`6.8.0-1070-azure`, ISA `aarch64`, Seitengröße **4096 Byte**, glibc 2.35,
Rust 1.99.1, LLVM 23.1.1. Höchste benötigte glibc-Symbolversion beider Linux-Binaries:
`GLIBC_2.34`. Die Buildbasis bleibt trotzdem Ubuntu 22.04/glibc 2.35.

Tatsächlich ausgeführte Befehle im ARM64-Releasejob (Pfadverkürzungen nur hier im Text):

```sh
cargo build --release --locked --target aarch64-unknown-linux-gnu
python3 scripts/release_elf.py target/aarch64-unknown-linux-gnu/release/pqkeep aarch64-unknown-linux-gnu --native
python3 scripts/check_binary.py target/aarch64-unknown-linux-gnu/release/pqkeep
python3 scripts/release_smoke.py target/aarch64-unknown-linux-gnu/release/pqkeep
python3 scripts/release_package.py target/aarch64-unknown-linux-gnu/release/pqkeep "$VERSION" aarch64-unknown-linux-gnu dist
cargo install --locked cargo-cyclonedx --version 0.5.9
cargo cyclonedx --format json --spec-version 1.5 --target aarch64-unknown-linux-gnu --override-filename "pqkeep-$VERSION-aarch64-unknown-linux-gnu.cdx"
python3 scripts/release_sbom.py "dist/pqkeep-$VERSION-aarch64-unknown-linux-gnu.cdx.json" "$VERSION" aarch64-unknown-linux-gnu "$GITHUB_SHA"
sha256sum -c "$RUNNER_TEMP/pqkeep-lock.sha256"
python3 scripts/release_elf.py target/aarch64-unknown-linux-gnu/release/pqkeep aarch64-unknown-linux-gnu --archive "dist/pqkeep-$VERSION-aarch64-unknown-linux-gnu.tar.gz"
```

[CI-Lauf 42778821214](https://github.com/SpecterAoD/pqkeep/actions/runs/42778821214):
alle zehn Jobs erfolgreich, einschließlich aller vier Plattformen, MSRV, beider
bestehenden Härtungsjobs, Limits, cargo-deny und Gitleaks.
ARM64 führt `cargo fmt --all --check`, beide Clippy-Varianten, `cargo test --locked`
und die v2-Python-Referenztests erfolgreich aus. **402 Rust-Tests inklusive drei
Doc-Tests, null Fehler, null ignorierte Tests**, zusätzlich zehn v2-Referenztests.
Damit sind auch die vorhandenen Crypto-, Memlock- und Sandbox-Tests nativ ausgeführt.
Einzelne Tests prüfen vorhandene Kernelmöglichkeiten; aus einer grünen Suite folgt keine
pauschale Garantie aller Landlock-Funktionen auf jedem Linux-System.

[CodeQL-Lauf 42778820817](https://github.com/SpecterAoD/pqkeep/actions/runs/42778820817):
Rust, Python und Actions erfolgreich.

### Artefaktnachweis

ARM64-Artefakt-ID `13745561341` im obigen Release-Lauf; Aufbewahrung bis 24.11.2026.
Enthalten: `.tar.gz` und `.cdx.json` mit passender Ziel-/Versionsbezeichnung.
CycloneDX 1.5, 126 Komponenten; zielbezogene Seriennummer
`urn:uuid:d24a7011-bd82-529e-a083-af6afce2f472`.

- Actions-ZIP-SHA-256: `2345a2d292b9d65bdf3a7663e2e9db533a20f57cde5d415f9b67411c24f95b52`.
- ARM64-Binary vor/nach Verpackung: `9ccc81b6bc8f2057d3aff41d3f30df5fa8e36f23bea22fe88017ba9722cfaf0e`.
- AMD64-Binary vor/nach Verpackung: `9d24166d17f8760470e19c7dd4269e991b68e4244342fde5a543674e9bd8c0fb`.

Das ARM64-Artefakt wurde zusätzlich lokal heruntergeladen. Python-Standardbibliothek prüfte
ZIP-Digest gegen die GitHub-Metadaten, SBOM-Format, Archivinhalt, ELF-Machine 183,
`root:root`/0755 des Programms und den Binaryhash gegen den nativen Buildlog. Anschließend:

```sh
python3 scripts/release_elf.py /home/codex-agent/projects/pqkeep/analysis/issue-93-phase2/arm-binary aarch64-unknown-linux-gnu
python3 scripts/check_binary.py /home/codex-agent/projects/pqkeep/analysis/issue-93-phase2/arm-binary
```

Beide Prüfungen bestanden. Diese lokalen Prüfungen auf x86_64 sind **statisch**; die echte
Ausführung erfolgte ausschließlich auf den passenden nativen GitHub-Runnern. Keine Emulation.
Lokale Protokolle und heruntergeladenes Artefakt: `analysis/issue-93-phase2/` im Projektordner,
außerhalb des Git-Arbeitsbaums. Hashes sind Integritätsnachweise, noch keine Release-Signaturen.

`cargo deny -L info check` hat nach Freigabe der Cache-Schreibrechte am 10.11.2026
die RustSec-Datenbank online geladen und erfolgreich geprüft: Advisories null Fehler,
null Warnungen; Bans eine bekannte `syn`-Duplikatwarnung. Lizenz- und Quellenprüfungen bestanden.
Die vorherige Sandbox-Ausführung `cargo deny check` scheiterte allein an der nicht
schreibbaren Cache-Sperrdatei. Diese Ausführung zählt nicht als bestandener Audit.

## Risiken und verbleibende Phasen

- Native Ausführung wird durch den ARM64-Runner und reale Tests belegt; eine Prüfung von
  `platform.machine()` allein kann Emulation nicht ausschließen. Es wird kein QEMU eingerichtet.
- Die tatsächlich gemessene Seitengröße ist im CI-Protokoll festzuhalten. Ein Lauf auf einer
  Seitengröße belegt nicht automatisch die Funktion auf allen ARM64-Kernelkonfigurationen.
- Rust `stable` und Runner-Images bewegen sich weiter; kein Nachweis bitidentischer Binaries
  zwischen beliebigen Toolchain-/Image-Versionen. Die Logs dokumentieren die konkrete Umgebung.
- Die glibc-Symbolgrenze ersetzt keine Installationsprüfung auf allen unterstützten Distributionen.
- Debian-Metadaten, gemeinsame Paketierungslogik und Installation folgen erst in Phasen 3–5.
  Dafür liegen in Phase 2 weder Pakete noch Installationsnachweise vor. musl bleibt außerhalb.
- Neue Artefakte sind vor Phase 6 nicht signierte CI-Kandidaten und keine freigegebenen Releases.

## Sicherung und Rückbau

Vor den Änderungen wurde eine verifizierte Sicherung angelegt:
`/home/codex-agent/projects/pqkeep/backups/issue-93-phase2-20261110T074737Z`.
Sie enthält die betroffenen zuvor vorhandenen Dateien, ihre Rechte und Prüfsummen sowie
die Liste neuer Pfade. Die ursprüngliche Arbeitskopie mit Nutzeränderungen bleibt unberührt;
die Entwicklung erfolgt im separaten Worktree `issue-93`.

Vor Merge: PR schließen und Entwicklungsbranch nicht übernehmen; keine Auswirkungen auf
installierte Programme, Benutzerdaten oder Schlüssel. Lokalen Rückbau nur im isolierten
Worktree durchführen: zuvor vorhandene Dateien aus der Sicherung mit ihren Rechten
wiederherstellen; ausschließlich die in dieser Phase neu hinzugefügten Dateien nach
Prüfung entfernen. Den zuvor vorhandenen Phase-1-Plan aus der Sicherung wiederherstellen.

Nach Merge: eigener Revert-PR für die Phase-2-Commits, normale CI erneut ausführen und
freigeben lassen. Keine Tags, Releases oder Nutzerschlüssel löschen. Für einen späteren
produktiven Einsatz ist eine eigenständige Freigabe erforderlich.

## Freigabestatus

Phase-2-Abnahme auf den angegebenen nativen Runnern bestanden. Empfehlung: den eigenen
Phase-2-PR prüfen; nach Übernahme und ausdrücklicher Freigabe mit Phase 3 beginnen.
Die separate 64-KiB-Kernelprüfung bleibt für die Installationsmatrix offen.

Phase 3 bleibt gesperrt, bis der Nutzer sie ausdrücklich freigibt. Issue #93 bleibt bis
zur vollständigen Abnahme aller sechs Phasen offen; ein Phase-2-PR verwendet deshalb
keine automatisch schließende Referenz. Veröffentlichung benötigt eine zusätzliche Freigabe.
