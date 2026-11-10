# Issue #93 – Phase 2: natives Linux ARM64

Stand: 10.11.2026. Phase 2 ausdrücklich vom Nutzer freigegeben.
Basis: `569c233afadb2b2b20553e0832c555023d35f055`.
Plan: [Architektur und sechs Phasen](issue-93-implementierungsplan.md).
Status: Implementierung vorbereitet; native CI-Abnahme wird vor Abschluss ergänzt.

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
```

Der ELF-Prüfer hat acht Tests; der Paket-/SBOM-/Smoke-Skripttest fünf Testgruppen.
Der dortige Smoke-Dry-Run ist nur ein Skripttest und kein Nachweis einer Binary-Ausführung.
Negative Tests müssen erwartungsgemäß Fehler zurückgeben; diese werden von den Tests geprüft.
Weitere lokale Rust-Prüfungen und native GitHub-Läufe werden nach ihrem Abschluss ergänzt.

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

Phase 3 bleibt gesperrt, bis der Nutzer sie ausdrücklich freigibt. Issue #93 bleibt bis
zur vollständigen Abnahme aller sechs Phasen offen; ein Phase-2-PR verwendet deshalb
keine automatisch schließende Referenz. Veröffentlichung benötigt eine zusätzliche Freigabe.
