# Checklisten / Checklists

## Definition of Done (pro Schritt / per step)

- [ ] Plan wurde vorgelegt und freigegeben
- [ ] Produktionsdateien ≤ 300 Zeilen, Funktionen ≤ 50, Testdateien ≤ 400; Tests nur in eigenen Dateien
- [ ] Kommentare, Doku und Hilfetexte zweisprachig (DE/EN)
- [ ] `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --locked` grün auf Linux **und** Windows
- [ ] Keine hartcodierten Geheimnisse, kein `unwrap()`/`expect()` in Produktionscode
- [ ] Negativ- und Grenzwerttests vorhanden
- [ ] Kurze Zusammenfassung: was gebaut, was getestet, bekannte Einschränkungen

## Pull-Request-Checkliste

- [ ] Keine Geheimnisse, Schlüssel oder Container-Dateien enthalten
- [ ] Neue Abhängigkeiten begründet, Lizenz Apache-2.0-kompatibel, `cargo deny` grün
- [ ] Keine proprietären oder binären Bestandteile
- [ ] Commits signiert

## Release-Checkliste (auch für Betas)

- [ ] CI auf `main` grün (Linux und Windows), `cargo audit`/`deny` ohne offene Funde
- [ ] Version in `Cargo.toml` und `CHANGELOG` angepasst
- [ ] **Signierten** Git-Tag `vX.Y.Z` bzw. `vX.Y.Z-beta.N` erstellt
- [ ] Release-Workflow lief im Environment `release` (Reviewer hat freigegeben)
- [ ] Fünf Artefakte (Linux AMD64/ARM64, Windows, Debian amd64/arm64): je Build-Provenance- und
      SBOM-Attestation, Sigstore-Signatur, SBOM; `SHA256SUMS` (signiert); Manifest-Job grün
- [ ] Paketrevision in `packaging/debian/metadata.json` geprüft (neue Upstream-Version: `1`)
- [ ] Windows-Binary mit SignPath signiert (sobald freigegeben), sonst Hinweis auf SmartScreen in den Release-Notes
- [ ] Verifikations-Job grün (Attestation, Signatur, Prüfsumme)
- [ ] Release-Entwurf geprüft (Assets, Notes) und von Hand veröffentlicht
- [ ] Beta als „Pre-release“ markiert
- [ ] Release-Notes zweisprachig, inkl. Verifikationsanleitung
