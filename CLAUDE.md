# CLAUDE.md – Arbeitsregeln für Claude Code / Rules for Claude Code

Verbindliche Grundlage: [`docs/SPEC.md`](docs/SPEC.md) (englisch / English: [`docs/SPEC.en.md`](docs/SPEC.en.md), im selben PR mitpflegen / update in the same PR). Fahrplan: [`docs/ROADMAP.md`](docs/ROADMAP.md). Checkliste: [`docs/CHECKLIST.md`](docs/CHECKLIST.md).

1. **Plan vor Code:** Pro Roadmap-Schritt zuerst einen kurzen Plan (Dateien, Crates, Tests) vorlegen und auf Freigabe warten. / Present a short plan per roadmap step and wait for approval.
2. **Ein Schritt nach dem anderen.** Ein Schritt ist fertig, wenn `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` und `cargo test --locked` grün sind und die Definition of Done erfüllt ist.
3. **Dateilimits:** Produktionsdateien max. 300 Zeilen, Funktionen max. 50, Testdateien max. 400. Tests ausschließlich in eigenen Dateien (`tests/` oder `*_tests.rs`).
4. **Zweisprachig:** Doku, Kommentare, Hilfetexte auf Deutsch und Englisch (`// DE:` / `// EN:`). Beiträge des Maintainers und von Claude sind immer zweisprachig; externe Beiträge dürfen nur Englisch sein – die deutsche Fassung wird nachgezogen (Label `needs translation`). Titel von Issues, Pull Requests und Commits auf Englisch, Beschreibung DE/EN. / Maintainer and Claude contributions are always bilingual; external contributions may be English only – German follows (label `needs translation`). Issue, pull request and commit titles in English, description DE/EN.
5. **Keine Secrets** im Repo oder in Workflows. Test-Passphrasen und -Schlüssel werden zur Laufzeit erzeugt.
6. **Crates prüfen** (Wartung, Advisories) vor dem Einbinden. `Cargo.lock` wird eingecheckt, Builds mit `--locked`.
7. **Kein proprietärer Code**, nur Apache-2.0-kompatible Abhängigkeiten.
8. **Bei Unklarheit nachfragen**, nicht raten. Einschränkungen (z. B. `zeroize`) ehrlich dokumentieren.
