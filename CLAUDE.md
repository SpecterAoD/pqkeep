# CLAUDE.md – Arbeitsregeln für Claude Code / Rules for Claude Code

Verbindliche Grundlage: [`docs/SPEC.md`](docs/SPEC.md). Fahrplan: [`docs/ROADMAP.md`](docs/ROADMAP.md). Checkliste: [`docs/CHECKLIST.md`](docs/CHECKLIST.md).

1. **Plan vor Code:** Pro Roadmap-Schritt zuerst einen kurzen Plan (Dateien, Crates, Tests) vorlegen und auf Freigabe warten. / Present a short plan per roadmap step and wait for approval.
2. **Ein Schritt nach dem anderen.** Ein Schritt ist fertig, wenn `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` und `cargo test --locked` grün sind und die Definition of Done erfüllt ist.
3. **Dateilimits:** Produktionsdateien max. 300 Zeilen, Funktionen max. 50, Testdateien max. 400. Tests ausschließlich in eigenen Dateien (`tests/` oder `*_tests.rs`).
4. **Zweisprachig:** Doku, Kommentare, Hilfetexte auf Deutsch und Englisch (`// DE:` / `// EN:`).
5. **Keine Secrets** im Repo oder in Workflows. Test-Passphrasen und -Schlüssel werden zur Laufzeit erzeugt.
6. **Crates prüfen** (Wartung, Advisories) vor dem Einbinden. `Cargo.lock` wird eingecheckt, Builds mit `--locked`.
7. **Kein proprietärer Code**, nur Apache-2.0-kompatible Abhängigkeiten.
8. **Bei Unklarheit nachfragen**, nicht raten. Einschränkungen (z. B. `zeroize`) ehrlich dokumentieren.
