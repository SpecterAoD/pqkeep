# Mitwirken / Contributing

**DE:** Beiträge sind willkommen. Mit einem Beitrag erklärst du, dass er unter der [Apache License 2.0](LICENSE) steht und **keinen proprietären Code** enthält. Bitte lies vorher `docs/SPEC.md` und `CLAUDE.md`.

**EN:** Contributions are welcome. By contributing you agree that your work is licensed under the [Apache License 2.0](LICENSE) and contains **no proprietary code**. Please read `docs/SPEC.md` and `CLAUDE.md` first.

## Regeln / Rules

- Ein Pull Request pro Thema, kleine Commits, **signierte Commits**. / One topic per PR, small, **signed commits**.
- Dateilimits: Produktion ≤ 300 Zeilen, Funktionen ≤ 50, Tests ≤ 400; Tests in eigenen Dateien. / File limits as above; tests in separate files.
- Doku, Kommentare, Hilfetexte zweisprachig (DE/EN). / Bilingual docs, comments, help texts.
- `cargo fmt`, `cargo clippy -D warnings`, `cargo test --locked` müssen grün sein. / Must pass.
- Niemals Geheimnisse, Schlüssel oder Container-Dateien einchecken. / Never commit secrets, keys or container files.
- Neue Abhängigkeiten begründen (Wartung, Lizenz, Advisories). / Justify new dependencies.
- Sicherheitslücken nicht öffentlich melden, siehe [`SECURITY.md`](SECURITY.md). / Do not report vulnerabilities publicly.
