# Contributing

[English](#english) | [Deutsch](#deutsch)

## English

Contributions are welcome. By contributing you agree that your work is licensed under the
[Apache License 2.0](LICENSE) and contains **no proprietary code**. Please read
[`docs/SPEC.md`](docs/SPEC.md) (German, binding specification) and [`CLAUDE.md`](CLAUDE.md)
(working rules) first, and follow the [Code of Conduct](CODE_OF_CONDUCT.md).

### Rules

- One topic per pull request, small and **signed commits**.
- File limits: production files ≤ 300 lines, functions ≤ 50 lines, test files ≤ 400 lines;
  tests only in separate files (`tests/` or `*_tests.rs`).
- Documentation, comments and help texts are bilingual (German/English, `// DE:` / `// EN:`).
- `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings` (with and without
  `--no-default-features`), `cargo test --locked`, `scripts/check_limits.sh` and `cargo deny check`
  must pass.
- Never commit secrets, keys or encrypted container files.
- Justify new dependencies (maintenance, licence, advisories).
- Report vulnerabilities privately, see [`SECURITY.md`](SECURITY.md).

### AI assistance

PQKeep itself is developed with an AI coding assistant (Claude by Anthropic) under the
maintainer's direction; such commits carry a `Co-Authored-By` trailer. Contributions created with
AI tools are welcome under the same rules: you are responsible for every line you submit, it must
be reviewed and tested by you, and please mention the assistance in the pull request.

---

## Deutsch

Beiträge sind willkommen. Mit einem Beitrag erklärst du, dass er unter der
[Apache License 2.0](LICENSE) steht und **keinen proprietären Code** enthält. Bitte vorher
[`docs/SPEC.md`](docs/SPEC.md) und [`CLAUDE.md`](CLAUDE.md) lesen und den
[Verhaltenskodex](CODE_OF_CONDUCT.md) beachten.

- Ein Pull Request pro Thema, kleine **signierte** Commits.
- Dateilimits: Produktion ≤ 300 Zeilen, Funktionen ≤ 50, Tests ≤ 400; Tests in eigenen Dateien.
- Doku, Kommentare, Hilfetexte zweisprachig (DE/EN).
- `cargo fmt`, `cargo clippy -D warnings` (mit und ohne `--no-default-features`),
  `cargo test --locked`, `scripts/check_limits.sh`, `cargo deny check` müssen grün sein.
- Niemals Geheimnisse, Schlüssel oder Container-Dateien einchecken.
- Neue Abhängigkeiten begründen (Wartung, Lizenz, Advisories).
- Sicherheitslücken nicht öffentlich melden, siehe [`SECURITY.md`](SECURITY.md).

**KI-Unterstützung:** PQKeep selbst wird mit einem KI-Assistenten (Claude von Anthropic) nach
Vorgabe des Maintainers entwickelt; solche Commits tragen einen `Co-Authored-By`-Vermerk. Mit
KI-Werkzeugen erstellte Beiträge sind unter denselben Regeln willkommen: Du verantwortest jede
eingereichte Zeile, hast sie geprüft und getestet und erwähnst die Unterstützung im Pull Request.
