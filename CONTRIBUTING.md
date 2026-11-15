# Contributing

[English](#english) | [Deutsch](#deutsch)

## English

Contributions are welcome – code, tests, documentation, translations, reviews and well-described
bug reports alike. By contributing you agree that your work is licensed under the
[Apache License 2.0](LICENSE) and contains **no proprietary code**. Please follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

### Getting started

1. Pick an issue: [good first issues](https://github.com/SpecterAoD/pqkeep/labels/good%20first%20issue),
   [help wanted](https://github.com/SpecterAoD/pqkeep/labels/help%20wanted) or the
   [milestones](https://github.com/SpecterAoD/pqkeep/milestones) for the bigger picture. Leave a
   short comment before you start so that work is not done twice.
2. Build and test (Rust ≥ 1.88; details, selective tests, sandbox pitfalls and all CI checks:
   [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md); questions: [Discussions](https://github.com/SpecterAoD/pqkeep/discussions)):
   ```
   cargo build --locked
   cargo test --locked
   ```
3. For larger changes, describe your approach in the issue first (files, tests, risks) and wait
   for feedback. The specification ([English](docs/SPEC.en.md), [German](docs/SPEC.md)) is binding; its
   [working rules for AI-assisted development](CLAUDE.md) apply to everyone.

Code map: [`ARCHITECTURE.md`](ARCHITECTURE.md).

### Languages

PQKeep is bilingual: documentation, comments and help texts exist in **English and German**, and
both are maintained as equals.

- **English alone is enough for your contribution.** You do not have to write German. Mark your
  pull request with "needs translation"; the German part is added by the maintainer or by another
  contributor.
- **Translations are welcome as contributions of their own** – also improvements to existing
  texts in either language (issues labelled `needs translation`).
- CLI messages live in `src/cli/text_en.rs` and `src/cli/text_de.rs`, and the compiler requires
  both. If you only write English, put the English text into both files and say so in the pull
  request.
- Issue and pull request titles are in English; descriptions may be English, German or both.
- Code identifiers are English.

### Rules

- One topic per pull request, small commits; please sign them (`git commit -S`). Pull requests are
  squash-merged, so `main` always stays signed.
- File limits: production files ≤ 300 lines, functions ≤ 50 lines, test files ≤ 400 lines;
  tests only in separate files (`tests/` or `*_tests.rs`).
- `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings` (with and without
  `--no-default-features`), `cargo test --locked`, `scripts/check_limits.sh` and `cargo deny check`
  must pass. The CI runs all of them.
- No `unsafe`, no `unwrap()`/`expect()` in production code.
- **Test policy:** new or changed functionality comes with tests in the same pull request – success
  cases plus negative and boundary cases (Definition of Done in [`docs/CHECKLIST.md`](docs/CHECKLIST.md)).
- Never commit secrets, keys or encrypted container files; tests create them at runtime.
- Justify new dependencies (maintenance, licence, advisories).
- Report vulnerabilities privately, see [`SECURITY.md`](SECURITY.md).

### AI assistance

PQKeep itself is developed with an AI coding assistant (Claude by Anthropic) under the
maintainer's direction; such commits carry a `Co-Authored-By` trailer. Contributions created with
AI tools are welcome under the same rules: you are responsible for every line you submit, it must
be reviewed and tested by you, and please mention the assistance in the pull request.

---

## Deutsch

Beiträge sind willkommen – Code, Tests, Dokumentation, Übersetzungen, Reviews und gut
beschriebene Fehlermeldungen. Mit einem Beitrag erklärst du, dass er unter der
[Apache License 2.0](LICENSE) steht und **keinen proprietären Code** enthält. Bitte den
[Verhaltenskodex](CODE_OF_CONDUCT.md) beachten.

### Einstieg

1. Issue aussuchen: [good first issues](https://github.com/SpecterAoD/pqkeep/labels/good%20first%20issue),
   [help wanted](https://github.com/SpecterAoD/pqkeep/labels/help%20wanted) oder die
   [Meilensteine](https://github.com/SpecterAoD/pqkeep/milestones) für den Überblick. Vor dem
   Start kurz im Issue kommentieren, damit nichts doppelt gemacht wird.
2. Bauen und testen (Rust ≥ 1.88; Einzelheiten, gezielte Tests, Sandbox-Fallen und alle CI-Prüfungen:
   [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md); Fragen: [Discussions](https://github.com/SpecterAoD/pqkeep/discussions)):
   ```
   cargo build --locked
   cargo test --locked
   ```
3. Bei größeren Änderungen zuerst den Ansatz im Issue beschreiben (Dateien, Tests, Risiken) und
   Rückmeldung abwarten. Die Spezifikation ([Deutsch](docs/SPEC.md), [Englisch](docs/SPEC.en.md)) ist verbindlich; die
   [Arbeitsregeln für KI-gestützte Entwicklung](CLAUDE.md) gelten für alle.

Wegweiser durch den Code: [`ARCHITECTURE.md`](ARCHITECTURE.md).

### Sprachen

PQKeep ist zweisprachig: Dokumentation, Kommentare und Hilfetexte gibt es auf **Deutsch und
Englisch**, beide werden gleichwertig gepflegt.

- **Für deinen Beitrag genügt Englisch.** Deutsch ist keine Pflicht. Den Pull Request mit „needs
  translation“ kennzeichnen; den deutschen Teil ergänzt der Maintainer oder jemand anderes.
- **Übersetzungen sind als eigene Beiträge willkommen** – auch Verbesserungen bestehender Texte in
  beiden Sprachen (Issues mit `needs translation`).
- CLI-Meldungen stehen in `src/cli/text_de.rs` und `src/cli/text_en.rs`; der Compiler verlangt
  beide. Wer nur Englisch schreibt, trägt den englischen Text in beide Dateien ein und erwähnt das
  im Pull Request.
- Titel von Issues und Pull Requests auf Englisch; Beschreibung auf Englisch, Deutsch oder beidem.
- Bezeichner im Code auf Englisch.

### Regeln

- Ein Pull Request pro Thema, kleine Commits; bitte signieren (`git commit -S`). Pull Requests
  werden per Squash übernommen, `main` bleibt dadurch immer signiert.
- Dateilimits: Produktion ≤ 300 Zeilen, Funktionen ≤ 50, Tests ≤ 400; Tests in eigenen Dateien
  (`tests/` oder `*_tests.rs`).
- `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings` (mit und ohne
  `--no-default-features`), `cargo test --locked`, `scripts/check_limits.sh` und
  `cargo deny check` müssen grün sein; die CI prüft alles.
- Kein `unsafe`, kein `unwrap()`/`expect()` im Produktionscode.
- **Testpflicht:** Neue oder geänderte Funktionen kommen mit Tests im selben Pull Request –
  Erfolgsfälle sowie Negativ- und Grenzfälle (Definition of Done in [`docs/CHECKLIST.md`](docs/CHECKLIST.md)).
- Niemals Geheimnisse, Schlüssel oder Container-Dateien einchecken; Tests erzeugen sie zur
  Laufzeit.
- Neue Abhängigkeiten begründen (Wartung, Lizenz, Advisories).
- Sicherheitslücken nicht öffentlich melden, siehe [`SECURITY.md`](SECURITY.md).

### KI-Unterstützung

PQKeep selbst wird mit einem KI-Assistenten (Claude von Anthropic) nach Vorgabe des Maintainers
entwickelt; solche Commits tragen einen `Co-Authored-By`-Vermerk. Mit KI-Werkzeugen erstellte
Beiträge sind unter denselben Regeln willkommen: Du verantwortest jede eingereichte Zeile, hast sie
geprüft und getestet und erwähnst die Unterstützung im Pull Request.
