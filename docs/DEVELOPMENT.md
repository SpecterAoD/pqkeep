# Development guide / Entwickleranleitung

[English](#english) | [Deutsch](#deutsch)

## English

How to build, test and check a change locally – the same way the CI does. Rules and the way of
working are in [`CONTRIBUTING.md`](../CONTRIBUTING.md), the code map in
[`ARCHITECTURE.md`](../ARCHITECTURE.md). Questions: [GitHub Discussions (Q&A)](https://github.com/SpecterAoD/pqkeep/discussions/categories/q-a).

### Setup

- Rust stable (the repository pins `stable` with `rustfmt` and `clippy` in `rust-toolchain.toml`);
  minimum supported version 1.88.
- Python 3 (standard library only) for the script tests.
- Linux is the main development platform; Windows works for everything except the sandbox.

### Run the checks the CI runs

```
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo clippy --all-targets --no-default-features --locked -- -D warnings
cargo test --locked
cargo test --locked --no-default-features
bash scripts/check_limits.sh
python3 -m unittest discover -s scripts -p 'test_*.py'
cargo deny check                     # needs: cargo install --locked cargo-deny
python3 scripts/check_attack_matrix.py --summary
python3 -m unittest discover -s scripts -p 'test_attack_matrix.py' -v
```

Clippy runs with `pedantic` warnings; `unwrap`, `expect`, `panic`, `todo`, `dbg!` are denied in
production code (allowed in tests). Functions over 50 code lines fail via clippy's
`too_many_lines`. The CI additionally checks MSRV, the hardened release binary
(`scripts/check_binary.py`), secrets (gitleaks), CodeQL and the workflow files
(`scripts/check_actions_policy.py`, actionlint, zizmor) – see
[`docs/security/CI_SECURITY.md`](security/CI_SECURITY.md).

### Run tests selectively

The [attack catalogue and baseline](security/ATTACK_TEST_MATRIX.md) record scoped assertions and
actual execution separately. Update case/test/CI references together; new execution records need
the tested commit, platform/features and run/job/attempt. The validator is offline and does not
execute stored commands. CI runs it on all four platforms; no-default runtime tests run on Ubuntu
latest and Windows latest, while Ubuntu 22.04/ARM64 additionally compile no-default with clippy.

```
cargo test --locked --test cli_files            # one integration test file
cargo test --locked --test cli_files passphrase # tests whose name contains "passphrase"
cargo test --locked --lib files::               # unit tests of one module
cargo test --locked --no-default-features       # without the REST API
```

- Integration tests live in `tests/`, grouped by prefix (`crypto_*`, `files_*`, `cli_*`, …);
  unit tests live next to the module as `<module>_tests.rs`, included with one
  `#[cfg(test)] mod …;` line.
- Tests create keys and passphrases at runtime with small Argon2 parameters
  (`tests/common/mod.rs`); never commit real secrets or encrypted files.
- Slower parts: known-answer tests (`tests/kat/`, large JSON files) and anything that runs the real
  Argon2 profile. Dependencies are optimised even in debug builds, so a full `cargo test` takes a few
  minutes, not hours.
- CLI tests start the real binary (`common::pqkeep`) with a temporary directory as working directory.

### The sandbox (Linux)

Every command restricts itself before reading any input (Landlock for paths, seccomp for system
calls; [`docs/SANDBOX.md`](SANDBOX.md)). Typical pitfalls:

- **"Permission denied" for a new file access:** the path is not in the command's list. Add it in
  `src/cli/access.rs` – only what the command really needs.
- **Process killed with `SIGSYS` (bad system call):** a new code path or dependency uses a system call
  that is not allowed. Find it with `strace -f pqkeep …` and add it to the right profile in
  `src/hardening/sandbox/syscalls.rs`, with a comment why.
- `pqkeep --no-sandbox …` helps to tell sandbox problems from other bugs – for debugging only.
- `pqkeep --verbose …` shows the sandbox state (e.g. `landlock=full seccomp=full`; `partial` on older kernels).
- The tests `sandbox_cli`, `sandbox_api` and `cli_sandbox` run with the active sandbox on Linux.

### Limits and conventions

- Production files ≤ 300 lines, functions ≤ 50 lines, test files ≤ 400 lines
  (`scripts/check_limits.sh`). Split modules early rather than fighting the limit.
- Comments in the form `// DE: …` / `// EN: …`. English alone is fine for external contributions –
  mark the pull request "needs translation".
- CLI texts: `src/cli/text_de.rs` and `src/cli/text_en.rs` (both required by the compiler).
- No new dependency without a short justification (maintenance, licence, advisories); `deny.toml`
  allows only Apache-2.0-compatible licences.

### Fuzzing

```
cargo +nightly install --locked cargo-fuzz
cd fuzz && cargo +nightly fuzz run pqkf_header -- -max_total_time=60
```

Targets: `fuzz/fuzz_targets/` (key files, public keys, `.pqkf` headers v1/v2, archive paths,
stream tampering, passphrases, API requests). The weekly workflow `fuzz.yml` runs all of them.

### Pull requests

Small, one topic, English title. The CI must be green; review comments are resolved before merging
(squash merge). If you are unsure about the approach, open a discussion or comment on the issue
first.

---

## Deutsch

Wie man eine Änderung lokal baut, testet und prüft – so wie die CI. Regeln und Arbeitsweise stehen
in [`CONTRIBUTING.md`](../CONTRIBUTING.md), der Wegweiser durch den Code in
[`ARCHITECTURE.md`](../ARCHITECTURE.md). Fragen: [GitHub Discussions (Q&A)](https://github.com/SpecterAoD/pqkeep/discussions/categories/q-a).

### Einrichtung

- Rust stable (das Repository legt in `rust-toolchain.toml` `stable` mit `rustfmt` und `clippy`
  fest); Mindestversion 1.88.
- Python 3 (nur Standardbibliothek) für die Skripttests.
- Hauptplattform ist Linux; unter Windows funktioniert alles außer der Sandbox.

### Dieselben Prüfungen wie die CI

```
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo clippy --all-targets --no-default-features --locked -- -D warnings
cargo test --locked
cargo test --locked --no-default-features
bash scripts/check_limits.sh
python3 -m unittest discover -s scripts -p 'test_*.py'
cargo deny check                     # vorher: cargo install --locked cargo-deny
python3 scripts/check_attack_matrix.py --summary
python3 -m unittest discover -s scripts -p 'test_attack_matrix.py' -v
```

Clippy läuft mit `pedantic`-Warnungen; `unwrap`, `expect`, `panic`, `todo`, `dbg!` sind im
Produktionscode verboten (in Tests erlaubt). Funktionen über 50 Codezeilen scheitern an
`too_many_lines`. Die CI prüft zusätzlich MSRV, das gehärtete Release-Programm
(`scripts/check_binary.py`), Geheimnisse (gitleaks), CodeQL und die Workflow-Dateien
(`scripts/check_actions_policy.py`, actionlint, zizmor) – siehe
[`docs/security/CI_SECURITY.md`](security/CI_SECURITY.md).

### Tests gezielt ausführen

[Angriffskatalog und Baseline](security/ATTACK_TEST_MATRIX.md) trennen Assertions und Ausführung.
Fall-/Test-/CI-Verweise gemeinsam pflegen; Nachweise benötigen Quell-SHA, Plattform/Features und
Run/Job/Attempt. Der Validator arbeitet offline und führt keine gespeicherten Kommandos aus.
Die CI prüft ihn auf vier Plattformen; No-default-Runtime läuft auf Ubuntu latest und Windows latest,
Ubuntu 22.04/ARM64 kompilieren No-default zusätzlich mit Clippy.

```
cargo test --locked --test cli_files            # eine Integrationstest-Datei
cargo test --locked --test cli_files passphrase # Tests, deren Name „passphrase“ enthält
cargo test --locked --lib files::               # Unit-Tests eines Moduls
cargo test --locked --no-default-features       # ohne REST-API
```

- Integrationstests liegen in `tests/`, nach Präfix gruppiert (`crypto_*`, `files_*`, `cli_*`, …);
  Unit-Tests liegen neben dem Modul als `<modul>_tests.rs`, eingebunden mit einer Zeile
  `#[cfg(test)] mod …;`.
- Tests erzeugen Schlüssel und Passphrasen zur Laufzeit mit kleinen Argon2-Parametern
  (`tests/common/mod.rs`); nie echte Geheimnisse oder verschlüsselte Dateien einchecken.
- Langsamer sind die Known-Answer-Tests (`tests/kat/`, große JSON-Dateien) und alles mit dem echten
  Argon2-Profil. Abhängigkeiten werden auch im Debug-Build optimiert; ein vollständiges
  `cargo test` dauert wenige Minuten.
- CLI-Tests starten das echte Programm (`common::pqkeep`) mit einem temporären Arbeitsordner.

### Die Sandbox (Linux)

Jeder Befehl schränkt sich vor der ersten Eingabe selbst ein (Landlock für Pfade, Seccomp für
Systemaufrufe; [`docs/SANDBOX.md`](SANDBOX.md)). Typische Fallen:

- **„Permission denied“ bei einem neuen Dateizugriff:** Der Pfad fehlt in der Liste des Befehls.
  In `src/cli/access.rs` ergänzen – nur, was der Befehl wirklich braucht.
- **Prozess endet mit `SIGSYS` (bad system call):** Ein neuer Codepfad oder eine Abhängigkeit nutzt
  einen nicht erlaubten Systemaufruf. Mit `strace -f pqkeep …` finden und im passenden Profil in
  `src/hardening/sandbox/syscalls.rs` ergänzen, mit Begründung als Kommentar.
- `pqkeep --no-sandbox …` trennt Sandbox-Probleme von anderen Fehlern – nur zur Fehlersuche.
- `pqkeep --verbose …` zeigt den Zustand (z. B. `landlock=full seccomp=full`; `partial` bei älteren Kerneln).
- Die Tests `sandbox_cli`, `sandbox_api` und `cli_sandbox` laufen unter Linux mit aktiver Sandbox.

### Grenzen und Konventionen

- Produktionsdateien ≤ 300 Zeilen, Funktionen ≤ 50, Testdateien ≤ 400
  (`scripts/check_limits.sh`). Lieber früh aufteilen als gegen die Grenze kämpfen.
- Kommentare in der Form `// DE: …` / `// EN: …`. Für externe Beiträge genügt Englisch – den Pull
  Request mit „needs translation“ kennzeichnen.
- CLI-Texte: `src/cli/text_de.rs` und `src/cli/text_en.rs` (der Compiler verlangt beide).
- Keine neue Abhängigkeit ohne kurze Begründung (Wartung, Lizenz, Advisories); `deny.toml` lässt
  nur Apache-2.0-kompatible Lizenzen zu.

### Fuzzing

```
cargo +nightly install --locked cargo-fuzz
cd fuzz && cargo +nightly fuzz run pqkf_header -- -max_total_time=60
```

Ziele: `fuzz/fuzz_targets/` (Schlüsseldateien, öffentliche Schlüssel, `.pqkf`-Header v1/v2,
Archivpfade, Stream-Manipulation, Passphrasen, API-Anfragen). Der wöchentliche Workflow `fuzz.yml`
führt alle aus.

### Pull Requests

Klein, ein Thema, englischer Titel. Die CI muss grün sein; Review-Kommentare werden vor dem Merge
geklärt (Squash-Merge). Bei Unsicherheit über den Ansatz zuerst eine Discussion eröffnen oder im
Issue kommentieren.
