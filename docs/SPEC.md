# MASTER-PROJEKT-SPEZIFIKATION v2: PQC KeyForge (Core, CLI & API)

> Arbeitsanweisung für Claude Code. Diese Spezifikation ist verbindlich. Bei Widersprüchen oder Lücken: nicht raten, sondern kurz nachfragen.

## 0. Arbeitsweise (gilt für jeden Schritt)

1. **Plan vor Code:** Vor jedem Schritt zuerst einen kurzen Plan (Dateien, Crates, Teststrategie) vorlegen und auf Freigabe warten.
2. **Ein Schritt nach dem anderen:** Erst wenn `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` und `cargo test` grün sind, gilt der Schritt als erledigt. Dann Zusammenfassung und erneut Freigabe abwarten.
3. **Recherche vor Crate-Wahl:** Aktuelle Versionen, Wartungsstatus und bekannte Advisories der Crates prüfen (docs.rs, RustSec). Keine Crates aus dem Gedächtnis einbinden, Versionen in `Cargo.lock` einfrieren.
4. **Ehrlichkeit:** Wo eine Anforderung technisch nur eingeschränkt erfüllbar ist (z. B. `zeroize`), das offen dokumentieren, nicht beschönigen.
5. **Commits:** Kleine, thematisch getrennte Commits pro Schritt.

## 1. Projekt-Ziel & Architektur-Prinzipien

Hochsichere, speichersichere, plattformübergreifende Anwendung (Windows & Linux) in reinem Rust zur **Generierung, Speicherung und Verwaltung** von Post-Quanten-Schlüsseln (ML-KEM, ML-DSA) und symmetrischen Schlüsseln (AES-256).

- **Keine Backdoors, minimale Angriffsfläche:** Strenge Eingabevalidierung (Länge, Zeichensatz, Format). Keine Telemetrie, **keine ausgehenden Netzwerkverbindungen**. Die API nimmt nur eingehende Verbindungen an.
- **Modulare Dateibeschränkung (angepasst):** Zweisprachige Kommentare verbrauchen viele Zeilen, daher gilt:
  - Produktionsdateien: max. **300 Zeilen** (physische Zeilen inkl. Kommentare und Leerzeilen).
  - Einzelne Funktionen: max. **50 Zeilen**.
  - Testdateien: max. **400 Zeilen**, ein Testthema pro Datei.
  - Wird eine Datei zu groß, in Untermodule aufteilen (z. B. `crypto/kem.rs`, `crypto/dsa.rs`, `crypto/kdf.rs`, `crypto/aead.rs`). Ein CI-Skript prüft alle Limits automatisch und lässt den Build bei Verstoß scheitern.
- **Tests grundsätzlich in eigenen Dateien:** Kein `#[cfg(test)] mod tests { ... }` mit Inhalt in Produktionsdateien. Tests der öffentlichen API liegen in `tests/*.rs`. Tests interner Funktionen liegen in einer eigenen Datei neben dem Modul (z. B. `src/crypto/kdf_tests.rs`), eingebunden nur per `#[cfg(test)] mod kdf_tests;` (eine Zeile). Das CI-Skript prüft, dass Produktionsdateien keine Testfunktionen (`#[test]`) enthalten.
- **Zweisprachigkeit:** Dokumentation, READMEs, Doc-Kommentare und Inline-Kommentare auf Deutsch **und** Englisch. Format: `// DE: ...` gefolgt von `// EN: ...`. Fehlermeldungen für Endnutzer (CLI) zweisprachig oder per `--lang de|en` wählbar.
- **Architektur:** Bibliothek (`lib.rs`) als Core, darauf aufbauend ein Binary (`main.rs`) mit CLI und API-Server. CLI und API nutzen ausschließlich die Core-API, keine duplizierte Kryptologik.
- **Fokus:** Zuerst Core, dann CLI, dann API. GUI ist ausdrücklich **nicht** Teil dieses Projekts (Non-Goal).
- **Begriff:** „Passkey“ in dieser Spezifikation meint eine **Passphrase** (Geheimnis des Nutzers), nicht WebAuthn/FIDO2-Passkeys. Im Code und in der Doku konsequent `passphrase` verwenden, um Verwechslungen zu vermeiden.

## 2. Bedrohungsmodell (kurz, in `docs/THREAT_MODEL.md` festhalten)

- **Schutzziel:** Vertraulichkeit und Integrität gespeicherter privater Schlüssel bei Verlust oder Diebstahl der Container-Datei (Offline-Angreifer).
- **In Scope:** Brute-Force auf die Passphrase, manipulierte Container-Dateien, fehlerhafte/bösartige Eingaben (CLI und API), Ressourcenerschöpfung (DoS) über die API.
- **Out of Scope:** Kompromittierter Host (Malware mit Speicherzugriff, Keylogger), Seitenkanäle auf Hardware-Ebene. Das wird in der Doku explizit genannt.

## 3. Sicherheits- & Performance-Anforderungen

### 3.1 Speichersicherheit
- `#![forbid(unsafe_code)]` im Projekt. Falls für Plattformfunktionen (z. B. Speicher-Locking) unvermeidbar: isoliert in einem einzigen, kommentierten Modul mit Begründung.
- Geheimnisse (private Schlüssel, Seeds, abgeleitete Schlüssel, Passphrase) in `Zeroizing<...>` bzw. Typen mit `ZeroizeOnDrop` / `secrecy`. Diese Typen implementieren **kein** `Debug`, `Display`, `Clone` oder `Serialize` mit Klartext-Ausgabe.
- Kein Logging von Geheimnissen oder Request-Bodies. Vergleich von Geheimnissen/Tags in konstanter Zeit (`subtle`).
- Doku-Hinweis: Zeroization ist „best effort“ (Kopien durch Compiler, Swap, Core Dumps). Optional und dokumentiert: Core Dumps deaktivieren, Speicherseiten sperren.

### 3.2 Kryptografie
- **Schlüsselaustausch:** ML-KEM (FIPS 203), Standard **ML-KEM-768**, wählbar ML-KEM-512/1024.
- **Signaturen:** ML-DSA (FIPS 204), Standard **ML-DSA-65**, wählbar ML-DSA-44/87.
- **Private Schlüssel** bevorzugt als kompakter **Seed** speichern und beim Laden neu ableiten (sofern die Crate das unterstützt), sonst als expandierter Schlüssel.
- **Symmetrische Schlüssel:** Erzeugung von AES-256-Schlüsseln (32 Byte) aus dem OS-CSPRNG (`getrandom`/`OsRng`).
- **Container-Verschlüsselung:** AES-256-GCM, 96-Bit-Nonce zufällig aus OS-CSPRNG, **pro Verschlüsselung neuer Salt und neuer Schlüssel**. Header und Metadaten werden als **AAD** mitauthentifiziert.
- **Schlüsselableitung:** Argon2id.
  - Parallelismus `p` = verfügbare CPU-Kerne (`available_parallelism`, nach oben begrenzt, z. B. max. 8).
  - **Wichtig:** `m`, `t`, `p` und Salt (≥ 16 Byte) werden im Container-Header gespeichert, damit die Entschlüsselung auf anderer Hardware funktioniert.
  - Untergrenzen beim Erzeugen (z. B. m ≥ 64 MiB, t ≥ 3), Obergrenzen beim Lesen fremder Container (z. B. m ≤ 1 GiB, t ≤ 10, p ≤ 16), um DoS über manipulierte Header zu verhindern.
  - Vordefinierte Profile (z. B. `standard`, `hardened`), Werte im Code zentral definiert.
- **Zufall:** Ausschließlich OS-CSPRNG. Kein `thread_rng`-Ersatz, keine eigenen Generatoren.
- **Krypto-Crates:** Bevorzugt gepflegte, reine Rust-Implementierungen (z. B. RustCrypto `ml-kem`, `ml-dsa`, `aes-gcm`, `argon2`, `zeroize`; alternativ `libcrux`). Auswahl begründen. Hinweis in der Doku: Die Crates sind nicht FIPS-140-validiert.

### 3.3 Passphrase-Sicherheit
- **Pflicht:** min. 16 Zeichen (Unicode-Zeichen zählen, nicht Bytes), Groß-/Kleinbuchstaben, Zahlen, Sonderzeichen.
- **Zusätzlich:** Ablehnung von Wiederholungen/Sequenzen (`aaaa…`, `1234…`), kleiner eingebauter Blocklist-Check häufiger Muster, geschätzte Entropie mit Mindestwert (z. B. ≥ 80 Bit) und Rückmeldung, **warum** abgelehnt wurde.
- **Generator:** Kryptografisch sicher, **ohne Modulo-Bias** (Rejection Sampling), garantiert alle Zeichenklassen, Standard ≥ 24 Zeichen bzw. ≥ 128 Bit Entropie. Optional: Wortlisten-Variante (Diceware, ≥ 6 Wörter). Entropie wird als `log2(Alphabetgröße) * Länge` berechnet und angezeigt.
- Eingabe nie über Kommandozeilenargumente oder Umgebungsvariablen, sondern nur über verdeckte Prompts, Stdin oder (API) Request-Body.

## 4. Container-Format (Basis für Schritt 3)

- JSON mit **Versionsfeld** (`format_version`) und Magic-/Typ-Feld. Binärdaten Base64 (Standard-Alphabet, strikt validiert).
- Klartext-Metadaten (authentifiziert als AAD): Name, Organisation, Firma, Abteilung, Account-Typ, Algorithmus-ID, Erstellungszeit (UTC), Schlüssel-ID (Fingerprint, z. B. SHA3-256 des öffentlichen Schlüssels), KDF-Parameter, Salt, Nonce.
- Verschlüsselter Teil: privater Schlüssel (bzw. Seed). Öffentlicher Schlüssel im Klartext.
- Hinweis in der Doku: Metadaten sind **nicht verschlüsselt** (personenbezogene Daten beachten).
- Parser: strenge Längen- und Zeichensatzgrenzen, `deny_unknown_fields`, maximale Dateigröße, keine Panics bei Fehleingaben.
- Keine Pfade im Container. Dateien werden **atomar** geschrieben (temporäre Datei, dann umbenennen), Linux-Rechte `0600`, unter Windows Ablage im Benutzerprofil.

## 5. Automatisierung & CI/CD (GitHub Actions)

- Trigger: jeder Push und Pull Request, Matrix `ubuntu-latest` und `windows-latest`, Rust stable (+ MSRV-Job).
- Pflicht-Jobs: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --locked`, Zeilenlimit-Check (max. 300), `cargo audit` oder `cargo deny` (Advisories, Lizenzen, verbotene Crates).
- Workflow-Härtung: `permissions: contents: read`, Actions auf Commit-SHA pinnen, Dependabot für Cargo und Actions, kein `pull_request_target`.
- **Keine Secrets** im Repository oder in Workflows. Tests erzeugen alle Passphrasen und Schlüssel zur Laufzeit dynamisch (Generator, temporäre Verzeichnisse via `tempfile`). Negativtests dürfen bewusst schwache Beispielwerte als Testdaten nutzen, aber nie echte oder wiederverwendete Geheimnisse.
- Zusätzliche Prüfungen: Secret-Scanning mit Push Protection (GitHub) und `gitleaks` im CI; Test-Check „keine `#[test]` in `src/` außer `*_tests.rs`“.
- Release und Signierung: siehe Abschnitt 5a.

## 5a. Release-Signierung & Lieferkette (Pflicht für Releases **und** Betas)

Alle veröffentlichten Artefakte (Release, Beta, Release Candidate) müssen signiert und nachprüfbar sein. Betas durchlaufen **denselben** Prozess, nur mit Tag `vX.Y.Z-beta.N` und als „Pre-release“ markiert.

- **Auslöser:** Nur ein **signierter Git-Tag** (`v*`) startet den Release-Workflow. Tags werden lokal signiert (SSH- oder GPG-Signatur). Der Workflow bricht ab, wenn die Tag-Signatur nicht verifizierbar ist.
- **Schutz des Hauptzweigs:** Branch Protection auf `main`: Pull Request mit Review, erforderliche Status-Checks, **signierte Commits erforderlich**, keine Force-Pushes, `CODEOWNERS`.
- **Build-Provenienz:** `actions/attest-build-provenance` (GitHub Artifact Attestations, SLSA-Provenance) für jedes Artefakt, Linux und Windows.
- **Keyless-Signatur:** Zusätzlich `cosign sign-blob` (Sigstore, OIDC-Identität des Workflows). Dafür sind **keine** hinterlegten privaten Schlüssel nötig, passend zur Regel „keine Secrets im Repo“.
- **Prüfsummen:** `SHA256SUMS` für alle Artefakte, selbst signiert und als Release-Asset beigefügt.
- **SBOM:** CycloneDX- oder SPDX-SBOM (z. B. `cargo-cyclonedx`) erzeugen, an das Release hängen und attestieren.
- **Windows-Binary:** Zusätzlich Authenticode-Signatur gegen SmartScreen-Warnungen über die **SignPath Foundation** (kostenlos für Open Source). Azure Artifact Signing (kostenpflichtig) ist nur die Ausweichlösung. Zugangsdaten (SignPath-API-Token) ausschließlich als GitHub-Environment-Secret, niemals im Repo.
  - **Voraussetzungen (müssen dauerhaft erfüllt bleiben):** öffentliches Repository, OSI-anerkannte Lizenz (Abschnitt 5c), **kein proprietärer Code** im Projekt, Multi-Faktor-Authentifizierung für alle Teammitglieder bei GitHub und SignPath, nur eigene Binaries signieren, Build ausschließlich über GitHub Actions aus dem öffentlichen Repository (Origin Verification).
  - **Pflichthinweis** in README und Release-Notes: „Free code signing provided by SignPath.io, certificate by SignPath Foundation.“ sowie eine Seite „Code Signing Policy“ mit Teamrollen.
  - **Bis zur Freigabe:** Der Signierschritt ist im Workflow optional (läuft nur, wenn die SignPath-Variablen gesetzt sind). Ohne ihn werden Windows-Artefakte unsigniert veröffentlicht, aber weiterhin per Attestation, Sigstore und Prüfsumme abgesichert. Die README weist dann auf die SmartScreen-Warnung hin.
- **Härtung des Release-Jobs:** Eigener Job mit GitHub Environment `release` (erforderlicher Reviewer), Berechtigungen nur dort: `contents: write`, `id-token: write`, `attestations: write`. Alle anderen Jobs: `contents: read`. Actions auf Commit-SHA gepinnt.
- **Reproduzierbarkeit:** `cargo build --release --locked`, `--remap-path-prefix`, festes `SOURCE_DATE_EPOCH`. Ziel: identischer Hash bei Wiederholung (soweit möglich, Abweichungen dokumentieren).
- **Verifikationsanleitung** (zweisprachig in der README): `gh attestation verify <datei> --repo <owner>/<repo>`, `cosign verify-blob ...`, `sha256sum -c SHA256SUMS`, Prüfung der Authenticode-Signatur unter Windows.
- **Tests:** Trockenlauf des Release-Workflows mit Beta-Tag; ein Verifikations-Job lädt die erzeugten Artefakte und prüft Attestation, Signatur und Prüfsumme automatisch.

## 5c. Lizenz & Open-Source-Reinheit

- **Lizenz (festgelegt):** **Apache License 2.0** (OSI-anerkannt, enthält eine Patentklausel, passend für Kryptografie). Datei `LICENSE` (Volltext) und `NOTICE` im Repo-Root, `license = "Apache-2.0"` in `Cargo.toml`. Alle Abhängigkeiten müssen mit Apache-2.0 kompatibel sein (Allowlist in `deny.toml`, z. B. Apache-2.0, MIT, BSD-2/3-Clause, ISC, Unicode-3.0; GPL/AGPL-Abhängigkeiten sind ausgeschlossen).
- **Kein proprietärer Code:** Weder im eigenen Code noch in Abhängigkeiten, Vendor-Verzeichnissen, Binärblobs oder eingebetteten Ressourcen. Keine vorkompilierten Binärdateien im Repo.
- **Automatische Prüfung:** `cargo deny` mit Lizenz-Allowlist (nur OSI-anerkannte, kompatible Lizenzen), Verbot unbekannter Registries/Git-Quellen und Prüfung auf Crates ohne Lizenzangabe. Zusätzlich Check, dass keine Binärdateien eingecheckt sind.
- **Beiträge:** `CONTRIBUTING.md` (DE/EN) mit Hinweis, dass eingereichter Code unter derselben Lizenz steht und keinen proprietären Code enthalten darf.
- **Dokumentation:** Lizenz und Hinweis zur Code-Signierung in der zweisprachigen README.

## 5b. Weitere Sicherheitsmaßnahmen

- **Passphrase-Normalisierung:** Unicode **NFKC** vor der Ableitung, sonst kann dieselbe Passphrase unter Windows und Linux zu unterschiedlichen Schlüsseln führen.
- **Optionaler zweiter Faktor:** Keyfile oder „Pepper“ (separate Datei) zusätzlich zur Passphrase in die Ableitung einbeziehen.
- **Downgrade-Schutz:** Container mit zu alter `format_version` oder zu schwachen KDF-Parametern werden abgelehnt oder nur mit expliziter Warnung/Bestätigung geöffnet.
- **Dateirechte beim Laden prüfen:** Unter Linux Warnung bei `group/world`-lesbaren Containern. Unter Windows Ablage im Benutzerprofil mit eingeschränkter ACL.
- **Kein Clipboard, keine Historie:** Passphrasen werden nie automatisch in die Zwischenablage kopiert, nie als Argument übergeben (Shell-History) und im Terminal nicht angezeigt (Ausnahme: Generator, nur auf ausdrücklichen Wunsch).
- **Core Dumps und Swap:** Core Dumps für den Prozess deaktivieren und Speicherseiten mit Geheimnissen sperren (`mlock`/`VirtualLock`), nur in einem isolierten, kommentierten Modul. Ehrlich dokumentieren: Das ist best effort.
- **Compiler-/Linker-Härtung:** `overflow-checks = true` auch im Release, `lto`, `strip`. Linux: PIE, Full RELRO (`-z relro -z now`). Windows: Control Flow Guard.
- **Lieferkette:** `cargo deny` mit Allowlist für Lizenzen und Quellen, möglichst wenige Abhängigkeiten, optional `cargo vet`, OpenSSF-Scorecard-Workflow, Dependabot, 2FA für alle Maintainer.
- **Fuzzing:** `cargo-fuzz` für Container-Parser und API-Eingaben, regelmäßig per geplantem Workflow.
- **API zusätzlich:** Optionales TLS (rustls) mit modernen Cipher Suites, Token nur als Hash gespeichert, Sperre nach wiederholten Fehlversuchen, Sicherheits-Header, kein CORS standardmäßig.
- **Backup und Rotation:** Doku zu Sicherung der Container, Schlüssel-Rotation und Ablaufdatum. Hinweis: Sicheres Löschen auf SSDs ist unzuverlässig, daher Verschlüsselung statt Löschen als Schutzprinzip.
- **Optional prüfen:** Hybrid-Verfahren (z. B. X25519 + ML-KEM) für Übergangszeit, mit eigener Entscheidung dokumentiert.

## 6. Verzeichnisstruktur (Vorschlag)

```
pqc-keyforge/
├─ Cargo.toml / Cargo.lock / deny.toml / rust-toolchain.toml
├─ src/  lib.rs  main.rs  error.rs  security.rs  envelope.rs  cli.rs  api.rs
│        crypto/ (mod.rs, kem.rs, dsa.rs, kdf.rs, aead.rs)
├─ tests/  integration_*.rs   (+ tests/kat/ für Known-Answer-Tests, tests/cli_help.rs)
│        (interne Tests: src/**/<modul>_tests.rs, nur per #[cfg(test)] mod eingebunden)
├─ scripts/  check_limits.sh  (Zeilenlimits, keine #[test] in Produktionsdateien)
├─ docs/  THREAT_MODEL.md  FORMAT.md
├─ README.md (DE/EN)  SECURITY.md  CONTRIBUTING.md  CODE_SIGNING_POLICY.md
├─ LICENSE (Apache-2.0)  NOTICE  CLAUDE.md  docs/ROADMAP.md  docs/CHECKLIST.md
└─ .github/workflows/ci.yml  dependabot.yml
```

## 7. Fahrplan (Step-by-Step)

Jeder Schritt wird erst nach grünem `cargo test` und Freigabe abgeschlossen. Pro Datei max. 300 Zeilen.

### Schritt 0: Projekt-Grundgerüst
- Aufgabe: Cargo-Projekt, Lints (`forbid(unsafe_code)`, Clippy-Konfiguration), `error.rs` (`thiserror`, keine Geheimnisse in Fehlertexten), CI-Rumpf mit Zeilenlimit-Check.
- Test: leerer Build und Lint auf beiden Plattformen.

### Schritt 1: Core-Krypto (`crypto/`)
- Aufgabe: ML-KEM- und ML-DSA-Schlüsselerzeugung, AES-256-Schlüsselerzeugung, Argon2id-Ableitung, AES-256-GCM-Verschlüsselung/Entschlüsselung des privaten Schlüssels.
- Tests:
  - Roundtrip: Erzeugen, Verschlüsseln, Entschlüsseln mit korrekter Passphrase; KEM-Encaps/Decaps und Sign/Verify funktionieren mit dem wiederhergestellten Schlüssel.
  - Fehlschlag bei falscher Passphrase, bei jedem einzelnen manipulierten Byte (Ciphertext, Tag, Nonce, Salt, AAD/Metadaten) und bei abgeschnittenen Daten.
  - Known-Answer-Tests (NIST-Testvektoren) für ML-KEM/ML-DSA, soweit die Crate sie zulässt.
  - KDF-Grenzwerte: zu schwache und zu hohe Parameter werden abgelehnt.
  - Zeroize: Typ-Level-Test, dass alle Geheimnistypen `ZeroizeOnDrop`/`Zeroizing` sind, plus Test, dass `zeroize()` den Puffer tatsächlich nullt. Ehrliche Doku zu den Grenzen.
  - Nonce-Eindeutigkeit über viele Verschlüsselungen.

### Schritt 2: Validierung & Passphrase (`security.rs`)
- Aufgabe: Stärkeprüfung (Abschnitt 3.3), Entropieschätzung, Generator.
- Tests: schwache Passphrasen werden mit nachvollziehbarem Grund abgelehnt (zu kurz, fehlende Klassen, Muster, Blocklist); starke werden akzeptiert; Generator liefert in N Durchläufen stets gültige, voneinander verschiedene Werte mit erwarteter Länge und Klassenabdeckung; Entropiewert stimmt mit Formel überein; Unicode-Grenzfälle.

### Schritt 3: Container (`envelope.rs`)
- Aufgabe: Struktur (Abschnitt 4), Serialisierung, Deserialisierung, Validierung der Metadaten.
- Tests: Roundtrip; Ablehnung unbekannter Felder, falscher Version, übergroßer oder fehlerhaft kodierter Daten; Pfadkonventionen Windows (`C:\Users\...`, Backslashes) und Linux (`/home/...`) via `PathBuf` und `tempfile`; atomares Schreiben; Dateirechte unter Linux; Fuzz-Test oder Property-Test (`proptest`) für den Parser (keine Panics).

### Schritt 4: CLI (`cli.rs`, `clap` + `dialoguer`)
- Aufgabe: Interaktives Menü **und** nicht-interaktive Subcommands (`generate`, `validate`, `inspect`, `export`, `passphrase`, `help`). Verdeckte Passphrase-Eingabe, Bestätigung vor Überschreiben, Ausgabe nur in vom Nutzer gewählte Pfade (Pfad-Validierung).
- **Integrierte Hilfe (zweisprachig DE/EN, per `--lang de|en`, Standard aus System-Locale):**
  - `--help` und `-h` global und pro Subcommand, jeweils mit Beschreibung, Parametern, Beispielen und Exit-Codes.
  - `keyforge help <thema>` mit Themen: `passphrase` (Regeln und Generator), `algorithms` (ML-KEM/ML-DSA/AES, Parametersätze), `container` (Format und Metadaten), `security` (Sicherheitshinweise und Grenzen), `verify` (Release-Signaturen prüfen).
  - Im interaktiven Menü ein Eintrag „Hilfe / Help“ sowie kontextbezogene Kurzhinweise bei jeder Eingabe (z. B. Passphrase-Regeln, Hinweis auf Metadaten im Klartext).
  - Manpage (`clap_mangen`) und Shell-Completions (`clap_complete`, bash/zsh/fish/PowerShell) werden per Subcommand `keyforge completions <shell>` bzw. `keyforge man` erzeugt, ohne Netzwerkzugriff.
- Tests (in eigenen Dateien): simulierte Eingaben (Integrationstests mit `assert_cmd`), erfolgreicher Export des Containers, erneutes Einlesen und Entschlüsseln, saubere Fehlermeldungen bei ungültigen Eingaben, Exit-Codes. Hilfetests: Jeder Subcommand und jedes Hilfethema liefert Text in **beiden** Sprachen, `--help` enthält mindestens ein Beispiel, kein Hilfetext enthält Beispielgeheimnisse, die wie echte Zugangsdaten aussehen.

### Schritt 5: API (`api.rs`, Axum)
- Aufgabe: Endpunkte `POST /v1/generate`, `POST /v1/validate`, `GET /v1/health`. Strikte JSON-Schemata.
- Härtung: Standard-Bind **127.0.0.1**, Anbindung an andere Interfaces nur explizit und mit Warnhinweis (TLS-Terminierung durch Reverse Proxy dokumentieren); Authentifizierung per Token aus Datei/Umgebung (konstante Zeit); Body-Größenlimit, Timeouts, Rate-Limiting; Argon2-Arbeit in `spawn_blocking` mit Semaphore (Begrenzung paralleler KDF-Jobs gegen DoS); keine Geheimnisse in Logs; generische Fehlerantworten ohne interne Details.
- Tests: HTTP-Integrationstests für alle Endpunkte (Erfolg, ungültige Eingabe, fehlende Auth, zu große Bodies, manipulierte Container, Parallelitätslimit).

### Schritt 6: CI/CD & Dokumentation
- Aufgabe: vollständige `ci.yml` (Abschnitt 5), `release.yml` mit Signierung (Abschnitt 5a), `SECURITY.md` (Meldeweg), `THREAT_MODEL.md`, `FORMAT.md`, zweisprachige `README.md` (Installation, Nutzung, Sicherheitshinweise, Grenzen, Verifikation von Releases).
- Tests: Workflow läuft grün auf Linux und Windows; Beta-Trockenlauf des Release-Workflows inklusive automatischer Verifikation von Attestation, Signatur und Prüfsumme; Dokumentationsbeispiele werden als Doctests oder Smoke-Tests ausgeführt.

### Schritt 7: Abschluss-Review
- Aufgabe: Sicherheits-Selbstreview (Checkliste: Geheimnisse in Logs/Fehlern, `unwrap`/`expect` in Produktionspfaden, Panics, Parameterlimits, Abhängigkeitsbaum, Maßnahmen aus 5b umgesetzt), `cargo audit`/`deny` ohne offene Funde, erste signierte Beta (`v0.1.0-beta.1`) veröffentlichen und die Verifikation nach Anleitung selbst nachvollziehen.

## 8. Definition of Done (pro Schritt)

- [ ] Produktionsdateien ≤ 300 Zeilen, Funktionen ≤ 50, Testdateien ≤ 400; Tests ausschließlich in eigenen Dateien
- [ ] Kommentare/Doku/Hilfetexte zweisprachig (DE/EN)
- [ ] `fmt`, `clippy -D warnings`, `cargo test --locked` grün auf Linux **und** Windows
- [ ] Keine hartcodierten Geheimnisse, keine `unwrap()`/`expect()` in Produktionscode
- [ ] Negativ- und Grenzwerttests vorhanden, nicht nur der Erfolgsfall
- [ ] Kurze Zusammenfassung: was gebaut, was getestet, bekannte Einschränkungen
