# Sicherheits-Selbstreview / Security self-review

**DE** | [EN](#english)

Selbstreview vor `v0.1.0-beta.1` (SPEC Schritt 7), Stand 07.11.2026, Commit-Basis `main` nach
Schritt 6. **Kein externes Audit** – dieser Bericht dokumentiert, was der Maintainer (mit
KI-Unterstützung) geprüft hat, wie, und mit welchem Ergebnis. Er ersetzt kein unabhängiges Review.

## Ergebnis in Kürze

Keine offenen Befunde mit Sicherheitsrelevanz. Zwei Maßnahmen aus SPEC 5b sind bewusst auf spätere
Updates verschoben (zweiter Faktor, Hybrid-Verfahren), eine durch eine dokumentierte Alternative
ersetzt (TLS über Reverse Proxy statt rustls). Bekannte Grenzen stehen unten und in
[`THREAT_MODEL.md`](THREAT_MODEL.md).

## Prüfpunkte

| # | Prüfpunkt | Methode | Ergebnis |
|---|---|---|---|
| 1 | Geheimnisse in Ausgaben und Fehlermeldungen | Suche nach allen `print!`/`eprintln!`/`format!`/`write!` mit Geheimnis-Bezug; Fehlertyp `Error` geprüft (nur feste Feldnamen, keine Werte, keine Pfade) | Einzige Ausgabe eines Geheimnisses: `pqkeep passphrase` gibt die **erzeugte** Passphrase auf Stdout aus – gewollt und dokumentiert. Die API gibt Eingaben nie zurück (Tests vorhanden). |
| 2 | Geheimnistypen ohne `Debug`/`Clone`/`Display` | Suche nach `derive` an `SecretBytes`, `Passphrase`, `StrongPassphrase`, `UnlockedKey` | Keine Ableitungen; Nullen beim Drop (Typ-Level-Tests seit Schritt 1). |
| 3 | `unsafe` im eigenen Code | `#![forbid(unsafe_code)]` in Bibliothek und Binary, Suche | Keins. |
| 4 | `unwrap`/`expect`/`panic`/`todo`/`unreachable` im Produktionscode | clippy (`deny`), Suche | Keine (einziger Treffer: absichtlich nicht kompilierendes Doku-Beispiel). |
| 5 | Mögliche Abstürze durch Indizes/Slices | clippy einmalig mit `indexing_slicing`, `string_slice`, `arithmetic_side_effects`, `as_conversions` als Prüfhilfe; alle 46 Index-/Slice-Stellen gesichtet, die fremde Eingaben verarbeiten (Archiv, Streaming, Pfade, Hex, Zeitstempel, Passphrase-Prüfung) | Alle begrenzt: Länge vor Zugriff geprüft, Lesemengen ≤ Puffer, Byte-Offsets auf Zeichengrenzen (Kleinschreibung über das erste Zeichen von `to_lowercase`, gleiche Länge der Listen). Überläufe führen wegen `overflow-checks` im Release zum Abbruch statt zu falschen Werten. |
| 6 | Grenzwerte | Konstanten gesichtet | Pfade (255 B/Komponente, 4096 B, Tiefe 64, 10⁶ Einträge), Schlüsseldatei 64 KiB, API-Body 64 KiB, Metadaten 128/64 Zeichen, Passphrase 16–1024 Zeichen (Eingabe ≤ 4096), Argon2id 64 MiB–1 GiB / 3–10 Iterationen / ≤ 16 Threads, Salt 16–64 B, API: Verbindungen, Rate-Limit, Sperre, Argon2-Budget. |
| 7 | Abhängigkeiten | `cargo tree`, `cargo deny check`, `cargo audit` | 121 Crates (Standard-Features, Linux). `cargo deny`: Advisories, Lizenzen, Quellen ok. `cargo audit`: keine Funde. Einzige doppelte Version: `syn` (nur zur Übersetzungszeit). Wöchentliches Audit in der CI. |
| 8 | Fuzzing (SPEC 5b) | cargo-fuzz, 8 Ziele mit Eigenschaftsprüfungen (Parser-Roundtrips, Manipulationserkennung im Streaming-AEAD, Pfadregeln, Passphrase-Prüfung, REST-API) | Erste Läufe je Ziel ohne Fund; wöchentlicher Lauf je 10 min (`.github/workflows/fuzz.yml`). |
| 9 | Statische Analyse | CodeQL (Rust, Python, Actions) | 24 frühere Meldungen geprüft: alle Fehlalarme (Testvektoren, mit Nullen angelegte Puffer vor dem Befüllen, statische Hinweistexte); Tests und Fuzz-Ziele sind von der Analyse ausgenommen. 0 offene Meldungen. |
| 10 | Geheimnis-Scan | gitleaks über die gesamte Historie (CI), GitHub Secret Scanning + Push Protection | Keine Funde. |
| 11 | Binärhärtung | `scripts/check_binary.py` in CI und Release | Linux: PIE, Full RELRO, NX. Windows: ASLR (High Entropy), DEP, Control Flow Guard. |

## Maßnahmen aus SPEC 5b

| Maßnahme | Stand |
|---|---|
| NFKC-Normalisierung der Passphrase | ✅ umgesetzt, Tests Windows/Linux |
| Optionaler zweiter Faktor (Pepper/Schlüsseldatei) | ⏳ **verschoben** auf ein Update (Issues #39–#41): würde kurz vor der Beta das Dateiformat ändern |
| Downgrade-Schutz | ✅ Formatversion und KDF-Untergrenzen werden beim Laden geprüft |
| Dateirechte beim Laden prüfen | ✅ Linux: Warnung bei für Gruppe/Andere lesbaren Dateien; Windows: keine eigene ACL (dokumentierte Lücke) |
| Kein Clipboard, keine Historie | ✅ Passphrase nie als Argument, nie in der Zwischenablage, verdeckte Eingabe |
| Core Dumps und Swap | ✅ Speichersperre, Core-Dump-Sperre (Linux), Nullen (best effort) – [`MEMORY_HARDENING.md`](MEMORY_HARDENING.md) |
| Compiler-/Linker-Härtung | ✅ `overflow-checks`, LTO, `codegen-units = 1`, `strip`, `panic = "abort"`, CFG |
| Lieferkette | ✅ cargo-deny, wöchentliches Audit, gepinnte Actions, Dependabot, signierte Commits/Tags, Attestation, Sigstore, SBOM |
| Fuzzing | ✅ seit Schritt 7 (siehe oben) |
| API: TLS, Token-Hash, Sperre, Header, kein CORS | ✅ bis auf TLS; **TLS bewusst über Reverse Proxy** statt rustls (Begründung: [`CRYPTO.md`](CRYPTO.md), [`API.md`](API.md)) |
| Backup und Rotation | ✅ [`KEY_MANAGEMENT.md`](KEY_MANAGEMENT.md) |
| Hybrid-Verfahren prüfen | ⏳ **bewusst nicht** in der Beta, Begründung in [`CRYPTO.md`](CRYPTO.md); Neubewertung Issue #56 |

## Bekannte Grenzen (Auswahl)

- Kein externes Audit; Bibliotheken nicht FIPS-140-validiert; `ml-kem`/`ml-dsa` sind 0.x-Versionen.
- Puffer von serde_json, hyper/axum und dialoguer lassen sich nicht nullen.
- Windows: keine Sandbox, keine eigene ACL, keine Admin-Warnung, Fehlerberichte (WER) nicht abschaltbar.
- Datei-Verschlüsselung: Größe sichtbar, Zeitstempel/Rechte nicht übernommen, TOCTOU beim Lesen der Quelle.
- Bitgenaue Reproduzierbarkeit der Builds ist angestrebt, aber nicht nachgewiesen.

---

## English

Self-review before `v0.1.0-beta.1` (SPEC step 7), 2026-11-07. **Not an external audit** – it
documents what the maintainer (with AI assistance) checked, how, and the result.

**Result:** no open security-relevant findings. Deferred by decision: optional second factor (issues
#39–#41, would change the file format right before the beta) and a hybrid scheme (issue #56,
rationale in `CRYPTO.md`); TLS is provided via a reverse proxy instead of rustls.

**Checked:** secrets in output and errors (only intended output: `pqkeep passphrase` prints the
generated passphrase); no `Debug`/`Clone` on secret types; no `unsafe`; no `unwrap`/`expect`/`panic` in
production code; all 46 indexing/slicing sites that process external input reviewed with additional
clippy lints – all bounded; limits for paths, files, metadata, passphrases, Argon2id and the API;
dependencies (121 crates, `cargo deny` and `cargo audit` clean, only duplicate `syn`, build time only);
fuzzing with 8 property-based targets (no findings so far, weekly runs); CodeQL (24 former alerts
reviewed as false positives, 0 open); gitleaks and GitHub secret scanning (no findings); binary
hardening checked in CI and release.

**SPEC 5b measures:** implemented except the deferred second factor and hybrid scheme; TLS via
reverse proxy; backup and rotation in [`KEY_MANAGEMENT.md`](KEY_MANAGEMENT.md).

**Known limitations:** no external audit, not FIPS 140 validated, 0.x crypto crates, non-zeroable
buffers in third-party crates, no sandbox/ACL on Windows, visible file size, no proven bit-for-bit
reproducible builds.
