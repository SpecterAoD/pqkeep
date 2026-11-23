# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning: [Semantic Versioning](https://semver.org/) (pre-1.0: formats and options may still change).
German release notes: see `docs/releases/`.

## [Unreleased]

- DE: NFKC-Zeichen-/Sortierarbeitsbereiche vor Befüllung sperren; bisherige Passphrase-Bytes
  gegen alle Unicode-Skalare und den vollständigen Unicode18-Korpus prüfen (#147 R6).
  EN: Lock normalization workspaces before use, preserving the pinned Unicode tables
  and passphrase derivation bytes. Other provider lifetime gaps remain open.

- DE: #147 Laufzeitnacharbeit: direkte Klartext-Datei-I/O, gesperrter Hash-Eingabepuffer,
  In-place-AEAD ohne allokierende Klartext-Zwischenkopie, gesperrtes Rekey-Framing und
  Token-Erzeugung; HTTP/1-/JSON-Speicheradapter und vertrauliche Archivnamen/Konfliktschlüssel.
  Listen-JSON unverändert, Rust-Pfad-/Tokenhash-Zugriffe explizit/fallibel. Provider-Konstruktoren
  und Prozess-/Helper-Unterstützung weiterhin offen, keine vollständige Schließungsbehauptung.
  EN: Locked runtime buffers, protected ingress owners/parser scratch and confidential
  metadata; strict failures and wire/JSON compatibility preserved. Provider construction
  and platform/helper verification remain open.
  DE: Listen-Datensätze einschließlich Typ/Größe vor Sammlung fest gesperrt; auch
  frühere Ownerbytes vor Unlock löschen. EN: ConfidentialEntries locks fixed record
  storage before collection and wipes former owner bytes before unlocking.
  Generated API tokens now require explicit borrowed exposure instead of a clonable String.


### Security
- Secret-lifetime audit (#147): inventory and synthetic std/provider copy probes, explicit
  remaining I/O/AEAD/rekey/hash/HTTP/token findings and scoped remediation/test proposals.
  Clarify memory-coverage claims and correct the Windows `DumpType=0` premise (custom dump,
  not disabled). No production/provider/format change; runtime findings remain open.
  **DE:** Secret-Kopien und Plattformgrenzen auditiert, gezielte Nacharbeit dokumentiert;
  Sicherheitsdoku präzisiert, keine Laufzeitbefunde als behoben ausgegeben.
- Verify the complete release bundle before creating a draft (#186), then reverify at the
  write boundary; bind signatures/attestations to repository, workflow, ref and source/signer
  commit. Trust signed tags only against protected main signers; release writes confined to draft.
  **DE:** Release-Verifikation technisch vor Entwurf erzwingen, Identität/Commit strikt prüfen,
  keine tag-eigenen Vertrauensanker. Bestehende Freigaben und manuelle Veröffentlichung erhalten.
- Mandatory locked secret memory (#148): fail closed on lock failure; typed locked Argon2
  workspace, locked HKDF/HMAC intermediates, AES state and explicit archive/STREAM buffers;
  bounded locked standard password input and generator. Additional copies remain in audit147.
  Existing v1/v2/v3 formats and derivation bytes unchanged.
  Linux needs sufficient existing memlock budget; Windows requests its own working-set capacity.
  Application unsafe prohibition retained; narrow provider patches documented in vendor/README.md.
  **DE:** Secret-Speicher zwingend sperren, keine ungesperrten Fallbacks; KDF-/HKDF-Zwischenwerte,
  explizite Archiv-/STREAM-Puffer und Standard-Passphrase-Eingabe abgesichert, bei
  Ressourcenfehler sicher abbrechen. Weitere Kopien siehe Audit147.

### Changed
- **Weekly preview build no longer runs on pull requests** (#269): only on its weekly schedule and
  by hand; changes to the shared `build.yml` are still built and tested by `release.yml` in pull
  requests. **DE:** Vorschau-Build läuft nicht mehr bei Pull Requests.

### Added
- **`--sign-passphrase-file` (#286):** `encrypt --sign-with` can now also sign passphrase-protected
  files without a terminal: the signing key's passphrase comes from its own file (same rules as
  `--passphrase-file`: regular file, one line, Linux `0600`). Without it the clear usage error stays.
  **DE:** Signieren passphrasegeschützter Dateien auch ohne Terminal.
- **Sender signature in the menu and the context menu (#287):** when encrypting, the menu and the
  context menu (windows and terminal, single and several files) optionally ask "Sign as sender?"
  and the own ML-DSA-87 key; after decrypting, the final message names the verified sender. With
  passphrase protection both password windows write into one pipe to the sandboxed child – the
  context menu process never sees a passphrase. **DE:** Absender-Signatur in Menü und Kontextmenü.
- **Sender signature inside `.pqkf` (#44, U1):** `pqkeep encrypt --sign-with <key.key.json>`
  (optionally `--sign-factor-file`) embeds an ML-DSA-87 signature over the whole header (all
  recipients) and the ciphertext; such files use the new **format v3** (`docs/V3_SIGNED.md`, SPEC
  v2.18). `decrypt`, `check` and `list` always verify signed files before any output and name the
  verified sender (also in `--json` as `signer`); `--signer <pub.json>` requires a specific sender
  (else exit code 7, no output). `inspect` shows the sender as unverified. A key commitment prevents
  a malicious sender from showing recipients different plaintexts. Unsigned files stay v1/v2 byte for
  byte; older releases report v3 files as unsupported. Not offered via the REST API, the menu or the
  context menu yet. **DE:** Absender-Signatur in `.pqkf` (Format v3) mit `--sign-with`, Prüfung beim
  Entschlüsseln/Prüfen, `--signer` erzwingt einen bestimmten Absender.
- **Authenticated archive listing (#117):** explicit `pqkeep list` for current v1/v2 containers;
  bounded metadata after full verification, no extraction/spool, listing-only JSON schema.
  **DE:** Archivnamen/Größen ausdrücklich nach vollständiger Prüfung, ohne Extraktion/Spool;
  begrenzte Metadaten und eigenes JSON, bestehende Formate/Befehle unverändert. See `docs/LIST.md`.
- **Key file passphrase changes (#109):** `pqkeep rekey` preserves key material, identity and v1/v2;
  explicit new output, or confirmed replacement with an exact old encrypted backup. Same factor
  and default KDF; strict publication needs hard links. Old copies are not revoked. See `docs/REKEY.md`.
  **DE:** Passphrase-Schutz erneuern bei gleichem Schlüssel/ID/Format; neue Ausgabe oder bestätigter
  Austausch mit exakter alter Sicherung. Faktor/KDF erhalten, Hardlinks nötig, alte Kopien bleiben nutzbar.
- **Deterministic fault/crash tests (#152):** scoped test-only I/O faults and acknowledged child
  termination/restart tests for keys, factors, archives and authenticated output; v1/v2 unchanged.
  Process termination does not establish OS-crash or power-loss durability.
  **DE:** Testgebundene I/O-Fehler und bestätigte Child-Abbruch-/Neustarttests für Schlüssel,
  Faktoren, Archive und authentifizierte Ausgabe; v1/v2 unverändert. Keine OS-/Stromverlustgarantie.
- **Weekly preview builds** (#269): pre-release `preview-<date>.<commit>` of `main`, built with the same
  workflow as the releases (`build.yml`), never "Latest"; new previews are keyless Sigstore-signed
  with build/SBOM attestations verified before publication (#281). Previews are marked in the
  program (`--version` shows `+preview.<id>`, banner on a terminal, "PREVIEW" in window titles);
  betas and releases are unchanged. See `docs/RELEASE.md`.
  **DE:** Neue Vorschauen mit Sigstore, Build-/SBOM-Attestationen und Prüfung vor Veröffentlichung;
  nie „Latest“, kein SignPath oder Release-Environment. Bestehende Vorschauen unverändert.

### Changed
- Archive path validation rejects later file ancestors independently of entry order, using an
  ordered prefix lookup; valid archives remain compatible. / Archivkonflikte auch bei späteren
  Datei-Vorfahren abweisen, ohne linearen Gesamtscan je Eintrag; gültige Archive bleiben kompatibel.
- Release workflow: build, packages, installation tests and manifest moved into the reusable
  `build.yml`; signing and publishing stay in `release.yml`. The release artifacts are unchanged.
- The root warning is no longer printed in child processes of the window flows (it made a complete
  success look "incomplete" when run as root).

## [0.1.0-beta.3] – 2026-11-19

Third public beta. **Not audited, not FIPS 140 validated – do not use for secrets you cannot afford to lose.**

### Known limitations
- No external audit; cryptographic crates are 0.x versions.
- Files and key files written with a factor file or for several recipients use format v2;
  beta.1 and beta.2 cannot open them. Everything else is still written as v1.
- Windows: no sandbox, no own ACL; binary not yet Authenticode-signed (SmartScreen may warn).
  The new windows and context menu flows were **not hand-tested on Windows** (#259).
- ARM64 with 64 KiB pages is untested (#163).
- See `docs/SECURITY_REVIEW.md` and `docs/THREAT_MODEL.md`.

### Security
- **REST API (`pqkeep serve`): a web page could lock the local user out** (#253). Requests without an
  `Authorization` header counted as failed token attempts, so any page in the browser could send a
  few cross-origin requests to `127.0.0.1:8787` and block the correct token for 15 minutes (no data
  access). Now requests without a token are not counted, browser requests (`Origin` or
  `Sec-Fetch-Site` header) are rejected with 403, and without `--allow-remote` only local `Host`
  values are accepted (DNS rebinding). Found with the test cases added to #151.

### Fixed
- **Free names keep the file extension** (#256): when the target is taken, `encrypt --rename` and
  the context menu now name the result `report (2).txt.pqkf` instead of `report.txt (2).pqkf`, so
  the decrypted file is `report (2).txt` and still opens with the right program. Existing files are
  unaffected. **DE:** Freie Namen behalten die Endung (`bericht (2).txt.pqkf` statt
  `bericht.txt (2).pqkf`).
- **Error message for an existing target** no longer suggests `--force`, which `encrypt`/`decrypt`
  do not have; it names `-o/--out` and `--rename` (#256).
- **Passphrase window says what it is for** (#256): on Linux with zenity the window showed only the
  generic "Password:"; it now shows "Passphrase of the encrypted file" or "Passphrase of your own
  key file" with hidden input, and Enter confirms. **DE:** Das Passphrase-Fenster nennt, wofür
  die Passphrase gebraucht wird.
- **Interrupted `pqkeep integrate install`** (#256): the list of own files is now saved after every
  written file, so an interruption (e.g. closed output) no longer leaves own context menu files
  that later count as foreign and that neither `install` nor `uninstall` would touch.
  **DE:** Abgebrochenes `integrate install` hinterlässt keine „fremden“ eigenen Dateien mehr.
- Small things (#256): the passphrase confirmation in the terminal prints a localised "Fehler:" /
  "Error:" instead of a fixed English "error:"; the Thunar backup name marks its UTC time with a
  `Z` (`uca.xml.pqkeep-bak_2026-11-19_1353Z`).

### Added
- **Security QA baseline (#151):** versioned bilingual attack catalogue with separate execution
  evidence, offline reference/contract validation and existing CI integration. Two replay tests
  characterize readable old valid v1/v2 containers; no freshness or anti-replay protection added.
  Native Linux/Windows CI also executes the no-default-feature suite on one runner per OS.
  **DE:** Versionierter DE/EN-Angriffskatalog mit getrennten Nachweisen, Offline-Verweisprüfung und
  bestehender CI. Zwei Tests belegen lesbare alte gültige v1/v2-Dateien; kein neuer Frische-/Replay-
  Schutz. Native Linux-/Windows-CI führt die No-default-Suite je einmal pro Betriebssystem aus.
- Core groundwork for the planned file format v2 (factor file, several recipients; `docs/V2_DRAFT.md`):
  key derivation with domain separation (Argon2id with the factor file as secret, HKDF-SHA3-256),
  reading/creating factor files (exactly 32 bytes, regular files only, Linux: mode `0600`, too open
  permissions are rejected), the binary v2 header with several access slots (strict, bounded parser;
  byte-exact against the Python reference), and encrypting/decrypting with several slots in the library
  (one passphrase, optionally with factor file, plus up to 64 recipients; a single slot without factor
  file is still written as v1), and key files protected by passphrase and factor file (`*.key.json`
  with `format_version` 2; without a factor file key files stay version 1, byte for byte as before;
  older releases reject version 2 key files as invalid). Nothing changes for existing files.
- **Optional second factor on the command line:** `pqkeep factor --out <path>` creates a factor file
  (32 random bytes, never overwritten, Linux: mode `0600`); `--factor-file <path>` with `generate`,
  `encrypt` (passphrase mode), `decrypt` and `sign` uses it in addition to the passphrase. Only the
  path is passed; the content never appears in arguments, environment or output. Only with this
  option format v2 is written (older releases cannot open such files and keys); without it output
  stays v1. `inspect` shows v2 files and whether a factor file is required. A missing or
  superfluous `--factor-file` is reported before the passphrase prompt (exit code 2), a wrong one
  like a wrong passphrase (exit code 3). The sandbox additionally allows reading exactly this one
  file. **Back up the factor file – without it nothing protected with it can be opened.**
- **Several recipients on the command line:** `--to` may be repeated (up to 64 public ML-KEM keys of
  any level); every recipient opens the file with their own key. `--with-passphrase` adds an own
  passphrase (optionally with `--factor-file`, which with `--to` is only allowed together with
  `--with-passphrase`). Recipients are listed with name and fingerprint and checked before the
  passphrase prompt: duplicates, more than 64 and non-ML-KEM keys are rejected (exit code 2). A single
  recipient without extras still writes v1, byte for byte as before; everything else writes v2, which
  older releases cannot open. Decrypting with a key that is not among the recipients now says so
  clearly. The sandbox additionally allows reading exactly the given `--to` files.
- **Several recipients in the menu and the context menu:** the menu asks for further recipients
  ("empty = done") and then whether to add an own passphrase (optionally with a factor file); the
  context menu (terminal and windows, one or several files) asks "Add another recipient?" after each
  confirmed fingerprint. The choice is now called "For recipients (public keys, one or more)".
- **`pqkeep check <file.pqkf>…`:** checks encrypted files completely (all chunks, checksums and
  archive paths, as when decrypting) without writing anything – for backup checks and monitoring.
  Needs the passphrase or key (`--key`, `--factor-file`, `--passphrase-stdin`/`--passphrase-file`),
  checks every file even if one fails, prints one line per file and a summary. Exit code 0 = all
  fine, 3 = wrong key/passphrase or tampering, 1 = other error, 2 = usage; with several files the
  first error counts. The sandbox only allows reading. Library: `files::check`.
- **`--json` for `check`, `inspect` and `verify`:** exactly one JSON object on stdout with the
  stable, versioned schema `pqkeep-json/1` (`docs/JSON.md`): `schema`, `command`, `ok`, `exit_code`
  plus per-command data; even failures produce valid JSON with `error` (`code`, stable `kind`,
  localized `message`); only argument errors stay text (exit 2). No secrets, no archive-internal
  paths. Exit codes 0–7 are now documented as a stable interface and listed completely in `--help`
  (6 = no windows, 7 = invalid signature were missing). `encrypt` and `decrypt` also accept `--json`:
  `results` per target (source, target, counters, skipped count) and `summary`; with `--each` or
  several files to decrypt every entry is reported, the first error sets the exit code.
- **Factor file in the menu, the guided flows and the context menu:** new menu item "Create factor
  file"; encrypting with a passphrase asks for an optional factor file (context menu: third choice
  "With passphrase and factor file"); decrypting asks for it exactly when the file or your key file
  requires one; guided key generation can use an existing factor file or create a new one, guided
  signing asks for it if the key needs it. These parts only pass the path on – the child process
  with the full sandbox reads the file.

## [0.1.0-beta.2] – 2026-11-12

Second public beta. **Not audited, not FIPS 140 validated – do not use for secrets you cannot afford to lose.**

### Added
- **Linux ARM64** (64-bit, `aarch64`): natively built and tested release archive (glibc ≥ 2.35).
- **Debian packages** (`.deb`) for amd64 and arm64: program, German and English man pages, shell
  completions and licence texts; no maintainer scripts, services or changes to user files. Tested in
  native containers on Debian 12/13 and Ubuntu 22.04/24.04/26.04 (install, upgrade, downgrade,
  removal, purge, rejected packages) – see `docs/INSTALL.md` and `docs/PACKAGE_TESTS.md`.
- Release pipeline: all five artifacts (Linux AMD64/ARM64, Windows, Debian amd64/arm64) carry a
  checksum, build provenance and SBOM attestations and a Sigstore signature; a fixed artifact manifest
  rejects missing, additional, duplicate or wrongly assigned files – see `docs/RELEASE.md`.
- Context menu for **Thunar** (Xfce): `pqkeep integrate install` adds two custom actions to
  `~/.config/Thunar/uca.xml` (multi-selection, window or terminal mode) without touching foreign
  actions; strict layout check, backup before writing, checksums per entry (integration list version 2),
  fully reversible – see `docs/INTEGRATION.md`.
- Guided flows for beginners: creating a key (purpose, strength with NIST category, name and further
  details, protection profile, passphrase, file names), signing and verifying. They start from the menu
  or when `generate`, `sign` or `verify` are called in a terminal without the required input – never
  without a terminal or with `--batch`. Each flow ends by showing the equivalent commands; all commands
  keep working unchanged.
- `pqkeep passphrase --min-bits <128–256>`: the generated passphrase is guaranteed to pass the check
  with the same value (needs 36 characters for 192 bits, 48 for 256).
- Unattended operation: global `--passphrase-file <path>` (one line, Linux owner-only permissions,
  works with systemd `LoadCredential=`) and `--batch` (never prompts) – see `docs/SERVER.md`.
- Context menu with multi-selection: each separately or one container (suggested, freely editable name),
  passphrase once, progress with cancel (unfinished output removed); Windows via "Send to → PQKeep" –
  see `docs/INTEGRATION.md`.
- Several sources at once: `pqkeep encrypt a b folder -o selection.pqkf` (one container, no new format),
  `--each` (each separately, passphrase entered once), `decrypt` of several files, `--rename` for free
  target names – see `docs/FILE_FORMAT.md`.
- File manager context menu on Linux (Nemo, Nautilus, Dolphin): `pqkeep integrate install|uninstall|status`
  (current user only, fully reversible) and the terminal helper `pqkeep context` – see `docs/INTEGRATION.md`.
- Context menu on Linux in window mode: small zenity/kdialog windows instead of a terminal
  (`pqkeep context --dialog`, `integrate install --terminal` to opt out); the passphrase goes through a
  pipe straight into the sandboxed child process – see `docs/INTEGRATION.md`.
- Windows context menu in window mode: launcher `pqkeepw.exe` (no console window, part of the Windows
  package) and PowerShell/Windows Forms windows; console fallback if PowerShell is restricted.
- Explorer context menu on Windows (`HKCU\Software\Classes`, no administrator rights, fully reversible,
  single selection; console window) – see `docs/INTEGRATION.md`.
- Detached file signatures in the library (`pqkeep::sign`): `.pqsig` format v1 with ML-DSA-87 over the
  streamed SHA3-512 of the file – see `docs/SIGNATURE_FORMAT.md`.
- `pqkeep sign` / `pqkeep verify`: detached signatures from the command line; verification prints
  `[VERIFIED]` or `[INVALID]` with the signer's fingerprint, exit code 7 for an invalid signature.

### Changed
- `pqkeep passphrase` now shows the same conservative strength estimate as `pqkeep validate`
  (previously the higher formula value), so both commands agree.
- **New passphrases need at least 128 bits** (was 80) – fit for post-quantum use even without counting
  Argon2id; `--min-bits` (128–256) raises it further. Existing files stay readable. The generator
  now defaults to 32 characters (≈ 210 bits, minimum 24); short form `pqkeep passphrase 40`.

### Known limitations
- No external audit; cryptographic crates are 0.x versions.
- Windows: no sandbox, no own ACL; binary not yet Authenticode-signed (SmartScreen may warn).
- Debian packages: no APT repository (update by installing the newer package); not tested on other
  distributions, on distribution kernels or on kernels with 64 KiB pages.
- See `docs/SECURITY_REVIEW.md` and `docs/THREAT_MODEL.md`.

## [0.1.0-beta.1] – 2026-11-07

First public beta. **Not audited, not FIPS 140 validated – do not use for secrets you cannot afford to lose.**

### Added
- Key generation and storage: ML-KEM-512/768/1024 (FIPS 203), ML-DSA-44/65/87 (FIPS 204), AES-256;
  private keys encrypted with AES-256-GCM under an Argon2id-derived key; integrity-protected metadata;
  public key export with fingerprint.
- File and directory encryption (`.pqkf`): passphrase mode or ML-KEM-768 recipient mode, streaming AEAD,
  safe extraction rules, no partial output.
- Passphrase strength check (NFKC, patterns, word lists, entropy estimate) and generator.
- CLI with interactive menu, bilingual help (English/German), man page and shell completions.
- Local REST API (`/v1/generate`, `/v1/validate`, `/v1/health`) with token stored as hash, rate limit,
  lockout, size and time limits, security headers.
- Hardening: no own `unsafe` code, memory locking, core dumps disabled, `panic = "abort"`, overflow checks;
  Linux sandbox (Landlock + seccomp) for every command, menu actions as separate sandboxed processes.
- Release pipeline: builds for Linux (x86_64, glibc ≥ 2.35) and Windows (x86_64), build provenance and SBOM
  attestations, Sigstore signatures, signed checksums, CycloneDX SBOM.
- Tests: known-answer tests (NIST ACVP, Wycheproof, RFC 9106), property tests, fuzzing (7 targets),
  CodeQL, gitleaks, cargo-deny.

### Known limitations
- No external audit; cryptographic crates are 0.x versions.
- Windows: no sandbox, no own ACL; binary not yet Authenticode-signed (SmartScreen may warn).
- See `docs/SECURITY_REVIEW.md` and `docs/THREAT_MODEL.md`.

[0.1.0-beta.3]: https://github.com/SpecterAoD/pqkeep/releases/tag/v0.1.0-beta.3
[0.1.0-beta.2]: https://github.com/SpecterAoD/pqkeep/releases/tag/v0.1.0-beta.2
[0.1.0-beta.1]: https://github.com/SpecterAoD/pqkeep/releases/tag/v0.1.0-beta.1
