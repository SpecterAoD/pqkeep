# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning: [Semantic Versioning](https://semver.org/) (pre-1.0: formats and options may still change).
German release notes: see `docs/releases/`.

## [Unreleased]

### Added
- Core groundwork for the planned file format v2 (factor file, several recipients; `docs/V2_DRAFT.md`):
  key derivation with domain separation (Argon2id with the factor file as secret, HKDF-SHA3-256),
  reading/creating factor files (exactly 32 bytes, regular files only, Linux: mode `0600`, too open
  permissions are rejected), the binary v2 header with several access slots (strict, bounded parser;
  byte-exact against the Python reference), and encrypting/decrypting with several slots in the library
  (one passphrase, optionally with factor file, plus up to 64 recipients; a single slot without factor
  file is still written as v1), and key files protected by passphrase and factor file (`*.key.json`
  with `format_version` 2; without a factor file key files stay version 1, byte for byte as before;
  older releases reject version 2 key files as invalid). **Not usable from the command line yet**; nothing changes for existing
  files.

## [0.1.0-beta.2] – 2026-11-12

Second public beta. **Not audited, not FIPS 140 validated – do not use for secrets you cannot afford to lose.**

### Added
- **Linux ARM64** (64-bit, `aarch64`): natively built and tested release archive (glibc ≥ 2.35).
- **Debian packages** (`.deb`) for amd64 and arm64: program, German and English man pages, shell
  completions and licence texts; no maintainer scripts, services or changes to user files. Tested in
  native containers on Debian 12/13 and Ubuntu 22.04/24.04/26.04 (install, upgrade, downgrade,
  removal, purge, rejected packages) – see `docs/INSTALL.md` and `docs/issue-93-testmatrix.md`.
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

[0.1.0-beta.2]: https://github.com/SpecterAoD/pqkeep/releases/tag/v0.1.0-beta.2
[0.1.0-beta.1]: https://github.com/SpecterAoD/pqkeep/releases/tag/v0.1.0-beta.1
