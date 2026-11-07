# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning: [Semantic Versioning](https://semver.org/) (pre-1.0: formats and options may still change).
German release notes: see `docs/releases/`.

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

[0.1.0-beta.1]: https://github.com/SpecterAoD/pqkeep/releases/tag/v0.1.0-beta.1
