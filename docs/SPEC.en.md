# MASTER PROJECT SPECIFICATION v2.13: PQKeep (Core, CLI & API) – English translation

> **Translation note:** This is the English translation of [`SPEC.md`](SPEC.md) (German), version
> 2.13. Both versions are maintained together; every change to one is made to the other in the
> same pull request. If they ever contradict each other, the German version applies until the
> difference is fixed – please report it as an issue.
>
> **Übersetzungshinweis:** Englische Übersetzung von [`SPEC.md`](SPEC.md), Version 2.13. Beide
> Fassungen werden gemeinsam gepflegt; bei Widersprüchen gilt bis zur Korrektur die deutsche.

> Change v2.1 (2026-11-06, approved by SpecterAoD): file and folder encryption (section 4a, step 3a).
> Change v2.2 (2026-11-06, approved by SpecterAoD): memory hardening (step 2a), build hardening (`panic = "abort"`, checks for PIE/RELRO/NX and ASLR/DEP/CFG), weekly audit, sandboxing (step 5a), root warning (step 4), timing equalisation for `/v1/validate` (step 5).
> Change v2.3 (2026-11-07, approved by SpecterAoD): planned updates after the first beta (section 9): signatures, multiple recipients, setup wizard, context menu.
> Change v2.4 (2026-11-07, approved by SpecterAoD): word lists for the passphrase check (step 2b), exception from 5c for the EFF word lists (CC BY 4.0).
> Change v2.5 (2026-11-07, approved by SpecterAoD): renamed from "PQC KeyForge" to **PQKeep** (crate, library and binary `pqkeep`, repository `SpecterAoD/pqkeep`) because of a name conflict with the card game "KeyForge". Format identifiers `PQKEEP-KEY`/`PQKEEP-PUB`, domain separation `PQKeep/…`, token prefix `pqk1_`; extension `.pqkf` and `PQKFENC` stay. Before the first release, therefore without compatibility with files of the old name.
> Change v2.6 (2026-11-07, approved by SpecterAoD): step 6 aligned with the implementation – `main` protected by a ruleset without required review (one maintainer; checks via required status checks), official SignPath wording, Linux release build on Ubuntu 22.04, release first as a draft, SignPath action only after approval, gitleaks as a verified binary instead of an action.
> Change v2.7 (2026-11-08, approved by SpecterAoD): U1-1 refined – signature format `.pqsig` v1 (`docs/SIGNATURE_FORMAT.md`): ML-DSA-87 only, SHA3-512 and file size, context string `PQKeep/sig/v1`, a fixed binary encoding is signed instead of JSON, file name not signed, timestamp is a claim of the signer.
> Change v2.8 (2026-11-08, approved by SpecterAoD with the merge of PR #79): format draft v2 for U0 and U2 together (`docs/V2_DRAFT.md`, not implemented at the time): second factor as a factor file with exactly 32 random bytes (Argon2id secret), multiple recipients as an access list (at most one passphrase slot + up to 64 ML-KEM recipients), v2 only when needed; decisions D1–D4 (recipient IDs visible, passphrase and recipients combinable, v2 only when needed, factor file with too open permissions rejected) confirmed on 2026-11-09; TPM/FIDO2 moved out (#89), numbers reserved.
> Change v2.9 (2026-11-09, approved by SpecterAoD): minimum strength of new passphrases raised from 80 to **128 bits** (≥ 64 bits even under an idealised Grover attack without Argon2 protection), selectable up to 256 bits (`--min-bits`); generator 32 characters by default, at least 24; short form `pqkeep passphrase <length>`. Existing files stay readable (check only on creation).
> Change v2.10 (2026-11-09, approved by SpecterAoD): guided flows in the CLI (create key, sign, verify) – in the menu or when `generate`/`sign`/`verify` are called in a terminal without required input; never without a terminal or with `--batch`. They only ask, show the corresponding commands and start them as separate processes with the full sandbox (no second logic, no secrets in the flow process).
> Change v2.11 (2026-11-10, approved by SpecterAoD with the plan for #92): context menu also for Thunar (Xfce) via the shared file `~/.config/Thunar/uca.xml` – only own blocks with fixed identifiers, foreign actions stay byte for byte, strict structure check without an XML crate, backup before writing, checksum per block (manifest version 2).
> Change v2.12 (2026-11-15, approved by SpecterAoD with the "community and structure" project plan): English translation `docs/SPEC.en.md`, maintained together; external contributions may be English only, the German version follows (`CONTRIBUTING.md`).
> Change v2.13 (2026-11-16, approved by SpecterAoD): exception from 5c for documentation images below `docs/images/` (PNG, JPEG, WebP, at most 500 KB per file, signature matching the extension; checked by `scripts/check_limits.sh`).

> Working instruction for Claude Code. This specification is binding. In case of contradictions or gaps: do not guess, ask briefly.

## 0. Way of working (applies to every step)

1. **Plan before code:** Before each step first present a short plan (files, crates, test strategy) and wait for approval.
2. **One step at a time:** A step is done only when `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test` are green. Then summarise and wait for approval again.
3. **Research before choosing a crate:** Check current versions, maintenance status and known advisories of the crates (docs.rs, RustSec). Do not add crates from memory; freeze versions in `Cargo.lock`.
4. **Honesty:** Where a requirement can only be met partially (e.g. `zeroize`), document it openly, do not gloss over it.
5. **Commits:** Small commits, separated by topic, per step.

## 1. Project goal & architecture principles

Highly secure, memory-safe, cross-platform application (Windows & Linux) in pure Rust for **generating, storing and managing** post-quantum keys (ML-KEM, ML-DSA) and symmetric keys (AES-256).

- **No backdoors, minimal attack surface:** Strict input validation (length, character set, format). No telemetry, **no outgoing network connections**. The API only accepts incoming connections.
- **Modular file limits (adapted):** Bilingual comments use many lines, therefore:
  - Production files: at most **300 lines** (physical lines incl. comments and blank lines).
  - Single functions: at most **50 lines**.
  - Test files: at most **400 lines**, one test topic per file.
  - If a file grows too large, split it into submodules (e.g. `crypto/kem.rs`, `crypto/dsa.rs`, `crypto/kdf.rs`, `crypto/aead.rs`). A CI script checks all limits automatically and fails the build on violations.
- **Tests always in separate files:** No `#[cfg(test)] mod tests { ... }` with content in production files. Tests of the public API live in `tests/*.rs`. Tests of internal functions live in their own file next to the module (e.g. `src/crypto/kdf_tests.rs`), included only via `#[cfg(test)] mod kdf_tests;` (one line). The CI script checks that production files contain no test functions (`#[test]`).
- **Bilingualism:** Documentation, READMEs, doc comments and inline comments in German **and** English. Format: `// DE: ...` followed by `// EN: ...`. Error messages for end users (CLI) bilingual or selectable via `--lang de|en`. (External contributions may be English only; see `CONTRIBUTING.md`.)
- **Architecture:** Library (`lib.rs`) as the core, on top of it a binary (`main.rs`) with CLI and API server. CLI and API use only the core API, no duplicated crypto logic.
- **Focus:** First core, then CLI, then API. A GUI is explicitly **not** part of this project (non-goal).
- **Term:** "Passkey" in this specification means a **passphrase** (the user's secret), not WebAuthn/FIDO2 passkeys. Use `passphrase` consistently in code and docs to avoid confusion.

## 2. Threat model (short, recorded in `docs/THREAT_MODEL.md`)

- **Protection goal:** Confidentiality and integrity of stored private keys if the container file is lost or stolen (offline attacker).
- **In scope:** Brute force against the passphrase, manipulated container files, faulty/malicious input (CLI and API), resource exhaustion (DoS) via the API.
- **Out of scope:** Compromised host (malware with memory access, keyloggers), hardware-level side channels. This is stated explicitly in the docs.

## 3. Security & performance requirements

### 3.1 Memory safety
- `#![forbid(unsafe_code)]` in the project. If unavoidable for platform functions (e.g. memory locking): isolated in a single, commented module with justification.
- Secrets (private keys, seeds, derived keys, passphrase) in `Zeroizing<...>` or types with `ZeroizeOnDrop` / `secrecy`. These types implement **no** `Debug`, `Display`, `Clone` or `Serialize` with plaintext output.
- No logging of secrets or request bodies. Secrets/tags compared in constant time (`subtle`).
- Documentation note: zeroisation is "best effort" (copies by the compiler, swap, core dumps). Optional and documented: disable core dumps, lock memory pages.

### 3.2 Cryptography
- **Key exchange:** ML-KEM (FIPS 203), default **ML-KEM-768**, selectable ML-KEM-512/1024.
- **Signatures:** ML-DSA (FIPS 204), default **ML-DSA-65**, selectable ML-DSA-44/87.
- **Private keys** preferably stored as a compact **seed** and re-derived on loading (if the crate supports it), otherwise as an expanded key.
- **Symmetric keys:** Generation of AES-256 keys (32 bytes) from the OS CSPRNG (`getrandom`/`OsRng`).
- **Container encryption:** AES-256-GCM, 96-bit nonce random from the OS CSPRNG, **new salt and new key per encryption**. Header and metadata are authenticated as **AAD**.
- **Key derivation:** Argon2id.
  - Parallelism `p` = available CPU cores (`available_parallelism`, capped, e.g. at most 8).
  - **Important:** `m`, `t`, `p` and salt (≥ 16 bytes) are stored in the container header so that decryption works on different hardware.
  - Lower bounds when creating (e.g. m ≥ 64 MiB, t ≥ 3), upper bounds when reading foreign containers (e.g. m ≤ 1 GiB, t ≤ 10, p ≤ 16) to prevent DoS via manipulated headers.
  - Predefined profiles (e.g. `standard`, `hardened`), values defined centrally in the code.
- **Randomness:** OS CSPRNG only. No `thread_rng` substitute, no own generators.
- **Crypto crates:** Preferably maintained, pure Rust implementations (e.g. RustCrypto `ml-kem`, `ml-dsa`, `aes-gcm`, `argon2`, `zeroize`; alternatively `libcrux`). Justify the choice. Note in the docs: the crates are not FIPS 140 validated.

### 3.3 Passphrase security
- **Required:** at least 16 characters (Unicode characters count, not bytes), upper and lower case letters, digits, special characters.
- **Additionally:** rejection of repetitions/sequences (`aaaa…`, `1234…`), a small built-in blocklist check of common patterns, estimated entropy with a minimum of **≥ 128 bits** (since v2.9; selectable up to 256 bits via `--min-bits`) and feedback on **why** it was rejected.
- **Generator:** Cryptographically secure, **without modulo bias** (rejection sampling), guarantees all character classes, 32 characters by default (≈ 210 bits), at least 24 characters (≥ 128 bits even without confusable characters). Optional: word list variant (Diceware, ≥ 6 words). Entropy is computed and shown as `log2(alphabet size) * length`.
- Input never via command-line arguments or environment variables, only via hidden prompts, stdin or (API) request body.

## 4. Container format (basis for step 3)

- JSON with a **version field** (`format_version`) and a magic/type field. Binary data Base64 (standard alphabet, strictly validated).
- Plaintext metadata (authenticated as AAD): name, organisation, company, department, account type, algorithm ID, creation time (UTC), key ID (fingerprint, e.g. SHA3-256 of the public key), KDF parameters, salt, nonce.
- Encrypted part: private key (or seed). Public key in plaintext.
- Note in the docs: metadata is **not encrypted** (mind personal data).
- Parser: strict length and character set limits, `deny_unknown_fields`, maximum file size, no panics on bad input.
- No paths in the container. Files are written **atomically** (temporary file, then rename), Linux permissions `0600`, on Windows stored in the user profile.

## 4a. File and folder encryption (basis for step 3a)

- **Purpose:** Encrypt and decrypt arbitrary single files and complete folders (recursively) in a quantum-safe way. Part of the core library (`src/files/`, crypto building blocks in `src/crypto/`), used by the CLI. **Not** offered via the REST API (attack surface and DoS risk from large uploads).
- **Key modes:**
  - *Passphrase:* Argon2id (section 3.2, parameters in the header) derives the key that wraps the file key.
  - *Recipient:* ML-KEM (default ML-KEM-768) with a person's public key; shared secret → HKDF-SHA3-256 (context: header) → key that wraps the file key. Initially exactly **one** recipient.
- **File key:** A new random 256-bit key (OS CSPRNG) per encryption, wrapped with AES-256-GCM.
- **Content:** Streaming AEAD following the STREAM construction with AES-256-GCM, chunk size 64 KiB, nonce = random prefix ‖ chunk counter ‖ last-chunk flag. Detects flipping, reordering, removing, truncating and appending chunks. Constant memory use regardless of file size.
- **Header:** magic, `format_version`, mode, KDF parameters and salt or KEM ciphertext, wrapped file key, nonce prefix, chunk size. The whole header is bound as AAD to every chunk. Strict limits when reading (section 4 applies accordingly, downgrade protection).
- **Content checksum:** SHA3-256 of the plaintext (per file for folders) is carried **inside** the encrypted part and checked after decryption (end-to-end check against read/write errors). It is never stored in plaintext because it would allow conclusions about the content.
- **Folders:** A folder becomes **one** encrypted archive (own minimal format: type, relative path, size, content, checksum). File names, count and structure stay hidden. The `tar` crate is not used (history of extraction vulnerabilities).
- **Decryption:** Output first to temporary files, released (renamed) only after full authentication and checksum verification; no partial output on errors. Existing targets are never overwritten.
- **Path safety when extracting:** Rejection of `..`, absolute paths, drive letters/UNC, control characters, Windows reserved names and overly long paths; limits for entries and nesting depth. Symlinks, devices and pipes are not followed when encrypting (skipped and reported) and never created when extracting. In recipient mode anyone with the public key can create valid files; the parser must therefore also safely reject malicious, correctly encrypted archives.
- **Not preserved:** timestamps, owners, permissions (content and structure only). Decrypted files get restrictive permissions (Linux `0600`/folders `0700`).
- **Originals:** are not deleted; secure deletion is unreliable on SSDs (section 5b).
- **Planned extensions (later updates):** mirror mode (folder structure preserved, each file encrypted separately), multiple recipients per file, optional ML-DSA signature of the sender.
- **Documentation:** `docs/FILE_FORMAT.md` (DE/EN), addition to `docs/THREAT_MODEL.md` (visible metadata: approximate size; attacks via manipulated archives).

## 5. Automation & CI/CD (GitHub Actions)

- Triggers: every push and pull request, matrix `ubuntu-latest` and `windows-latest`, Rust stable (+ MSRV job).
- Required jobs: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --locked`, line limit check (max. 300), `cargo audit` or `cargo deny` (advisories, licences, banned crates).
- Workflow hardening: `permissions: contents: read`, actions pinned to commit SHAs, Dependabot for Cargo and Actions, no `pull_request_target`.
- **No secrets** in the repository or in workflows. Tests generate all passphrases and keys dynamically at runtime (generator, temporary directories via `tempfile`). Negative tests may use deliberately weak sample values as test data, but never real or reused secrets.
- Additional checks: secret scanning with push protection (GitHub) and `gitleaks` in CI; test check "no `#[test]` in `src/` except `*_tests.rs`".
- Release and signing: see section 5a.

## 5a. Release signing & supply chain (required for releases **and** betas)

All published artefacts (release, beta, release candidate) must be signed and verifiable. Betas go through the **same** process, only with tag `vX.Y.Z-beta.N` and marked as "pre-release".

- **Trigger:** Only a **signed Git tag** (`v*`) starts the release workflow. Tags are signed locally (SSH or GPG signature). The workflow aborts if the tag signature cannot be verified.
- **Protection of the main branch:** Ruleset on `main`: pull requests only, required status checks, **signed commits required**, linear history, no force pushes, no deletion, `CODEOWNERS`. As long as there is only one maintainer, **0 required reviews** (otherwise the maintainer blocks themselves); third-party contributions are reviewed before merging.
- **Build provenance:** `actions/attest-build-provenance` (GitHub Artifact Attestations, SLSA provenance) for every artefact, Linux and Windows.
- **Keyless signature:** Additionally `cosign sign-blob` (Sigstore, OIDC identity of the workflow). This needs **no** stored private keys, matching the rule "no secrets in the repo".
- **Checksums:** `SHA256SUMS` for all artefacts, itself signed and attached as a release asset.
- **SBOM:** Create a CycloneDX or SPDX SBOM (e.g. `cargo-cyclonedx`), attach it to the release and attest it.
- **Windows binary:** Additionally an Authenticode signature against SmartScreen warnings via the **SignPath Foundation** (free for open source). Azure Artifact Signing (paid) is only the fallback. Credentials (SignPath API token) only as a GitHub environment secret, never in the repo.
  - **Requirements (must remain fulfilled permanently):** public repository, OSI-approved licence (section 5c), **no proprietary code** in the project, multi-factor authentication for all team members on GitHub and SignPath, sign only own binaries, build exclusively via GitHub Actions from the public repository (origin verification).
  - **Required notice** (after approval) in README and release notes, official wording: "Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org)" and the "Code signing policy" page with team roles and privacy statement (`CODE_SIGNING_POLICY.md`).
  - **Until approval:** The place for the signature (before packaging) is reserved in the workflow; the SignPath action is only added after approval because it needs SignPath's project data. Without it, Windows artefacts are published unsigned but still protected by attestation, Sigstore and checksum. The README then points out the SmartScreen warning.
- **Hardening of the release job:** Own job with GitHub environment `release` (required reviewer), permissions only there: `contents: write`, `id-token: write`, `attestations: write`. All other jobs: `contents: read`. Actions pinned to commit SHAs.
- **Reproducibility:** `cargo build --release --locked`, `--remap-path-prefix`, fixed `SOURCE_DATE_EPOCH`; archives with fixed order and fixed timestamps. Goal: identical hash on repetition (as far as possible, document deviations). Linux build on Ubuntu 22.04 (glibc 2.35) for broad compatibility.
- **Publication:** The workflow creates a release **draft**; the maintainer publishes it by hand after the verification job is green (procedure: `docs/RELEASE.md`).
- **Verification instructions** (bilingual in the README): `gh attestation verify <file> --repo <owner>/<repo>`, `cosign verify-blob ...`, `sha256sum -c SHA256SUMS`, checking the Authenticode signature on Windows.
- **Tests:** Dry run of the release workflow with a beta tag; a verification job downloads the created artefacts and checks attestation, signature and checksum automatically.

## 5c. Licence & open-source purity

- **Licence (fixed):** **Apache License 2.0** (OSI-approved, contains a patent clause, suitable for cryptography). File `LICENSE` (full text) and `NOTICE` in the repo root, `license = "Apache-2.0"` in `Cargo.toml`. All dependencies must be compatible with Apache-2.0 (allowlist in `deny.toml`, e.g. Apache-2.0, MIT, BSD-2/3-Clause, ISC, Unicode-3.0; GPL/AGPL dependencies are excluded).
- **Exception (approved 2026-11-07):** The EFF word lists (data, not software) are licensed under **CC BY 4.0** (not an OSI licence). They are shipped as data files under `data/wordlists/` with attribution in `NOTICE`. All other word lists are under OSI licences (MIT, BSD-3-Clause). Lists with "non-commercial" clauses (e.g. CC BY-NC) remain excluded.
- **No proprietary code:** Neither in own code nor in dependencies, vendor directories, binary blobs or embedded resources. No precompiled binaries in the repo. **Exception (v2.13):** own documentation images below `docs/images/` (PNG, JPEG, WebP, at most 500 KB per file), licensed like the project.
- **Automatic check:** `cargo deny` with a licence allowlist (only OSI-approved, compatible licences), ban on unknown registries/Git sources and check for crates without a licence. Additionally a check that no binary files are committed (except the images below `docs/images/`, whose extension, size and file signature are checked).
- **Contributions:** `CONTRIBUTING.md` (DE/EN) stating that submitted code is under the same licence and must not contain proprietary code.
- **Documentation:** Licence and code signing notice in the bilingual README.

## 5b. Further security measures

- **Passphrase normalisation:** Unicode **NFKC** before derivation, otherwise the same passphrase could lead to different keys on Windows and Linux.
- **Optional second factor:** Include a keyfile or "pepper" (separate file) in the derivation in addition to the passphrase.
  - Factor file (32 random bytes) as Argon2id secret, see [V2_DRAFT.md](V2_DRAFT.md); implemented in the core, on the command line (`pqkeep factor`, `--factor-file`) and in menu, guided flow and context menu, v1 unchanged.
- **Downgrade protection:** Containers with too old a `format_version` or too weak KDF parameters are rejected or opened only with an explicit warning/confirmation.
- **Check file permissions on loading:** On Linux a warning for `group/world`-readable containers. On Windows storage in the user profile with a restricted ACL.
- **No clipboard, no history:** Passphrases are never copied to the clipboard automatically, never passed as an argument (shell history) and not shown in the terminal (exception: generator, only on explicit request).
- **Core dumps and swap:** Disable core dumps for the process and lock memory pages holding secrets (`mlock`/`VirtualLock`), only in an isolated, commented module. Document honestly: this is best effort.
- **Compiler/linker hardening:** `overflow-checks = true` also in release, `lto`, `codegen-units = 1`, `strip`, `panic = "abort"` (release only; destructors do not run on panic – acceptable because core dumps are disabled). Linux: PIE, full RELRO (`-z relro -z now`), NX stack. Windows: ASLR (high entropy), DEP, Control Flow Guard. A CI job checks these properties on the built release binary (`scripts/check_binary.py`).
- **Supply chain:** `cargo deny` with allowlists for licences and sources, plus a weekly scheduled advisory run (`.github/workflows/audit.yml`), as few dependencies as possible, optionally `cargo vet`, OpenSSF Scorecard workflow, Dependabot, 2FA for all maintainers.
- **Fuzzing:** `cargo-fuzz` for container parsers and API input, regularly via a scheduled workflow.
- **API additionally:** Optional TLS (rustls) with modern cipher suites, token stored only as a hash, lockout after repeated failed attempts, security headers, no CORS by default.
- **Backup and rotation:** Docs on backing up containers, key rotation and expiry. Note: secure deletion on SSDs is unreliable, therefore encryption instead of deletion as the protection principle.
- **Optionally evaluate:** Hybrid schemes (e.g. X25519 + ML-KEM) for the transition period, with the decision documented.

## 6. Directory structure (proposal)

```
pqkeep/
├─ Cargo.toml / Cargo.lock / deny.toml / rust-toolchain.toml
├─ src/  lib.rs  main.rs  error.rs  security.rs  envelope.rs  cli.rs  api.rs
│        crypto/ (mod.rs, kem.rs, dsa.rs, kdf.rs, aead.rs, stream.rs, wrap.rs)
│        files/  (mod.rs, format.rs, archive.rs, paths.rs)
├─ tests/  integration_*.rs   (+ tests/kat/ for known-answer tests, tests/cli_help.rs)
│        (internal tests: src/**/<module>_tests.rs, included only via #[cfg(test)] mod)
├─ scripts/  check_limits.sh  (line limits, no #[test] in production files)
├─ docs/  THREAT_MODEL.md  FORMAT.md  FILE_FORMAT.md  CRYPTO.md
├─ README.md (DE/EN)  SECURITY.md  CONTRIBUTING.md  CODE_SIGNING_POLICY.md
├─ LICENSE (Apache-2.0)  NOTICE  CLAUDE.md  docs/ROADMAP.md  docs/CHECKLIST.md
└─ .github/workflows/ci.yml  dependabot.yml
```

## 7. Roadmap (step by step)

Each step is completed only after a green `cargo test` and approval. At most 300 lines per file.

### Step 0: Project skeleton
- Task: Cargo project, lints (`forbid(unsafe_code)`, Clippy configuration), `error.rs` (`thiserror`, no secrets in error texts), CI skeleton with line limit check.
- Test: empty build and lint on both platforms.

### Step 1: Core crypto (`crypto/`)
- Task: ML-KEM and ML-DSA key generation, AES-256 key generation, Argon2id derivation, AES-256-GCM encryption/decryption of the private key.
- Tests:
  - Roundtrip: generate, encrypt, decrypt with the correct passphrase; KEM encaps/decaps and sign/verify work with the restored key.
  - Failure on a wrong passphrase, on every single manipulated byte (ciphertext, tag, nonce, salt, AAD/metadata) and on truncated data.
  - Known-answer tests (NIST test vectors) for ML-KEM/ML-DSA, as far as the crate allows.
  - KDF limits: too weak and too high parameters are rejected.
  - Zeroize: type-level test that all secret types are `ZeroizeOnDrop`/`Zeroizing`, plus a test that `zeroize()` actually zeroes the buffer. Honest docs on the limits.
  - Nonce uniqueness over many encryptions.

### Step 2: Validation & passphrase (`security.rs`)
- Task: strength check (section 3.3), entropy estimation, generator.
- Tests: weak passphrases are rejected with a comprehensible reason (too short, missing classes, patterns, blocklist); strong ones are accepted; over N runs the generator always returns valid, mutually different values with the expected length and class coverage; the entropy value matches the formula; Unicode edge cases.

### Step 2a: Memory and process hardening (`hardening/`)
- Task: lock memory pages holding secrets (mlock/VirtualLock, page counter), core dump block and "not dumpable" (Linux), immediate zeroing after use; without own `unsafe` code. Details: `docs/MEMORY_HARDENING.md`.
- Tests: lock/unlock, shared pages, continuing when locking is forbidden, core dump limit.

### Step 2b: Word lists and word model (`security/dictionary.rs`)
- Task: entropy estimation by the word model (letter sequences at most like words, list words ≈ 12.9 bits, digits log2(10), repeated separators 1 bit) with embedded word lists (EFF, BIP-39, German Diceware lists); reason "consists mostly of words".
- Tests: compound words are rejected (e.g. "FIPS-140-validiert"), long sentences and random characters accepted, formula values recomputed.

### Step 3: Container (`envelope.rs`)
- Task: structure (section 4), serialisation, deserialisation, validation of the metadata.
- Tests: roundtrip; rejection of unknown fields, wrong version, oversized or badly encoded data; path conventions Windows (`C:\Users\...`, backslashes) and Linux (`/home/...`) via `PathBuf` and `tempfile`; atomic writing; file permissions on Linux; fuzz test or property test (`proptest`) for the parser (no panics).

### Step 3a: File and folder encryption (`files/`, `crypto/stream.rs`, `crypto/wrap.rs`)
- Task: implement section 4a: streaming AEAD, wrapping the file key (passphrase, ML-KEM recipient), header, archive format for folders, path check, atomic output, content checksum.
- Tests: roundtrip of empty, small, chunk-aligned and large files (several chunks); folders with subfolders, empty folders and Unicode names; manipulation of every header byte and of chunks (flip, reorder, truncate, append); wrong passphrase or wrong key; malicious archives (path traversal, absolute and Windows paths, symlink entries, too many entries, wrong checksum); no partial output on errors; an existing target is not overwritten; property tests for header and archive parsers (no panics).

### Step 4: CLI (`cli.rs`, `clap` + `dialoguer`)
- Task: interactive menu **and** non-interactive subcommands (`generate`, `validate`, `inspect`, `export`, `passphrase`, `encrypt`, `decrypt`, `help`). Hidden passphrase input, confirmation before overwriting, output only to paths chosen by the user (path validation).
- **Least privilege:** The CLI needs no administrator/root rights and prints a clear warning when started with such rights. First call at startup: `hardening::harden_process()`.
- **Built-in help (bilingual DE/EN, via `--lang de|en`, default from the system locale):**
  - `--help` and `-h` globally and per subcommand, each with description, parameters, examples and exit codes.
  - `pqkeep help <topic>` with topics: `passphrase` (rules and generator), `files` (file/folder encryption, modes, limits), `algorithms` (ML-KEM/ML-DSA/AES, parameter sets), `container` (format and metadata), `security` (security notes and limits), `verify` (verifying release signatures).
  - In the interactive menu an entry "Hilfe / Help" and context-specific short hints for every input (e.g. passphrase rules, note on plaintext metadata).
  - Man page (`clap_mangen`) and shell completions (`clap_complete`, bash/zsh/fish/PowerShell) are generated via the subcommands `pqkeep completions <shell>` and `pqkeep man`, without network access.
- Tests (in separate files): simulated input (integration tests with `assert_cmd`), successful export of the container, re-reading and decrypting, clean error messages on invalid input, exit codes. Help tests: every subcommand and every help topic returns text in **both** languages, `--help` contains at least one example, no help text contains sample secrets that look like real credentials.

### Step 5: API (`api.rs`, Axum)
- Task: endpoints `POST /v1/generate`, `POST /v1/validate`, `GET /v1/health`. Strict JSON schemas. File/folder encryption (section 4a) is deliberately **not** available via the API.
- Hardening: default bind **127.0.0.1**, binding to other interfaces only explicitly and with a warning (document TLS termination by a reverse proxy); authentication by token from file/environment (constant time); body size limit, timeouts, rate limiting; Argon2 work in `spawn_blocking` with a semaphore (limit on parallel KDF jobs against DoS); no secrets in logs; generic error responses without internal details. `/v1/validate` pads every response to a fixed minimum duration so that the response time allows no conclusions about the structure of the passphrase (the check itself is not constant-time). Token comparison in constant time (`subtle`).
- Tests: HTTP integration tests for all endpoints (success, invalid input, missing auth, oversized bodies, manipulated containers, concurrency limit).

### Step 5a: Sandboxing (Linux)
- Task: restrict privileges after startup. **Landlock**: file access only to the paths chosen by the user (CLI) or configured paths (API). **Seccomp-BPF**: only required system calls; in the CLI no network, no `execve`, no `ptrace`; the API additionally only `accept` on its own socket. Separate profiles for CLI and API, derived from the system calls actually used (incl. Argon2 threads). Older kernels without Landlock: warning instead of abort. Windows: no equivalent mechanism without major effort (AppContainer) – documented.
- Tests: forbidden accesses (file outside the allowed set, network in the CLI, `execve`) fail; normal flows (generate, encrypt/decrypt, API requests) work unchanged.

### Step 6: CI/CD & documentation
- Task: complete `ci.yml` (section 5), `release.yml` with signing (section 5a), `SECURITY.md` (reporting channel), `THREAT_MODEL.md`, `FORMAT.md`, bilingual `README.md` (installation, usage, security notes, limits, release verification).
- Tests: workflow runs green on Linux and Windows; beta dry run of the release workflow including automatic verification of attestation, signature and checksum; documentation examples are run as doctests or smoke tests.

### Step 7: Final review
- Task: security self-review (checklist: secrets in logs/errors, `unwrap`/`expect` in production paths, panics, parameter limits, dependency tree, measures from 5b implemented), `cargo audit`/`deny` without open findings, publish the first signed beta (`v0.1.0-beta.1`) and reproduce the verification according to the instructions.

## 9. Planned updates (after `v0.1.0-beta.1`)

Each update is its own step with plan, approval, tests and Definition of Done. Order by dependencies.

### U1: Digital signatures (ML-DSA-87)
- Sign a file with one's own private ML-DSA key; detached signature file (`<file>.pqsig`) with format version, algorithm, key ID of the signer, SHA3-512 of the file, timestamp, context string and signature. Large files are hashed streaming (not loaded into memory). Format: `docs/SIGNATURE_FORMAT.md` (v1, ML-DSA-87 only; file name not signed; timestamp is a claim of the signer).
- Verify with the public key: output clearly `[VERIFIED]` or `[INVALID]` (exit code 0 or ≠ 0); display of the signer's key ID/fingerprint.
- **Honest assessment:** The signature proves that the file is unchanged and was signed by the holder of the private key. Who that holder is must be confirmed via the fingerprint through a second channel. It is **not** a qualified electronic signature under eIDAS (that would require a qualified certificate and a trust service provider); it is therefore not "legally binding" in the legal sense.
- Extension for `.pqkf`: optional sender signature in the container (replaces the earlier entry "optional ML-DSA signature of the sender").

### U2: Multiple recipients (multi-recipient container)
- One random AES-256-GCM file key (as before); in the header one entry per recipient (ML-KEM encapsulation, default ML-KEM-1024, recipient ID, wrapped key). Each recipient opens with their own private key; no shared password.
- Limits: maximum number of recipients (e.g. 64), new `format_version` with downgrade protection, tests for every recipient, wrong/missing recipients, manipulated entries.
- Decision in the plan: recipient IDs visible (quickly finding one's own entry) or hidden (trial decryption, more privacy). Draft together with U0: [V2_DRAFT.md](V2_DRAFT.md) (proposal: visible).
  - Implemented in the core (#46) and on the command line (#47): repeated `--to` (up to 64, any ML-KEM level), optionally with an own passphrase (`--with-passphrase`, also with a factor file); a single recipient stays v1. Menu and context menu ask "another?" after each confirmed recipient; only the menu offers the additional own passphrase.

### U3: Setup wizard (console)
- On first start a coloured, interactive console wizard (terminal UI crates, chosen in the plan): 1. secure master passphrase (rules from 3.3, Argon2id), 2. own key pair ML-KEM-1024 (encryption) and ML-DSA-87 (signatures), 3. optionally register the context menu (U4), 4. introduction and emergency backup (copy of the key files to a chosen location, notes on safe storage, test restore).
- Storage in the user profile (Linux `~/.local/share/pqkeep`, Windows `%APPDATA%\PQKeep`), permissions as in section 4. Can be run again (`pqkeep setup`), never overwrites without confirmation.

### U4: Context menu (right-click) with passphrase dialog
- Actions "Secure with PQC" / "Decrypt PQC" (later "Sign"/"Verify") in the file manager. Registration only at user level, without administrator rights, fully reversible: Windows `HKCU\Software\Classes\…\shell`; Linux Nemo actions (Cinnamon/Mint), Nautilus scripts, Dolphin service menus, Thunar actions (`uca.xml`, Xfce).
- Without a terminal a small input window for the passphrase opens. **Deviation from section 1 ("GUI is a non-goal"):** only this dialog, no application interface; implementation decided in the plan (e.g. existing system tools such as `zenity`/`kdialog` on Linux or a minimal native dialog on Windows). The passphrase is passed only via pipe/memory, never via arguments or environment variables.

### Further updates
- Mirror mode for folders (structure preserved, files encrypted separately).
- Diceware generator with an own or public-domain word list (DE/EN), no CC BY list (section 5c).

## 8. Definition of Done (per step)

- [ ] Production files ≤ 300 lines, functions ≤ 50, test files ≤ 400; tests only in separate files
- [ ] Comments/docs/help texts bilingual (DE/EN)
- [ ] `fmt`, `clippy -D warnings`, `cargo test --locked` green on Linux **and** Windows
- [ ] No hard-coded secrets, no `unwrap()`/`expect()` in production code
- [ ] Negative and boundary tests present, not only the success case
- [ ] Short summary: what was built, what was tested, known limitations
