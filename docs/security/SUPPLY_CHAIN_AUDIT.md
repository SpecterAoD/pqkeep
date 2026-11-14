# Supply-chain and egress audit (Issue #185)

Status: preliminary assessment. No firewall, proxy or runner isolation is currently deployed by this change.

| Component | Existing observed control | Open risk |
|---|---|---|
| actions/checkout, upload/download-artifact, CodeQL, attest, cosign-installer | full 40-character SHA refs in inspected workflows | publisher/runner compromise; verify updates and action provenance |
| gitleaks archive | pinned version and SHA-256 checksum in CI | source host availability, future hash updates |
| cargo-deny | cargo install --locked, fixed version | downloaded crates/build scripts execute on runner |
| cargo-cyclonedx | cargo install --locked, fixed version | same; build-time dependency execution |
| OpenCode npm CLI (feature branch) | version @2.2.7 | npm package contents and transitive dependencies not independently verified; lifecycle scripts |
| Rust project | Cargo.lock and --locked | dependency advisories, malicious upstream, build scripts |
| GitHub-hosted runner | ephemeral hosted VM | outbound HTTP/DNS are **not** assumed blocked |

## Required work

- [ ] Inventory every external action and runtime download in all branches; record publisher, SHA/version, digest and purpose
- [ ] Check npm package integrity from a committed lockfile and trusted registry metadata; consider immutable prebuilt digest, no lifecycle scripts where compatible
- [ ] Test checksum failure and unauthorized download using synthetic fixtures
- [ ] Run actionlint/zizmor and dependency review alongside existing cargo-deny/gitleaks/CodeQL without duplicating reports
- [ ] Measure actual outbound destinations of secret-bearing jobs in test mode
- [ ] Evaluate isolated runner/proxy with explicit allowlist, including DNS and indirect exfiltration channels; document operational feasibility
- [ ] Introduce egress enforcement only after a tested non-blocking observation phase and explicit approval
- [ ] Ensure Linux, Windows and ARM builds pass

## Rollback

Restore previous dependency installation in isolated PR; disable only newly added network policy, not existing CI security checks.

**Risk:** Without enforced egress controls, a compromised dependency executing with a secret can transmit that secret. Version pinning alone does not eliminate this.
