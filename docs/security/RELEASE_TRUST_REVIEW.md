# Release trust chain review (Issue #186)

Status: repository workflow inspection only. No release triggered or published.

## Observed flow

1. `prepare`: checks signed annotated tag with `git verify-tag` against `.github/allowed_signers`, compares tag to Cargo.toml version, requires release notes.
2. `build`: Linux/Windows/ARM builds with `--locked`; produces packages, SBOMs and artifacts.
3. `debian`, `manifest`: package and assemble `release-input` artifact.
4. `publish`: environment `release`, `contents:write`, `id-token:write`, `attestations:write`; downloads release-input, creates attestations, hashes, Sigstore bundles, uploads release-bundle and creates a **draft** release on tags.
5. `verify`: after publish, checks manifest, SHA256SUMS, GitHub attestations and Sigstore signatures.

## Important ordering gap

`publish` can create the draft release **before** `verify` succeeds. It is not automatically published to end users, but draft assets exist before final verification. Recommend splitting privileged staging from draft-release creation: build -> stage/sign -> verify -> create draft. The final draft step should use `contents:write`; signing/staging should avoid this write permission where possible. Separate PR and dry-run tests are mandatory before changing release behavior.

## Verification checklist

- [ ] Confirm live `release` environment branch/tag restrictions, reviewers, self-approval and bypass settings
- [ ] Confirm release-input artifact comes from same run and expected commit; validate manifest and digests before attest/sign
- [ ] Negative tests: wrong ref/tag signature, wrong manifest digest, swapped PR artifact, missing SBOM/signature
- [ ] Ensure `workflow_dispatch` never creates GitHub Release
- [ ] Verify attestations bind repository, workflow identity, ref and expected commit; check keyless certificate identity
- [ ] Run tag/release smoke test in safe staging repository without publishing production assets
- [ ] Keep compatibility with existing #144 and #154; no duplicate update-verifier or QA implementation

## Rollback

Revert each staging/verification/draft workflow step separately; retain previous tested release workflow. Never remove existing signatures/attestations without replacement.

## Current residual risk

Repository-controlled build inputs, artifact transfers, and environment settings remain privileged trust boundaries. The repository file alone cannot prove live GitHub settings.
