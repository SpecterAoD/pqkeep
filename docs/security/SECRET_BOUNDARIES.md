# Secret and token boundaries (Issue #183)

Status: verified from repository YAML, **not** verified against live GitHub settings. No secret values accessed.

| Job | Trigger | Token scope | Named secret | Risk / control |
|---|---|---|---|---|
| CI: test, msrv, limits, binary, deny, gitleaks | push main / PR | contents:read | none referenced | PR source code and dependencies are untrusted |
| CodeQL: analyze | push / PR / schedule / dispatch | contents:read, security-events:write, actions:read | none referenced | CodeQL upload permission; do not expose arbitrary shell to write token |
| Release: prepare/build/debian/manifest | tag / dispatch / selected PR paths | contents:read | none referenced | downloaded artifacts require integrity checks |
| Release: publish | tag / dispatch; not PR | contents:write, id-token:write, attestations:write | none referenced | environment release; live protection rules unverified |
| Release: verify | after publish | contents:read, attestations:read | none referenced | verifies released bundle, but **draft creation precedes verification** |
| OpenCode: preflight (feature branch only) | PR paths | contents:read | none | installs npm CLI; no Gemini secret |
| OpenCode: authorize (feature branch only) | issue_comment | contents:read | GEMINI_API_KEY in later step | live owner comment verification; npm CLI receives secret |
| OpenCode: gemini-pr-smoke (feature branch only) | maintainer-owned PR #178 | permissions:{} | GEMINI_API_KEY | no checkout; npm CLI can still access key |

## Required security changes

1. Separate authorization (no secrets) from model invocation (Gemini key); ensure authorization is checked immediately before use and tied to exact comment ID, issue ID and immutable event payload. Track in #184.
2. For any future agent implementation, use an isolated approval stage and a short-lived least-privilege GitHub App token; no automatic write token in analysis.
3. Pin/verify the OpenCode installer and dependencies; treat npm execution as a secret-bearing trust boundary (#185).
4. Review publish permissions, environment rules, and artifact provenance (#186).
5. Use synthetic canary secrets in negative tests, never actual production credentials.
6. Do not place secrets in CLI arguments, artifacts, caches, debug logs or untrusted prompts.
7. Audit live repository/environment secret names and access policies through approved settings access; never read secret values.

## Incident handling

On credible exposure: preserve evidence, disable affected jobs, revoke and rotate **only affected** credentials, inspect runs/releases, restore known-good config. Password/2FA remain unchanged; no mandatory passkeys or blanket PAT migration.

## Acceptance and rollback

- [ ] Live metadata checked (names/scopes only)
- [ ] Fork PR, foreign comment, failed auth cannot access model secret (tested)
- [ ] Synthetic secret cannot appear in logs/artifacts/caches
- [ ] Release/CI regression tests pass
- [ ] Runtime isolation implemented and reviewed

Documentation-only rollback: revert this file. #183 stays open until technical and settings checks pass.
