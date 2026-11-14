# GitHub Repository Protection — Manual Verification Checklist (#182)

**State:** proposed settings; live GitHub settings not yet verified or changed.

## Before any changes
1. Capture screenshots or export of current branch protection/rulesets, required checks, Actions permissions, `release` environment and CODEOWNERS recognition.
2. Confirm repository visibility/plan feature availability and a recovery route for sole maintainer.
3. Verify current CI checks have stable names and pass on a test PR.

## Main branch
- Require pull requests for normal contributions where available.
- Require existing passing CI and security checks, but **do not add a required check until it passes**.
- Prevent force pushes and branch deletion.
- Limit bypass privileges; audit all bypass actors.
- Confirm CODEOWNERS paths and behavior; do **not** require a second person to approve when there is only one maintainer.
- Confirm whether GitHub permits self-approval under the selected protection configuration; do not activate a deadlocking setting.

## Sensitive paths
`.github/workflows/**`, `.github/actions/**`, `.github/CODEOWNERS`, `scripts/oc_gate.py`, `scripts/release_*.py`, `scripts/check_actions_policy.py` require review of permissions, event triggers, secret access, external actions and artifacts.

## Release environment
- Verify deployment branch/tag restrictions and required approvals.
- Test a safe manual dispatch and a blocked unauthorized ref **without** publishing a release.
- Confirm ability to stop compromised releases and preserve evidence.

## Verification and rollback
- [ ] Test normal solo-maintainer PR and merge path (without merging security PRs prematurely)
- [ ] Test blocked direct push / force push in disposable branch or repository
- [ ] Test malicious workflow PR with missing checks is blocked
- [ ] Confirm no changes to account authentication or forced PAT migration
- [ ] Retain settings snapshot and documented restore procedure

**Caution:** CODEOWNERS alone does not prevent account takeover; do not claim otherwise. No live ruleset change is made by this document.
