# GitHub Actions Security Monitoring & Incident Runbook

Status: **Design only** (Issue #187). No external monitor is deployed.

## Monitoring architecture

Use a read-only GitHub App installation or fine-grained read-only credential on a host **outside** the repository's Actions runners and security boundary. Restrict access to this repository and required API endpoints. Never store monitoring credentials in PQKeep Actions. Record UTC timestamp, repository, source event, ref, run ID, workflow path, commit SHA, actor ID, decision and a hash of the normalized event; do **not** store secret values or untrusted comment bodies. Store append-only with restricted permissions and a retention policy. Test actual API availability and plan limitations before deployment.

Monitor changes to `.github/workflows/**`, `.github/actions/**`, `.github/CODEOWNERS`, `scripts/oc_gate.py`, release scripts, branch protections/rulesets/environments (when API-accessible), new releases and Actions runs. Compare against an externally retained baseline. Missing run IDs are **signals for investigation, not evidence of deletion**.

## Alerts and response

- Critical: unexpected workflow modification, newly granted write/OIDC permission, release outside approved refs, unexplained environment/ruleset change.
- High: unknown actor modifying protected files, unexpected release asset/digest, unauthorized OpenCode invocation.
- Informational: run ID gaps, failed workflows, expected dependency updates.

Send alerts to a channel outside the repository; deduplicate by event ID and rate-limit. Include links/identifiers, not raw secrets.

## Incident checklist

1. Record alert time and source; preserve external event log, workflow YAML at known commit, SHA and run metadata.
2. Confirm whether the change was authorized; compare against signed/reviewed commits and branch protection.
3. If compromise is plausible, suspend affected workflows or release permissions through an authorized administrator; do not automatically delete evidence.
4. Revoke and rotate **affected** repository/environment credentials after assessing exposure; avoid blind rotation of unrelated credentials.
5. Inspect release assets, provenance, package checksums, PRs, workflow logs and relevant security events. Assume logs may be incomplete.
6. Restore known-good workflows and settings through reviewed changes, verify checks, and document recovery.
7. Record timeline, affected assets, confidence level, remaining uncertainty and corrective actions.

## Acceptance tests (pending implementation)

- [ ] External read-only monitor deployed and credentials scoped to minimum permissions
- [ ] Simulated workflow modification produces an alert
- [ ] Simulated false-positive/run gap does not assert a compromise
- [ ] External event evidence remains available if repository workflow is removed
- [ ] No secrets in logs, notification bodies or artifacts
- [ ] Incident tabletop test performed and documented
- [ ] Tested disable/revoke/restore procedure and rollback for monitor

## Rollback

Disable the independent monitor and revoke only its own read credential. Repository CI and releases must remain unaffected.

## Boundaries

GitHub personal account API/plan may not expose every settings or audit-log event. Do not claim comprehensive visibility. Strong password and existing 2FA remain unchanged; passkeys/hardware keys are optional.
