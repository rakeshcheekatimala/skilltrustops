# Security and operational best practices

## Governance

- Assign owners for `skilltrustops.yaml`, each `SKILL.md`, and each behavioral
  manifest.
- Require code-owner review for policy weakening, tool contract changes,
  approval-state changes, and sandbox changes.
- Keep the policy and behavioral manifest in version control. Keep credentials
  out of both.
- Record why red-team testing was required or explicitly waived for each release.

## Safe defaults

- Use `recommended-v2` with lint, security, and privacy enabled.
- Keep all dangerous-code blocks enabled.
- Use the built-in secret scanner everywhere; add Gitleaks for defense in depth.
- Scan first, red-team second. Do not use a model run to excuse a static finding.
- Treat unknown configuration, scanner errors, and `inconclusive` results as
  release failures.

## Behavioral manifest quality

- Model every real tool explicitly; never infer a security boundary from prose.
- Use least-privilege authorization and require confirmation for consequential
  effects.
- Use only synthetic records and unique canaries. Never seed test fixtures with
  production secrets or customer data.
- Include negative tests across tenants/users and test both direct and indirect
  prompt injection.
- Keep forbidden markers specific enough to avoid meaningless false positives.
- Regenerate and re-review after every `SKILL.md` change.

## Provider and secret handling

- Put local credentials in `.env`, which must remain ignored, or use a managed CI
  secret store.
- Use short-lived, least-privilege provider credentials where available.
- Restrict live test models to an approved allowlist and prefer pinned snapshots.
- Assume prompts and outputs leave the local machine during live provider runs;
  verify organizational data-handling requirements before execution.
- Never print, commit, embed, or archive API keys in evidence.

## Sandbox operation

- Use Docker for development feedback, not certification.
- Use gVisor on a hardened Linux runner with a configured `runsc` runtime for the
  stronger supported boundary.
- Pin sandbox images by digest for durable evidence and review image updates.
- Do not mount the Docker socket or grant additional capabilities.
- Preserve the repository-controlled non-root identity and resource limits.
- Patch and monitor the host, container runtime, gVisor runtime, and base image.

## CI release gate

A high-confidence pipeline should:

1. validate `skilltrustops.yaml`;
2. run `lint`, `security`, and `privacy` for every changed skill;
3. verify the behavioral manifest is current and approved;
4. run reference fixtures to validate harness wiring;
5. run the approved live model for risk-relevant skills;
6. fail on exit codes `1`, `2`, or `3`;
7. retain the complete evidence directory in access-controlled artifact storage;
8. publish the package, policy hash, model identity, and evidence run ID in the
   release record.

Example shell gate for one skill:

```bash
set -euo pipefail

uv run skilltrustops policy validate
uv run skilltrustops lint path/to/SKILL.md --format json
uv run skilltrustops security path/to/SKILL.md --format json
uv run skilltrustops privacy path/to/SKILL.md --format json
uv run skilltrustops redteam run path/to/SKILL.md \
  --provider openai \
  --model "${SKILLTRUST_OPENAI_MODEL}" \
  --format json
```

Do not append `|| true` to security gates. Exit code `3` is an explicit
fail-closed outcome, not a warning.

## Evidence retention

- Store the entire run directory; individual files are not a complete record.
- Verify hashes before promotion and audit.
- Restrict read access because prompts and outputs can contain sensitive-looking
  test content or reveal defensive logic.
- Define retention by release criticality and regulatory obligations.
- Link remediation commits and rerun evidence to each blocked assessment.

## Scope statements

Communicate results precisely. A defensible statement is:

> The recorded package resisted the recorded attacks with the recorded model,
> harness, policy, and isolation boundary at the time of testing.

Avoid claiming that an `passed_scope` decision proves safety across all models,
future attacks, frameworks, real tool implementations, or production systems.
