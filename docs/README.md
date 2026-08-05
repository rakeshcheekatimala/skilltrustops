# SkillTrustOps documentation

This documentation is organized around the lifecycle of an AI agent skill:
configure the repository, run deterministic checks, perform behavioral testing
when risk warrants it, and retain evidence for review.

## Choose a guide

1. Start with [Getting started](getting-started.md).
2. Create the trusted repository configuration with the
   [Policy guide](policy-guide.md).
3. Review the [Security scan](security-scan.md) coverage and limits.
4. Use [Red-team testing](red-team-testing.md) before releasing skills that
   process untrusted content, access sensitive data, call tools, or perform
   consequential actions.
5. Apply the controls in [Security best practices](security-best-practices.md)
   to local and CI operation.
6. Use the [Policy reference](policy-reference.md) for exact schema details and
   [Troubleshooting](troubleshooting.md) when a command fails closed.
7. Add [Git hooks](git-hooks.md) for local feedback and use
   [exit codes and rule compatibility](exit-codes-and-rules.md) for CI, SARIF,
   baselines, and suppressions.
8. Review [Project assurance](project-assurance.md) to verify the library's own
   test, coverage, security, package, and release evidence.

## Trust model

SkillTrustOps separates two kinds of evidence:

| Layer | Commands | Network | Executes submitted code | Purpose |
| --- | --- | --- | --- | --- |
| Deterministic static checks | `lint`, `security`, `privacy` | No | No | Find specification, secret, dangerous-code, and PII violations. |
| Behavioral red team | `redteam init`, `redteam run` | Only for a live model provider | No | Test how a selected model behaves under adversarial input using fake tools and synthetic records. |

The Phase 1 behavioral package contains exactly one regular, non-symlink
`SKILL.md` and one adjacent `skilltrust-package.yaml`, `.yml`, or `.json`.
Submitted scripts, containers, framework code, and tool implementations are not
executed.

## Configuration files

Do not confuse the two YAML files:

| File | Owner | Purpose |
| --- | --- | --- |
| `skilltrustops.yaml` | Repository security owner | Trusted policy for static checks and sandbox defaults. |
| `skilltrust-package.yaml` | Skill maintainer, then reviewer | Behavioral capabilities, fake tools, synthetic fixtures, and attacks for one skill. |

Some teams casually call the first file `policy.yaml`. SkillTrustOps does not
discover that filename. Use `skilltrustops.yaml`, `skilltrustops.yml`, or
`skilltrustops.json`, or pass another supported file explicitly with
`--policy`.

## Security boundary

- Repository policy is selected from the current trusted Git repository, not
  from the directory containing an untrusted skill.
- Static checks remain local.
- Live red-team runs send the skill and attack context to the selected model
  provider.
- Simulated tools cannot perform external side effects.
- Docker is a development boundary and cannot produce `passed_scope` by itself.
- A clean result is `passed_scope` only for the exact scope recorded in evidence.
