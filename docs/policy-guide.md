# Repository policy guide

The repository policy is the trusted, version-controlled configuration for
SkillTrustOps. Its conventional filename is `skilltrustops.yaml`.

## Create a policy

Run this command from the repository root:

```bash
uv run skilltrustops policy init \
  --profile recommended-v2 \
  --format yaml
```

The command creates `skilltrustops.yaml` and refuses to overwrite an existing
file. To create JSON or use another destination:

```bash
uv run skilltrustops policy init \
  --profile recommended-v2 \
  --format json \
  --output /tmp/skilltrustops.json
```

## Recommended enterprise baseline

```yaml
version: 1
profile: recommended-v2

checks:
  lint:
    enabled: true
    ruleset: agent-skills-specification

  security:
    enabled: true
    secrets:
      enabled: true
      scanners:
        - engine: builtin
          enabled: true
    dangerous_code:
      enabled: true
      engine: ast
      block_eval: true
      block_destructive_shell: true
      block_remote_pipe: true

  privacy:
    enabled: true
    pii:
      enabled: true
      engine: builtin
      entities:
        - email
        - phone
        - ssn
        - credit_card

redteam:
  sandbox:
    provider: docker
    image: alpine:3.20
    timeout_seconds: 90
    pids_limit: 64
    memory: 256m
    cpus: 1.0
    user_id: 65532
    group_id: 65532
    tmpfs_size_mb: 16
```

Docker is useful for development but is deliberately non-certifying. For a
certifying boundary, use `provider: gvisor` on a Linux host configured with the
`runsc` runtime and pin the image by digest.

```yaml
redteam:
  sandbox:
    provider: gvisor
    image: alpine@sha256:<reviewed-digest>
    timeout_seconds: 90
    pids_limit: 64
    memory: 256m
    cpus: 1.0
    user_id: 65532
    group_id: 65532
    tmpfs_size_mb: 16
```

## Validate before use

Validate the automatically discovered policy:

```bash
uv run skilltrustops policy validate
```

Validate a specific file:

```bash
uv run skilltrustops policy validate --policy /path/to/policy.yaml
```

A valid result prints the effective profile, source, and SHA-256. Reports also
record that provenance so reviewers can identify the exact policy used.

## How discovery works

When `--policy` is omitted, SkillTrustOps:

1. locates the Git root from the current working directory;
2. looks for exactly one of `skilltrustops.yaml`, `skilltrustops.yml`, or
   `skilltrustops.json` at that root; and
3. uses the built-in `recommended-v2` profile if none exists.

An explicit `--policy` always takes precedence. Discovery is based on the
trusted current repository, not on the untrusted skill's directory.

Keep exactly one discoverable policy at the repository root. Multiple matching
files are rejected. Policy symlinks, unknown fields, invalid types, and files
larger than 256 KiB are also rejected.

## Turn checks on or off

Enable a static command through its corresponding `enabled` field:

```yaml
checks:
  lint:
    enabled: true
  security:
    enabled: true
  privacy:
    enabled: true
```

The complete nested configuration remains required by `recommended-v2`; see
the baseline above. Invoking a disabled or unconfigured command returns exit
code `2`.

Red-team testing is different. There is no `redteam.enabled` field. It becomes
active only when an operator invokes `skilltrustops redteam run`. The policy's
`redteam.sandbox` block selects the default isolation behavior. CLI options
`--sandbox` and `--sandbox-image` override those two values for one run; resource
and identity limits remain repository-controlled.

## Add Gitleaks defense in depth

The optional Gitleaks executable can run after the built-in scanner:

```yaml
checks:
  security:
    enabled: true
    secrets:
      enabled: true
      scanners:
        - engine: builtin
          enabled: true
        - engine: gitleaks
          enabled: true
          timeout_seconds: 30
          config: .skilltrustops/gitleaks.toml
```

Paths are resolved relative to the policy file. Referenced configuration is
included in the effective policy hash. Keep it inside the trusted policy tree,
review it, and commit it with the repository policy.

## Change management

- Protect the policy with code-owner review.
- Treat disabling a detector or weakening sandbox limits as a security change.
- Validate the policy in CI before any scan.
- Keep environment-specific overrides explicit and auditable with `--policy`.
- Re-run all affected assessments when the policy hash changes.
- Use `recommended-v2` for new repositories. `recommended-v1` is an immutable,
  lint-only compatibility profile and cannot contain security or privacy blocks.

For every field and accepted value, see [Policy reference](policy-reference.md).
