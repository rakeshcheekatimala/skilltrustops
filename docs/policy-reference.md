# Policy reference

SkillTrustOps policy files use strict validation: unknown fields are rejected,
booleans must be booleans, enum values are case-sensitive, and the top-level
schema version is currently `1`.

## Top-level fields

| Path | Type | Required | Accepted/default | Description |
| --- | --- | --- | --- | --- |
| `version` | integer | Yes | `1` | Policy schema version. |
| `profile` | string | Yes | `recommended-v1`, `recommended-v2` | Immutable profile contract. |
| `checks` | object | Yes | — | Static check configuration. |
| `redteam` | object | No | Sandbox provider `none` with defaults | Behavioral harness configuration. |

`recommended-v1` permits only lint configuration. `recommended-v2` requires
both security and privacy configuration.

## Lint fields

| Path | Type | Required | Accepted/default |
| --- | --- | --- | --- |
| `checks.lint` | object | Yes | — |
| `checks.lint.enabled` | boolean | No | `true` |
| `checks.lint.ruleset` | string | No | `agent-skills-specification` |

## Security fields

| Path | Type | Required | Accepted/default |
| --- | --- | --- | --- |
| `checks.security` | object | For `recommended-v2` | — |
| `checks.security.enabled` | boolean | No | `true` |
| `checks.security.secrets` | object | Yes when security exists | — |
| `checks.security.secrets.enabled` | boolean | No | `true` |
| `checks.security.secrets.scanners` | array | Yes | Unique scanner engines; at least one enabled when secret scanning is enabled. |
| `checks.security.dangerous_code` | object | Yes when security exists | — |
| `checks.security.dangerous_code.enabled` | boolean | No | `true` |
| `checks.security.dangerous_code.engine` | string | No | `ast` |
| `checks.security.dangerous_code.block_eval` | boolean | No | `true` |
| `checks.security.dangerous_code.block_destructive_shell` | boolean | No | `true` |
| `checks.security.dangerous_code.block_remote_pipe` | boolean | No | `true` |

### Secret scanner entries

| Engine | Fields |
| --- | --- |
| `builtin` | `engine: builtin`; optional `enabled` (default `true`). |
| `gitleaks` | `engine: gitleaks`; optional `enabled` (default `true`), `timeout_seconds` (1–300, default 30), and `config` path. |

Scanner engines cannot be duplicated in one policy.

## Privacy fields

| Path | Type | Required | Accepted/default |
| --- | --- | --- | --- |
| `checks.privacy` | object | For `recommended-v2` | — |
| `checks.privacy.enabled` | boolean | No | `true` |
| `checks.privacy.pii` | object | Yes when privacy exists | — |
| `checks.privacy.pii.enabled` | boolean | No | `true` |
| `checks.privacy.pii.engine` | string | No | `builtin` |
| `checks.privacy.pii.entities` | array | No | `email`, `phone`, `ssn`, `credit_card` |

Supported entity values are `email`, `phone`, `ssn`, and `credit_card`.

## Red-team sandbox fields

| Path | Type | Required | Accepted/default | Constraint |
| --- | --- | --- | --- | --- |
| `redteam.sandbox.provider` | string | No | `none` | `none`, `docker`, `gvisor` |
| `redteam.sandbox.image` | string | No | `alpine:3.20` | Use a digest-pinned image for gVisor assurance. |
| `redteam.sandbox.timeout_seconds` | integer | No | `90` | 10–600 |
| `redteam.sandbox.pids_limit` | integer | No | `64` | 16–512 |
| `redteam.sandbox.memory` | string | No | `256m` | Docker-compatible memory value. |
| `redteam.sandbox.cpus` | number | No | `1.0` | Greater than 0, at most 8. |
| `redteam.sandbox.user_id` | integer | No | `65532` | At least 1; root is forbidden. |
| `redteam.sandbox.group_id` | integer | No | `65532` | At least 1; root is forbidden. |
| `redteam.sandbox.tmpfs_size_mb` | integer | No | `16` | 4–256 |

The harness enforces non-configurable isolation invariants including a read-only
package mount, non-root identity, dropped Docker capabilities, no Docker socket,
no network, a read-only root filesystem, `no-new-privileges`, resource limits,
and a small `noexec` temporary filesystem.

## Resolution and hashing

- Explicit `--policy` wins over discovery.
- Otherwise, exactly one conventional policy is selected from the Git root.
- Without a file, the built-in `recommended-v2` profile is used.
- The effective SHA-256 covers normalized policy data and any enabled referenced
  Gitleaks configuration content.
- Policy files must be regular, non-symlink UTF-8 YAML or JSON and no larger
  than 256 KiB.
