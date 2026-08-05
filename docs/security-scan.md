# Security scan

The `security` command performs a deterministic, local scan of a complete skill
package rooted beside one `SKILL.md`. It never executes package content, follows
links, extracts archives, or uploads content.

```bash
uv run skilltrustops security path/to/SKILL.md
uv run skilltrustops security path/to/SKILL.md --format json
```

## What it covers

The default `recommended-v2` policy enables two groups of checks.

### Secrets and credentials

| Rule | Check | Severity |
| --- | --- | --- |
| `STO-SEC-001` | RSA, EC, and OpenSSH private-key blocks | `critical` |
| `STO-SEC-002` | AWS access-key IDs beginning with `AKIA` or `ASIA` | `critical` |
| `STO-SEC-003` | GitHub tokens with a supported `gh*_` prefix | `critical` |
| `STO-SEC-004` | Values assigned to names such as `api_key`, `access_token`, `password`, or `secret` | `high` |
| `RT-006` | Red-team canaries left in a skill | `medium` |

The generic credential check ignores common placeholder markers such as
`example`, `placeholder`, `changeme`, `redacted`, `${...}`, and `<...>`.
Matched secret values are never included in terminal or JSON output.

The built-in scanner favors a small set of high-confidence signatures. A
repository can also select the local Gitleaks CLI for broader secret coverage.
When Gitleaks is selected but unavailable, times out, or returns an invalid
report, the command fails instead of claiming that the skill passed.

### Dangerous instructions

| Rule | Check | Severity |
| --- | --- | --- |
| `STO-SEC-100` | Dynamic Python execution through `eval()` or `exec()` | `high` |
| `STO-SEC-101` | Recursive or forced `rm` commands | `critical` |
| `STO-SEC-102` | `curl` or `wget` output piped directly to `sh`, `bash`, or `zsh` | `critical` |
| `STO-SEC-103` | Shell execution through `os.system()` or `subprocess` with `shell=True` | `high` |

Python code fences are parsed with Python's abstract syntax tree. The scanner
also applies deterministic text patterns to the rest of the Markdown. Parsing
and matching do not execute any submitted code.

### Complete-package risk

| Rule | Meaning | Severity | Developer action |
| --- | --- | --- | --- |
| `STO-PKG-200` | Prompt-injection or authority-override language | `high` | Remove it or isolate it as a labeled test fixture. |
| `STO-PKG-201` | Runtime payload decoding or reconstruction | `high` | Keep executable behavior transparent and reviewable. |
| `STO-PKG-202` | Startup, scheduler, authentication, or hook persistence | `critical` | Remove persistent host changes. |
| `STO-PKG-203` | Potential secret or data-exfiltration flow | `critical` | Remove transmission or constrain data and destinations. |
| `STO-PKG-204` | Excessive privilege or permission changes | `high` | Apply least privilege and exact resource scopes. |
| `STO-PKG-205` | Install or build lifecycle execution hook | `high` | Review or remove executable supply-chain hooks. |
| `STO-PKG-206` | Link or special filesystem entry | `high` | Replace it with a reviewed regular file. |
| `STO-PKG-207` | Unsafe or over-limit archive | `critical` | Rebuild it with bounded regular relative entries. |
| `STO-PKG-208` | Unpinned dependency | `medium` | Pin reviewed versions and hashes. |
| `STO-PKG-209` | Missing file referenced by `SKILL.md` | `medium` | Add the file or remove the stale instruction. |
| `STO-PKG-210` | `SKILL.md` delegates to a risky adjacent file | `high` | Review and constrain the referenced behavior. |

Package inspection is bounded to 2,000 regular files, 32 MiB total input, and
1 MiB for each decoded text file. Archives are inspected as metadata only and
are limited to 5,000 members and 128 MiB declared expansion. Exceeding a bound
is an error, never a pass.

## How it runs

1. SkillTrustOps discovers or loads the trusted repository policy.
2. It confirms that the security check exists and is enabled.
3. The safe loader accepts exactly one regular file named `SKILL.md`.
4. The package inventory walks adjacent files without following links and checks
   manifests, dependencies, archives, scripts, references, and assets.
5. The policy selects the secret and dangerous-instruction detectors.
6. Every selected detector scans the same in-memory text.
7. SkillTrustOps returns `PASS` when there are no findings, or `FAIL` with rule
   IDs, severity, line location, redacted evidence, and remediation.

The JSON report also records the tool version, target path, effective policy
profile and hash, scan duration, and `deterministic: true`.

## Configure the scan

The generated `recommended-v2` policy uses these secure defaults:

```yaml
checks:
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
```

See the [policy reference](policy-reference.md) for every supported field. Keep
the built-in scanner and all dangerous-code blocks enabled unless a reviewed
repository policy explicitly requires different behavior.

## Understand the boundary

A passing security scan means that the configured deterministic detectors found
no matching pattern in the bounded package snapshot. It does not prove safety.

The command does not currently:

- determine whether a detected credential is active;
- cover every provider-specific secret format;
- decide whether a dangerous-looking instruction is safe in its broader
  operational context; or
- perform semantic program analysis across arbitrary languages; or
- test model behavior under adversarial input.

Run `lint` and `privacy` alongside the security scan. Use `redteam run` when you
need evidence about how a selected model behaves under attack.
