# SkillTrustOps

SkillTrustOps is a local-first CLI for reviewing AI agent skills before they
are allowed to run inside an organization.

The project is being built in small, independently tested phases. It currently
provides specification linting plus deterministic security and privacy scans.
It does not execute skill code, make network requests, or require an account or
API key.

## Local quick start

SkillTrustOps requires Python 3.12 or newer.

The fastest development setup uses
[uv](https://docs.astral.sh/uv/):

```bash
uv sync --extra dev
uv run skilltrustops --help
```

You can also use a standard virtual environment:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
skilltrustops --help
```

Commands below use `uv run`. If you activated the virtual environment, remove
the `uv run` prefix.

## Test locally

### 1. Validate the repository policy

The repository includes [`skilltrustops.yaml`](skilltrustops.yaml):

```bash
uv run skilltrustops policy validate
```

Expected result:

```text
VALID .../skilltrustops.yaml
Profile: recommended-v2
SHA-256: ...
```

### 2. Test a valid skill

```bash
uv run skilltrustops lint examples/valid-skill/SKILL.md
```

Expected result and exit code:

```text
PASS .../examples/valid-skill/SKILL.md
```

```bash
echo $?
# 0
```

Generate the same result as machine-readable JSON:

```bash
uv run skilltrustops lint examples/valid-skill/SKILL.md --format json
```

The report contains:

```json
{
  "schema_version": "1.1",
  "command": "lint",
  "policy": {
    "profile": "recommended-v2",
    "source": ".../skilltrustops.yaml",
    "sha256": "..."
  },
  "passed": true,
  "findings": []
}
```

### 3. Test an invalid skill

```bash
uv run skilltrustops lint examples/invalid-skill/SKILL.md
```

This command is expected to show findings and return exit code `1`:

```bash
echo $?
# 1
```

Each finding includes:

- A stable rule ID
- Severity
- Evidence
- Remediation
- File location

JSON output is also available:

```bash
uv run skilltrustops lint examples/invalid-skill/SKILL.md --format json
```

### 4. Test an explicit JSON policy

Generate a JSON policy outside the repository root so automatic discovery
continues to see exactly one repository policy:

```bash
uv run skilltrustops policy init \
  --format json \
  --output /tmp/skilltrustops-policy.json
```

Validate and use it explicitly:

```bash
uv run skilltrustops policy validate \
  --policy /tmp/skilltrustops-policy.json

uv run skilltrustops lint examples/valid-skill/SKILL.md \
  --policy /tmp/skilltrustops-policy.json \
  --format json
```

The YAML and JSON forms produce the same effective policy hash.

### 5. Test your own skill

Pass the `SKILL.md` file directly:

```bash
uv run skilltrustops lint /absolute/path/to/my-skill/SKILL.md
uv run skilltrustops security /absolute/path/to/my-skill/SKILL.md
uv run skilltrustops privacy /absolute/path/to/my-skill/SKILL.md
```

Phase 1 does not accept a directory and does not recurse through folders.

## Run developer checks

Run the full automated test and quality suite:

```bash
uv run --extra dev pytest
uv run --extra dev ruff check .
uv run --extra dev mypy src
uv build
```

Expected results:

```text
58 passed
All checks passed!
Success: no issues found
Successfully built ...
```

## Exit codes

| Exit code | Meaning |
| --- | --- |
| `0` | The requested check passed. |
| `1` | The requested scan completed and found violations. |
| `2` | The command or policy configuration is invalid. |

For CI, fail the job on any non-zero exit code:

```bash
uv run skilltrustops lint path/to/skill/SKILL.md --format json
```

## Policy

SkillTrustOps uses one trusted repository policy. The current
`recommended-v2` profile enables specification linting, deterministic security
checks, and PII detection:

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
      engine: builtin
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
```

Generate or validate YAML and JSON policies locally:

```bash
uv run skilltrustops policy init --format yaml
uv run skilltrustops policy init \
  --format json \
  --output /tmp/skilltrustops-policy.json
uv run skilltrustops policy validate --policy skilltrustops.yaml
uv run skilltrustops lint ./my-skill/SKILL.md \
  --policy /tmp/skilltrustops-policy.json
```

An explicit `--policy` takes precedence. Otherwise, SkillTrustOps looks for
exactly one `skilltrustops.yaml`, `skilltrustops.yml`, or `skilltrustops.json`
at the Git repository root. If none exists, the built-in `recommended-v2`
profile is used. Policy discovery is based on the current trusted repository,
not on the untrusted skill's directory.

Policy generation never overwrites an existing file. Keep only one
automatically discovered policy at the repository root. Additional test
policies can be stored elsewhere and selected with `--policy`.

`recommended-v1` remains available as the immutable lint-only profile.
`recommended-v2` is the default for newly generated policies and
zero-configuration fallback.

### Enable security and privacy checks

For a new repository with no policy file, generate the current profile:

```bash
uv run skilltrustops policy init \
  --profile recommended-v2 \
  --format yaml
```

If the repository already uses `recommended-v1`, do not change only the
profile name. Add the complete `security` and `privacy` blocks shown above,
then change `profile` to `recommended-v2`. The v2 schema requires both blocks
so a policy cannot claim a check that has no configuration.

Validate the effective policy before scanning:

```bash
uv run skilltrustops policy validate
```

Run every currently implemented check explicitly:

```bash
uv run skilltrustops lint path/to/skill/SKILL.md
uv run skilltrustops security path/to/skill/SKILL.md
uv run skilltrustops privacy path/to/skill/SKILL.md
```

To use a policy outside the repository root, pass it explicitly to every
command:

```bash
uv run skilltrustops security path/to/skill/SKILL.md \
  --policy /path/to/skilltrustops.json
uv run skilltrustops privacy path/to/skill/SKILL.md \
  --policy /path/to/skilltrustops.json
```

Top-level `checks.security.enabled` and `checks.privacy.enabled` control the
commands. Calling a command disabled by policy returns exit code `2`; it never
reports the skipped check as passing.

Individual engines can be disabled while keeping the parent check enabled:

```yaml
checks:
  security:
    enabled: true
    secrets:
      enabled: false
      engine: builtin
    dangerous_code:
      enabled: true
      engine: ast
      block_eval: true
      block_destructive_shell: true
      block_remote_pipe: true
```

PII entity selection is also policy-driven:

```yaml
checks:
  privacy:
    enabled: true
    pii:
      enabled: true
      engine: builtin
      entities:
        - email
        - ssn
```

Supported built-in entities are `email`, `phone`, `ssn`, and `credit_card`.
After any policy edit, rerun `skilltrustops policy validate`.

## Deterministic security scanning

Run the security check:

```bash
uv run skilltrustops security path/to/skill/SKILL.md
uv run skilltrustops security path/to/skill/SKILL.md --format json
```

The built-in secret detector currently recognizes:

- PEM private-key headers
- AWS access key IDs
- GitHub tokens
- Common hard-coded credential assignments

The AST and command-pattern detector checks for:

- Python `eval()` and `exec()`
- `os.system()` and `subprocess` calls using `shell=True`
- Recursive or forced `rm` commands
- `curl` or `wget` content piped directly to a shell

SkillTrustOps never includes a detected secret value in report evidence.
Security findings retain their individual severity; they are not hidden inside
a combined score.

## Deterministic privacy scanning

Run the privacy check:

```bash
uv run skilltrustops privacy path/to/skill/SKILL.md
uv run skilltrustops privacy path/to/skill/SKILL.md --format json
```

The built-in PII detector supports policy-selected:

- Email addresses
- Phone numbers
- US Social Security numbers
- Payment card numbers that pass the Luhn checksum

Detected PII values are redacted from evidence and terminal/JSON reports.

## Scanner adapters

Policy uses one consistent `engine` attribute. The working defaults are local
and dependency-light:

```yaml
secrets:
  engine: builtin
pii:
  engine: builtin
dangerous_code:
  engine: ast
```

The detector protocols and engine factory allow future adapters for
detect-secrets, Gitleaks, Microsoft Presidio, and YARA without changing CLI
commands or report models. Those third-party engines are not yet accepted as
policy values, so a policy cannot claim an analysis that was not executed.

## Phase 1 skill contract

Phase 1 accepts exactly one regular UTF-8 file named `SKILL.md`, no larger than
1 MiB. It does not traverse directories. The file starts with YAML front matter:

```markdown
---
name: my-skill
description: Explains clearly when and why this skill should be used.
---

# My skill

Instructions for the agent.
```

Phase 1 lint rules follow the
[Agent Skills specification](https://agentskills.io/specification). A skill
name is limited to 64 characters, uses lowercase alphanumeric characters and
hyphens, and matches its parent directory. A description is non-empty and no
longer than 1024 characters. The optional `license`, `compatibility`,
`metadata`, and experimental `allowed-tools` fields are also validated.
