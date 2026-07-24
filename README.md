# SkillTrustOps

SkillTrustOps is a local-first CLI for reviewing AI agent skills before they
are allowed to run inside an organization.

The project is being built in small, independently tested phases. Phase 1
provides static structure validation through the `lint` command. It does not
execute skill code, make network requests, or require an account or API key.

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

## Test linting locally

### 1. Validate the repository policy

The repository includes [`skilltrustops.yaml`](skilltrustops.yaml):

```bash
uv run skilltrustops policy validate
```

Expected result:

```text
VALID .../skilltrustops.yaml
Profile: recommended-v1
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
    "profile": "recommended-v1",
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
44 passed
All checks passed!
Success: no issues found
Successfully built ...
```

## Exit codes

| Exit code | Meaning |
| --- | --- |
| `0` | The requested check passed. |
| `1` | Lint completed and found violations. |
| `2` | The command or policy configuration is invalid. |

For CI, fail the job on any non-zero exit code:

```bash
uv run skilltrustops lint path/to/skill/SKILL.md --format json
```

## Policy

SkillTrustOps uses one trusted repository policy. The Phase 1
`recommended-v1` profile enables Agent Skills specification linting:

```yaml
version: 1
profile: recommended-v1
checks:
  lint:
    enabled: true
    ruleset: agent-skills-specification
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
at the Git repository root. If none exists, the built-in `recommended-v1`
profile is used. Policy discovery is based on the current trusted repository,
not on the untrusted skill's directory.

Policy generation never overwrites an existing file. Keep only one
automatically discovered policy at the repository root. Additional test
policies can be stored elsewhere and selected with `--policy`.

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
