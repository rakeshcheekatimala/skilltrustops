# SkillTrustOps

SkillTrustOps is a local-first CLI for reviewing AI agent skills before they
are allowed to run inside an organization.

The project is being built in small, independently tested phases. It currently
provides specification linting plus deterministic security and privacy scans.
It does not execute skill code, make network requests, or require an account or
API key.

## Phase 1 behavioral red-team harness

SkillTrustOps can also test one `SKILL.md` in a controlled reference harness.
This is separate from the deterministic `lint`, `security`, and `privacy`
commands: a behavioral run invokes the selected model, gives it generated
in-memory tools and synthetic records, and observes whether adversarial inputs
cause unsafe output or tool intent.

The harness currently supports:

- One `SKILL.md` beside one declarative package manifest
- JSON Schema-style tool inputs and outputs
- Generated tools that never perform real side effects
- Synthetic records and uniquely detectable canaries
- Direct and indirect prompt injection
- Sensitive-data disclosure
- Unauthorized tool-call attempts
- Confirmation bypass
- Multi-turn authority escalation
- Deterministic assertions over model output and tool traces
- A content-addressed SkillTrustOps evidence bundle
- An Inspect-oriented JSONL event export for later import/adaptation
- `assured`, `blocked`, and `inconclusive` decisions

The example package is in
[`examples/redteam-support`](examples/redteam-support). Run its safe,
deterministic demonstration target:

```bash
uv run skilltrustops redteam run \
  examples/redteam-support/skilltrust-package.yaml \
  --model resistant-demo
```

Run the deliberately weak target to inspect failures and blocked tool calls:

```bash
uv run skilltrustops redteam run \
  examples/redteam-support/skilltrust-package.yaml \
  --model vulnerable-demo
```

Evidence is written under `.skilltrustops/redteam-runs/<run-id>/` unless
`--evidence-dir` is supplied. Submitted Python, JavaScript, shell scripts,
Dockerfiles, and tool implementations are never executed in Phase 1.

### Test a real OpenAI model

The reference models require no API key. To opt into a real model call, copy
`.env.example` to `.env`, add the key, and restart the backend:

```dotenv
OPENAI_API_KEY=your-local-key
SKILLTRUST_OPENAI_MODEL=gpt-5.6-terra
```

Then run:

```bash
uv run skilltrustops redteam run \
  examples/redteam-support/skilltrust-package.yaml \
  --provider openai \
  --model gpt-5.6-terra
```

The CLI reads `OPENAI_API_KEY` from its process environment. The Studio backend
also loads the repository-local `.env`. The key is not accepted from the
browser, returned by the API, or included in evidence. A real-provider run is
not fully deterministic even with fixed inputs; the report records that fact.

For durable assessments, choose a pinned provider model snapshot when one is
available rather than a moving alias.

### Generate behavioral tests from one SKILL.md

When a skill has no adjacent manifest, generate a model-proposed draft:

```bash
uv run skilltrustops redteam init examples/my-skill/SKILL.md \
  --provider openai \
  --model gpt-5.6-terra
```

Studio provides the same flow with **Generate behavioral test draft**. The
generator treats SKILL.md as untrusted data, requests schema-constrained attack
proposals, adds baseline attacks and synthetic canaries, validates the complete
manifest, and writes `skilltrust-package.yaml` beside the skill. Submitted code
is not executed.

Generated manifests are bound to the source skill SHA-256 and marked as
review-required. A confirmed attack still produces `blocked`; a clean run stays
`inconclusive` until the generated capabilities, tools, attacks, and expected
markers have been reviewed. Changing SKILL.md makes the draft stale and requires
regeneration.

### What `assured` means

`assured` means that all applicable Phase 1 cases were resisted by the exact
skill, manifest, model, harness, and attack definitions identified in the
evidence bundle. It does not claim that the skill is universally safe in every
agent framework or production application. Changing the skill, tool contract,
model, harness, or attack suite requires a new assessment.

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
69 passed
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
      enabled: true
      scanners:
        - engine: builtin
          enabled: false
        - engine: gitleaks
          enabled: true
          timeout_seconds: 30
          config: .skilltrustops/gitleaks.toml
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

### Use Gitleaks for secret scanning

Gitleaks is an optional local executable; it is not downloaded or installed by
SkillTrustOps. Install it separately and verify it is available:

```bash
# macOS
brew install gitleaks

gitleaks version
```

For Linux, Windows, and other installation methods, use the
[official Gitleaks installation documentation](https://github.com/gitleaks/gitleaks#installing).

Replace the `secrets` block in `skilltrustops.yaml`:

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
    dangerous_code:
      enabled: true
      engine: ast
      block_eval: true
      block_destructive_shell: true
      block_remote_pipe: true
```

Validate and run:

```bash
uv run skilltrustops policy validate
uv run skilltrustops security path/to/skill/SKILL.md
```

The included `.skilltrustops/gitleaks.toml` extends Gitleaks' default rules.
Its contents are included in the effective SkillTrustOps policy hash.

The adapter streams the bounded `SKILL.md` content to `gitleaks stdin`. It does
not scan Git history, recurse through neighboring files, execute skill code, or
make a network request. It invokes Gitleaks with `shell=False`, full output
redaction, a timeout, and `gitleaks:allow` comments disabled. Ambient
`GITLEAKS_CONFIG` variables are removed so policy controls configuration.
Secret, match, and source-line values from the Gitleaks report are never copied
into SkillTrustOps evidence.

If policy selects `gitleaks` but the executable is unavailable or fails to
produce a valid JSON report, the command returns exit code `2`. SkillTrustOps
does not silently fall back to the built-in detector.

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

Secret scanning accepts an ordered `scanners` list. The working default is
local and dependency-light; Gitleaks can run alone or alongside it:

```yaml
secrets:
  enabled: true
  scanners:
    - engine: builtin
      enabled: true
    - engine: gitleaks
      enabled: true
      timeout_seconds: 30
      config: .skilltrustops/gitleaks.toml
pii:
  engine: builtin
dangerous_code:
  engine: ast
```

The detector protocols and engine factory allow future adapters for
detect-secrets, Microsoft Presidio, and YARA without changing CLI commands or
report models. Unsupported third-party engines are rejected so a policy cannot
claim an analysis that was not executed.

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
