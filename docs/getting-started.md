# Getting started

This guide takes a repository from installation to its first deterministic and
behavioral assessment.

## 1. Install the development environment

SkillTrustOps requires Python 3.11 or newer.

```bash
uv sync --extra dev
uv run skilltrustops --help
```

Without `uv`, use a virtual environment:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
skilltrustops --help
```

The remaining examples use `uv run`. Omit that prefix in an activated virtual
environment.

## 2. Create the repository policy

From the Git repository root:

```bash
uv run skilltrustops policy init \
  --profile recommended-v2 \
  --format yaml

uv run skilltrustops policy validate
```

The generated `skilltrustops.yaml` enables lint, security, and privacy checks.
Commit this file so local and CI assessments use the same reviewed controls.

## 3. Run deterministic checks

Pass one `SKILL.md` file—not its directory—to each command:

```bash
uv run skilltrustops lint path/to/SKILL.md
uv run skilltrustops security path/to/SKILL.md
uv run skilltrustops privacy path/to/SKILL.md
```

Use JSON output for automation:

```bash
uv run skilltrustops security path/to/SKILL.md --format json
```

Fix every reported violation before behavioral testing. Static findings are
usually faster and cheaper to resolve than model-level failures.

## 4. Decide whether red-team testing is required

Red-team testing should be a release gate when a skill does any of the
following:

- reads documents, web pages, messages, tickets, or other untrusted content;
- handles credentials, personal data, proprietary data, or tenant data;
- calls read, write, destructive, financial, or communication tools;
- relies on user authorization or confirmation boundaries;
- performs multi-turn workflows; or
- changes model, tool, prompt, policy, or permission behavior after approval.

For a low-risk, text-only skill, static checks may be sufficient under your
organization's risk policy. Record that decision; do not silently skip testing.

## 5. Create a behavioral manifest

For an offline, deterministic draft:

```bash
uv run skilltrustops redteam init path/to/SKILL.md \
  --provider deterministic
```

For a model-assisted draft, place the provider key in an uncommitted `.env`:

```dotenv
OPENAI_API_KEY=replace-with-a-local-secret
SKILLTRUST_OPENAI_MODEL=replace-with-an-approved-model-id
```

Then run:

```bash
uv run skilltrustops redteam init path/to/SKILL.md \
  --provider openai \
  --model <approved-model-id>
```

This creates `skilltrust-package.yaml` beside `SKILL.md`. Generated content is
untrusted and review-required. Follow the approval checklist in
[Red-team testing](red-team-testing.md#review-and-approve-the-manifest).

## 6. Run a behavioral assessment

Verify the workflow offline first:

```bash
uv run skilltrustops redteam run path/to/SKILL.md \
  --provider reference \
  --model resistant-demo \
  --sandbox none
```

Then run the approved live target when required:

```bash
uv run skilltrustops redteam run path/to/SKILL.md \
  --provider openai \
  --model <approved-model-id>
```

Evidence is written under `.skilltrustops/redteam-runs/<run-id>/` by default.
Review `friendly-report.md` first, then retain the JSON report and integrity
manifest for audit.

## 7. Enforce exit codes in CI

| Code | Meaning | CI action |
| --- | --- | --- |
| `0` | Check passed, or red-team decision is `passed_scope` | Continue. |
| `1` | Static violations or red-team decision is `blocked` | Fail the job. |
| `2` | Invalid command, policy, package, or scanner configuration | Fail the job and fix configuration. |
| `3` | Red-team decision is `inconclusive` | Fail closed; investigate or rerun. |

Any non-zero code should fail a release gate.
