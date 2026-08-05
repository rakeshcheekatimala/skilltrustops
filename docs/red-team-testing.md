# Red-team testing

Behavioral red-team testing answers a different question from static scanning:
when a selected model follows this skill, will it resist adversarial input,
protect synthetic sensitive data, enforce authorization, and require confirmation
before consequential simulated tool calls?

## When red-team testing is required

Run it before initial release and after material changes when a skill:

- ingests untrusted documents, messages, web content, retrieval results, or tool
  output;
- can reveal personal, tenant, confidential, or credential-like data;
- calls tools, especially write, external communication, destructive, or
  financial tools;
- makes authorization decisions or depends on current-user scope;
- requires user confirmation for consequential actions;
- uses multi-turn state; or
- operates in a regulated or high-impact workflow.

Re-run after changing `SKILL.md`, the behavioral manifest, model/model snapshot,
tool schema, authorization or confirmation rules, policy, sandbox image/runtime,
harness version, or attack library. Evidence from one combination does not
automatically apply to another.

## What “turn it on” means

Red-team testing is explicitly invoked; it is not a background policy check.
There is no valid `redteam.enabled: true` field.

```bash
uv run skilltrustops redteam run path/to/SKILL.md \
  --provider reference \
  --model resistant-demo
```

The `redteam.sandbox` policy selects the default isolation stage. A one-run
`--sandbox` or `--sandbox-image` override is available, but resource limits and
the non-root identity remain policy-controlled.

## Package layout

```text
my-skill/
├── SKILL.md
└── skilltrust-package.yaml
```

Phase 1 accepts one regular, non-symlink `SKILL.md` beside one YAML or JSON
manifest. It does not execute skill code or real tool implementations.

## Generate a manifest draft

Offline deterministic generation:

```bash
uv run skilltrustops redteam init my-skill/SKILL.md \
  --provider deterministic
```

Model-assisted generation:

```bash
uv run skilltrustops redteam init my-skill/SKILL.md \
  --provider openai \
  --model <approved-model-id>
```

Use `--force` only when deliberately replacing an existing generated manifest.
The generator reads `SKILL.md` as untrusted data, validates and normalizes its
proposal, adds baseline attacks and canaries, records generation provenance,
and writes a review-required draft.

## Review and approve the manifest

Generation is not approval. A security reviewer should verify:

- capabilities match the actual skill;
- every real tool has an explicit JSON Schema contract;
- tool effects (`read`, `write`, `external_communication`, `destructive`, or
  `financial`) are accurate;
- `current_user` authorization points to the correct resource argument;
- confirmation is required for consequential actions;
- sensitive data is denied unless explicitly necessary;
- synthetic records represent both authorized and unauthorized resources;
- canaries are unique, synthetic, and easy to detect;
- attacks cover direct and indirect injection, disclosure, unauthorized tool
  calls, confirmation bypass, and multi-turn escalation where applicable;
- forbidden tools and output markers are precise; and
- OWASP LLM and MITRE ATLAS mappings are appropriate.

Generated manifests include provenance similar to:

```yaml
generation:
  status: draft
  method: openai
  generator_version: "<recorded-version>"
  source_skill_sha256: "<generated-hash>"
  requires_review: true
  model: "<generation-model>"
```

After review, change only the approval fields:

```yaml
generation:
  status: approved
  method: openai
  generator_version: "<recorded-version>"
  source_skill_sha256: "<generated-hash>"
  requires_review: false
  model: "<generation-model>"
```

Do not edit `source_skill_sha256`. If `SKILL.md` changes, loading fails and the
manifest must be regenerated and reviewed again. A clean draft remains
`inconclusive`.

## Choose a target

### Reference target

Reference targets are transparent fixtures, not language models. Use them to
test the harness and CI wiring without network access:

```bash
# Expected clean behavior
uv run skilltrustops redteam run examples/redteam-support/SKILL.md \
  --provider reference --model resistant-demo --sandbox none

# Expected security failures
uv run skilltrustops redteam run examples/redteam-support/SKILL.md \
  --provider reference --model vulnerable-demo --sandbox none
```

### OpenAI target

Store the key in an uncommitted repository `.env` or inject it through your CI
secret manager:

```dotenv
OPENAI_API_KEY=replace-with-a-secret
SKILLTRUST_OPENAI_MODEL=replace-with-an-approved-model-id
```

```bash
uv run skilltrustops redteam run my-skill/SKILL.md \
  --provider openai \
  --model <approved-model-id>
```

Existing process environment values take precedence. The key is not accepted
from the browser, embedded in the package manifest, or written to evidence.
Live provider runs are not fully deterministic; use an approved pinned model
snapshot when the provider offers one.

For another provider or an internal model gateway, use `generic-http`. The
endpoint must use HTTPS, except loopback endpoints used for local testing. The
request contains schema version `1.0`, the selected model name, skill text,
validated manifest, current attack case, and turn index. The response must match
the strict `ModelResponse` schema: `content` plus optional `tool_calls`.

```bash
export SKILLTRUSTOPS_PROVIDER_TOKEN=replace-with-a-secret
uv run skilltrustops redteam run my-skill/skilltrust-package.yaml \
  --provider generic-http \
  --endpoint https://gateway.example/evaluate \
  --model approved-model
```

Use `--token-env` to select another environment variable. Tokens are never
accepted in manifests or report output.

## Choose a sandbox boundary

| Provider | Intended use | Can a clean run be `passed_scope`? |
| --- | --- | --- |
| `none` | Harness development or environments with a separately accepted boundary | Yes, if all other assurance conditions hold; document the external boundary. |
| `docker` | Local development isolation | No; a clean run is intentionally `inconclusive`. |
| `gvisor` | Stronger Linux isolation with `runsc` and a digest-pinned image | Yes, if all checks and other assurance conditions pass. |

For gVisor:

```bash
uv run skilltrustops redteam run my-skill/SKILL.md \
  --provider openai \
  --model <approved-model-id> \
  --sandbox gvisor \
  --sandbox-image alpine@sha256:<reviewed-digest>
```

The run fails closed. If the runtime is unavailable, the trusted probe fails,
or the container times out, attacks do not start and the result is
`inconclusive`. Timed-out containers are forcibly removed before reporting.

## Interpret results

Decision precedence is:

```text
confirmed security failure -> blocked
missing or uncertain evidence -> inconclusive
all required evidence passed -> passed_scope
```

- `blocked`: remediate the confirmed assertion and rerun the full affected
  scope.
- `inconclusive`: do not approve. Fix the draft, provider, sandbox, or evidence
  problem and rerun.
- `passed_scope`: approve only the exact package/model/harness/attack scope recorded.

## Evidence

By default, each run writes:

```text
.skilltrustops/redteam-runs/<run-id>/
├── evidence-manifest.json
├── friendly-report.md
├── inspect-events.jsonl
└── report.json
```

Use `--evidence-dir` to choose another evidence root and `--format json` for
machine-readable terminal output. The bundle includes package hashes, model and
harness versions, attacks, conversations, outputs, assertions, fake-tool
traces, decision reasons, sandbox results, and generation provenance. Verify
the integrity manifest before audit or promotion.

Evidence may contain prompts and model outputs. Apply access controls, retention
rules, and secure artifact storage even though test fixtures should be
synthetic.
