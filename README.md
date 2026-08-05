# SkillTrustOps

[![Tests, coverage, and audit](https://img.shields.io/github/actions/workflow/status/rakeshcheekatimala/skilltrustops/ci.yml?branch=library&label=tests%20%7C%20coverage%20%7C%20audit)](https://github.com/rakeshcheekatimala/skilltrustops/actions/workflows/ci.yml)
[![Snyk Security](https://img.shields.io/github/actions/workflow/status/rakeshcheekatimala/skilltrustops/snyk.yml?branch=library&label=Snyk%20Security)](https://github.com/rakeshcheekatimala/skilltrustops/actions/workflows/snyk.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/rakeshcheekatimala/skilltrustops/codeql.yml?branch=library&label=CodeQL)](https://github.com/rakeshcheekatimala/skilltrustops/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/rakeshcheekatimala/skilltrustops/badge)](https://scorecard.dev/viewer/?uri=github.com/rakeshcheekatimala/skilltrustops)
[![PyPI](https://img.shields.io/pypi/v/skilltrustops)](https://pypi.org/project/skilltrustops/)
[![Python](https://img.shields.io/pypi/pyversions/skilltrustops)](https://pypi.org/project/skilltrustops/)
[![License: MIT](https://img.shields.io/pypi/l/skilltrustops)](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/LICENSE)

SkillTrustOps finds unsafe instructions, secrets, personal data, dangerous code,
and risky package structure before an agent loads a skill. Its core primitive is
a policy-bound scan report: deterministic findings with stable rule IDs, evidence,
and exit codes for local review or CI.

## Verified project assurance

Every badge above links to independently inspectable evidence. A green result
applies to the exact commit, dependency lock, scanner versions, and advisory data
used by that run; it is not a claim that unknown vulnerabilities cannot exist.

| Signal | What must pass |
| --- | --- |
| Tests and coverage | Full unit-test suite across Linux, macOS, Windows and Python 3.11–3.13; branch coverage cannot fall below 80% |
| Dependency security | PyPA `pip-audit` and Snyk Open Source check the locked runtime dependency graph and fail on detected vulnerabilities |
| Source security | Bandit and Snyk Code are blocking gates; CodeQL runs the `security-extended` query suite and publishes independently reviewable alerts |
| Package integrity | Wheel and source archive build, pass Twine metadata validation, and install in isolated smoke tests |
| Supply chain | Runtime resolutions are locked, Actions are commit-pinned, Dependabot is enabled, an SPDX SBOM is generated, and releases use OIDC Trusted Publishing plus build-provenance attestations |
| Repository practices | OpenSSF Scorecard measures the public repository controls instead of relying on a self-issued score |

See [Project assurance](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/project-assurance.md) for exact commands, badge interpretation,
Snyk setup, evidence locations, and limitations.

## Try it

```bash
python -m pip install skilltrustops
skilltrustops policy init --profile recommended-v2
skilltrustops scan .
# Optional depth, still one workflow:
skilltrustops scan . --redteam --benchmark
skilltrustops scan . --debt-report engineering-debt.md
# 0 = passed, 1 = findings, 2 = scanner or configuration error
```

## What it does

| Need | What SkillTrustOps provides |
| --- | --- |
| Review one or many skills | Recursive discovery, one policy, stable ordering, per-skill timing |
| Inspect the full package | `SKILL.md`, scripts, references, assets, manifests, dependencies, archives, and symlinks |
| Find static risk | Structure, secrets, PII, dangerous code, injection, obfuscation, persistence, exfiltration, permissions, lifecycle, and cross-file rules |
| Use it in CI | Exit-code contract, JSON, SARIF 2.1.0, expiring suppressions, fingerprinted baselines |
| Test behavior | Synthetic data, simulated tools, deterministic assertions, immutable evidence |
| Stay offline | Static scanning and reference red-team testing without an API key |
| Verify claims | Locked corpus, Docker resource limits, raw runs, checksums, calibration metrics |

See [invariants and failure modes](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/invariants-and-failure-modes.md) for what
the scanner guarantees, and [anti-patterns](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/anti-patterns.md) for unsafe ways
to integrate it. Production integrations can use the documented
[structured logging and OpenTelemetry spans](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/observability.md).

[![SkillTrustOps scanning and red-team workflow](https://raw.githubusercontent.com/rakeshcheekatimala/skilltrustops/library/docs/images/skilltrustops-overview.png)](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/images/skilltrustops-overview.png)

## Requirements and installation

SkillTrustOps requires **Python 3.11 or newer**.

```bash
python -m pip install skilltrustops
skilltrustops --help
```

Until the first PyPI release, install a locally built wheel or the Git repository
instead. The package exposes both the `skilltrustops` CLI and `skilltrustops.scan`
Python API.

| Capability | Network or OpenAI key required? |
| --- | --- |
| Recursive lint, security, and privacy scan | No |
| Docker benchmark reproduction | No after corpus and container image inputs are available locally |
| Reference-provider red-team harness validation | No |
| Deterministic red-team manifest generation | No |
| Red-team assessment of a live model | Yes; use OpenAI or a generic HTTPS provider |

Offline red-team runs validate the harness, fixtures, attack assertions, evidence
format, and deterministic reference behavior. They do **not** establish how an
unqueried production model will behave.

## Catch unsafe skill instructions before an agent follows them

Run the quality gate with one command:

```bash
uv run skilltrustops scan .
```

You get a local, deterministic pass or fail for skill structure, exposed
credentials, dangerous instructions, and personal data. Start with
[Getting started](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/getting-started.md) for installation alternatives and
behavioral testing.

## Scan one skill or a folder

Apply one policy to every `SKILL.md` below a folder and emit deterministic
evidence:

```bash
uv run skilltrustops scan path/to/skills \
  --policy skilltrustops.yaml \
  --format json > skilltrustops-report.json
```

For code scanning platforms, change the format to SARIF. To create a local Git
gate, install the supplied pre-commit and pre-push hook. CI must run the same scan
because local hooks can be bypassed.

```bash
skilltrustops scan path/to/skills --format sarif > skilltrustops.sarif
```

See [Git hooks](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/git-hooks.md) and
[exit codes and rule compatibility](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/exit-codes-and-rules.md).

The same stable report is available from Python:

```python
from skilltrustops import scan

report = scan("path/to/skills", policy_path="skilltrustops.yaml")
for skill in report.skills:
    print(skill.relative_path, skill.status)
```

Folder discovery is recursive, deterministic, and limited to regular,
non-symlink files named `SKILL.md`. A failed skill produces findings while a
scanner failure is reported separately as an error; errors are never counted as
passes.

> [!IMPORTANT]
> Static checks never execute the submitted skill or upload its content.
> Red-team runs call the model provider you select. All tools used by the
> red-team harness are in-memory simulations and perform no real side effects.

## Three gates to trust

SkillTrustOps evaluates a skill in three stages: structure, security and
privacy, then model behavior under attack.

[![Three SkillTrustOps trust gates: lint, security and privacy, and red-team testing](https://raw.githubusercontent.com/rakeshcheekatimala/skilltrustops/main/docs/images/skilltrustops-three-gates.png)](https://github.com/rakeshcheekatimala/skilltrustops/blob/main/docs/images/skilltrustops-three-gates.png)

## Control scan depth

```bash
uv run skilltrustops scan . --security --privacy
uv run skilltrustops scan . --redteam
uv run skilltrustops scan . --benchmark
uv run skilltrustops scan . --metrics
```

Security and privacy are enabled by default. `--no-security` and `--no-privacy`
exist for focused troubleshooting, not for certification. `--benchmark` verifies
that a replay produces identical evidence. `--metrics` opts into nondeterministic
wall-clock timings and cannot be combined with the replay check.

### What the security scan checks

The security stage reads the complete adjacent skill package under strict
file, byte, archive, and symlink limits. It checks text and known manifests for
credentials, dangerous execution, prompt injection, obfuscation, persistence,
exfiltration, excessive permissions, lifecycle hooks, unsafe archives, unpinned
dependencies, and risky cross-file delegation. It never follows links or executes
package content. Sensitive matches are redacted from output.

See [Security scan](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/security-scan.md) for the complete rule list, execution
flow, configuration, and scope limits.

## Evidence, explanations, and engineering debt

```bash
skilltrustops certify .
skilltrustops explain STO-SEC-103 --report scan.json
skilltrustops scan . --debt-report engineering-debt.md
```

`certify` is an evidence matrix, not a blanket badge: unsupported controls are
shown as `NOT ASSESSED`. `explain` connects a stable rule ID to observed evidence,
risk, remediation, and primary references. The debt report groups and prioritizes
the same findings without inventing a score.

## Agent-to-Skill trust boundary

SkillTrustOps is a pre-trust review gate. It evaluates an untrusted skill before
a reviewer allows an agent runtime to load it; it is not an inline production
proxy.

### Static review stays local

[![Static review trust boundary sequence](https://raw.githubusercontent.com/rakeshcheekatimala/skilltrustops/library/docs/images/skilltrustops-static-review.png)](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/images/skilltrustops-static-review.png)

### Red-team testing uses simulated tools

[![Red-team testing with simulated tools sequence](https://raw.githubusercontent.com/rakeshcheekatimala/skilltrustops/library/docs/images/skilltrustops-redteam-flow.png)](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/images/skilltrustops-redteam-flow.png)

## Red-team a skill

After creating and reviewing an adjacent behavioral manifest, use the same scan
workflow:

```bash
uv run skilltrustops scan path/to/SKILL.md --redteam
```

This primary workflow uses the offline deterministic reference target. Advanced
live-provider and sandbox configuration remains in
[red-team testing](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/red-team-testing.md).

## Measured on 605 public skills

The final lean-package benchmark used Python 3.11, seven Docker CPU/memory
profiles, five complete runs per profile, and no model or API key. Timed
containers had networking disabled.

| Docker limit | Median for 605 skills | Throughput | Peak memory |
| --- | ---: | ---: | ---: |
| 0.25 CPU / 1 GiB | 57.694 s | 10.486 skills/s | 126.3 MB |
| 1 CPU / 512 MiB | 26.031 s | 23.242 skills/s | 127.3 MB |
| 1 CPU / 1 GiB | 25.484 s | 23.740 skills/s | 123.7 MB |
| 2 CPU / 1 GiB | 25.398 s | 23.821 skills/s | 124.4 MB |

All 605 skills completed with zero scanner errors. 137 passed the selected
policy and 468 produced findings for review. Those counts are not labels of
safe or malicious content. The public corpus has no adjudicated ground truth.

[Open the benchmark dashboard source](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/benchmarks/market-scan/index.html), read the
[plain-English summary](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/benchmarks/market-scan/BENCHMARK-SUMMARY.md), or verify
the compressed raw results and checksums in
[`results/library-2026-08-05`](https://github.com/rakeshcheekatimala/skilltrustops/tree/library/benchmarks/market-scan/results/library-2026-08-05).
The 500-case calibration report is a constructed regression result, not an
independent real-world accuracy claim.

## Documentation

| Guide | Use it when you need to… |
| --- | --- |
| [Documentation home](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/README.md) | Find the right guide and understand the trust model. |
| [Getting started](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/getting-started.md) | Install SkillTrustOps and complete a first assessment. |
| [Policy guide](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/policy-guide.md) | Create, validate, discover, and maintain `skilltrustops.yaml`. |
| [Policy reference](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/policy-reference.md) | Look up every supported policy field and constraint. |
| [Security scan](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/security-scan.md) | Understand secret and dangerous-instruction checks, execution flow, and limits. |
| [Project assurance](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/project-assurance.md) | Verify test, coverage, security, package, and release evidence for this library. |
| [Red-team testing](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/red-team-testing.md) | Decide when to test, activate it, review manifests, and interpret evidence. |
| [Security best practices](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/security-best-practices.md) | Operate SkillTrustOps safely in development and CI. |
| [Troubleshooting](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/troubleshooting.md) | Resolve common policy, provider, sandbox, and exit-code failures. |

## What the decisions mean

| Decision | Meaning |
| --- | --- |
| `passed_scope` | Every applicable case passed for the exact approved package, model, harness, sandbox boundary, and attack definitions recorded in evidence. |
| `blocked` | At least one deterministic assertion confirmed a security failure. |
| `inconclusive` | Required evidence was missing or uncertain, a draft was unapproved, or the configured isolation boundary was non-certifying. |

`passed_scope` is scoped evidence, not a universal safety guarantee. Never convert
`inconclusive` into a pass.

## Development

```bash
uv run --extra dev pytest
uv run --extra dev ruff check .
uv run --extra dev mypy src
uv build
```

## License

MIT. See [`LICENSE`](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/LICENSE).
