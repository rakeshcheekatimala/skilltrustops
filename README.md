# SkillTrustOps

[![PyPI](https://img.shields.io/pypi/v/skilltrustops?style=flat-square)](https://pypi.org/project/skilltrustops/)
[![Python](https://img.shields.io/pypi/pyversions/skilltrustops?style=flat-square)](https://pypi.org/project/skilltrustops/)
[![CI](https://img.shields.io/github/actions/workflow/status/rakeshcheekatimala/skilltrustops/ci.yml?branch=library&label=CI&style=flat-square)](https://github.com/rakeshcheekatimala/skilltrustops/actions/workflows/ci.yml)
[![OpenSSF Best Practices](https://img.shields.io/cii/summary/13962?label=OpenSSF%20Best%20Practices&style=flat-square)](https://www.bestpractices.dev/projects/13962)
[![License: MIT](https://img.shields.io/pypi/l/skilltrustops?style=flat-square)](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/LICENSE)

**Review AI agent skills before an agent trusts them.**

An agent skill is more than a Markdown file. Its package can contain
instructions, scripts, dependencies, assets, archives and permission
assumptions. SkillTrustOps treats that package as untrusted input and produces a
policy-bound report for local review or CI.

It does not run the skill. It returns stable rule IDs, redacted evidence, clear
remediation, and a result that keeps findings separate from scanner errors.

## Install and scan

SkillTrustOps supports Python 3.11 and newer.

```bash
python -m pip install skilltrustops

skilltrustops policy init --profile recommended-v2
skilltrustops scan .
```

`scan` discovers every `SKILL.md` below the target, inspects each adjacent skill
package and applies one repository policy. `policy init` creates
`skilltrustops.yaml` and never overwrites an existing file.

Use JSON for automation or SARIF for code-scanning platforms:

```bash
skilltrustops scan . --format json > skilltrustops.json
skilltrustops scan . --format sarif > skilltrustops.sarif
```

## What it checks

| Area | Coverage |
| --- | --- |
| Skill contract | Agent Skills front matter, required fields and supported package shape |
| Package contents | `SKILL.md`, scripts, references, assets, manifests, dependency files, archive metadata and links |
| Security | Secrets, dangerous execution, prompt injection, obfuscation, persistence, exfiltration, excessive permissions and lifecycle hooks |
| Privacy | Configured email, phone, US SSN and payment-card patterns across bounded text files |
| Cross-file behavior | Missing references and delegation from `SKILL.md` into risky adjacent files |
| Behavioral testing | Optional attacks for data leakage, authorization, confirmation and simulated tool use |

The default scan runs structure, security and privacy checks. Findings include a
severity, source location, redacted evidence and a suggested fix. Reports also
record the tool version, ruleset version, effective policy and policy hash.

See the [security scan reference](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/security-scan.md)
for the complete rule list and detection limits.

## Designed for a release gate

SkillTrustOps keeps three outcomes separate:

| Exit code | Meaning |
| ---: | --- |
| `0` | The requested checks completed with no unsuppressed findings. |
| `1` | Findings require review. |
| `2` | Input, policy, provider or scanner failure prevented a trustworthy result. |
| `3` | Behavioral testing was inconclusive. Treat it as a failure. |

Scanner errors never become passes. Default JSON and SARIF reports omit
wall-clock timing so the same input and policy produce stable evidence. Add
`--metrics` when you need timings, or use `--benchmark` to replay the scan and
verify that the evidence is identical.

```bash
skilltrustops scan . --benchmark
skilltrustops scan . --metrics
```

The two modes are intentionally separate: timing is nondeterministic; trust
evidence should not be.

## From finding to fix

The CLI supports the rest of the review workflow without introducing a second
control plane:

```bash
# Explain one stable rule and include evidence from a report
skilltrustops explain STO-SEC-103 --report skilltrustops.json

# Produce a prioritized Markdown backlog from the same findings
skilltrustops scan . --debt-report engineering-debt.md

# Show which controls have evidence and which were not assessed
skilltrustops certify .
```

`certify` produces an evidence matrix, not a blanket certificate. Unsupported
controls stay `NOT ASSESSED`.

For accepted risk, generate a review-required baseline and apply it explicitly:

```bash
skilltrustops scan . --write-baseline skilltrustops-suppressions.yaml
skilltrustops scan . --suppressions skilltrustops-suppressions.yaml
```

Suppressions require a rule ID, path, justification and expiry. Fingerprinted
entries apply only to the exact finding that was reviewed.

## Test model behavior when static analysis is not enough

Static scanning answers what is present in a package. Behavioral testing asks
what a selected model attempts when an attack tries to make it reveal data,
cross an authorization boundary, skip confirmation or misuse a tool.

Add a reviewed `skilltrust-package.yaml` beside each skill, then run the offline
reference workflow:

```bash
skilltrustops scan path/to/skills --redteam
```

The reference target is a deterministic fixture. It validates manifests, attack
assertions, simulated tools, evidence capture and CI wiring without an API key.
It does not establish how an unqueried production model will behave.

For a live assessment, use the advanced red-team command with OpenAI or a
generic HTTPS model provider:

```bash
skilltrustops redteam run path/to/SKILL.md \
  --provider openai \
  --model <approved-model-id>
```

Live runs send the skill and attack context to the selected provider. Tool calls
remain in-memory simulations over synthetic data, so the harness cannot perform
the proposed filesystem, network, communication, destructive or financial
action.

Every run writes a human-readable report, structured report, event log and
integrity manifest. Its decision has deliberately narrow semantics:

| Decision | Meaning |
| --- | --- |
| `passed_scope` | Every required assertion passed for the exact package, model, harness, sandbox and attack definitions in the evidence. |
| `blocked` | At least one deterministic assertion confirmed a security failure. |
| `inconclusive` | Evidence was missing, uncertain, unapproved, or produced under a non-certifying boundary. |

`passed_scope` is evidence for a recorded scope, not a universal safety claim.
Never convert `inconclusive` into a pass.

Read [Red-team testing](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/red-team-testing.md)
for manifest review, live providers, sandbox choices and evidence handling.

## Python API

The same deterministic batch report is available as a library:

```python
from skilltrustops import scan

report = scan("path/to/skills", policy_path="skilltrustops.yaml")

for skill in report.skills:
    print(skill.relative_path, skill.status)
```

Install `skilltrustops[observability]` to emit a `skilltrustops.scan`
OpenTelemetry span. The library does not configure an exporter or record skill
contents, findings, credentials or provider payloads in span attributes.

## Local by default

| Operation | Network required | Executes submitted code |
| --- | --- | --- |
| Structure, security and privacy scan | No | No |
| Deterministic manifest generation | No | No |
| Reference red-team run | No | No |
| Live-model red-team run | Yes, to the selected provider | No |

Package inspection is bounded to 2,000 regular files and 32 MiB of input, with a
1 MiB decoded-text limit per file. Archives are inspected as metadata only; they
are never extracted. Links are reported but never followed. Crossing a bound is
an error, never a pass.

SkillTrustOps is a pre-trust review gate. It is not a runtime proxy, a malware
sandbox, or a replacement for agent permissions and isolation.

## Measured, not claimed

The committed benchmark locks 605 public skills from eight repositories by
commit and file hash. Whole-package structure, security and privacy scanning
completed for all 605 with zero scanner errors and no model or network access.

On the 1 CPU / 512 MiB profile, the median run took 26.031 seconds (23.242
skills/s) with 127.3 MB peak memory. These numbers measure compatibility,
throughput and resource use. The corpus has no adjudicated security labels, so
it does not establish real-world detection accuracy.

Read the [benchmark summary](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/benchmarks/market-scan/BENCHMARK-SUMMARY.md)
or [reproduce the run](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/benchmarks/market-scan/README.md).

## Project assurance

The library's own release path is evidence-backed:

- tests run on Linux, macOS and Windows with Python 3.11–3.13, with an 80%
  branch-coverage floor;
- Ruff, strict mypy, Bandit, pip-audit, Snyk and CodeQL cover code and locked
  dependencies;
- wheel and source distributions are built and installed in isolated smoke
  tests; and
- releases use OIDC Trusted Publishing, an SPDX SBOM and build-provenance
  attestations.

Each badge applies to a specific commit and workflow run. It does not prove that
unknown vulnerabilities do not exist. See [Project assurance](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/project-assurance.md)
for the exact gates, versions and evidence locations.

## Documentation

| Guide | Use it for |
| --- | --- |
| [Getting started](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/getting-started.md) | First policy, scan and behavioral assessment |
| [Policy guide](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/policy-guide.md) | Policy discovery, configuration and maintenance |
| [Security scan](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/security-scan.md) | Rules, package bounds and detection limits |
| [Invariants and failure modes](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/invariants-and-failure-modes.md) | Guarantees, errors and recovery |
| [Git hooks](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/git-hooks.md) | Pre-commit and pre-push integration |
| [Observability](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/observability.md) | Structured logging and OpenTelemetry |
| [Anti-patterns](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/anti-patterns.md) | Unsafe integration choices to avoid |
| [Troubleshooting](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/docs/troubleshooting.md) | Common failures and fixes |

## Development

```bash
uv sync --locked --extra dev
uv run pytest --cov=skilltrustops --cov-report=term-missing
uv run ruff check .
uv run mypy src
```

See [CONTRIBUTING.md](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/CONTRIBUTING.md)
before opening a pull request. Report security issues through
[SECURITY.md](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/SECURITY.md),
not a public issue.

## License

MIT. See [LICENSE](https://github.com/rakeshcheekatimala/skilltrustops/blob/library/LICENSE).
