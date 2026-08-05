# SkillTrustOps publication readiness and benchmark strategy

**Assessment date:** 2026-08-05  
**Decision:** **Do not market or publish SkillTrustOps as an enterprise-grade skill
certification product yet.** A Python preview release is technically buildable, but
the security coverage, corpus evaluation, calibration, and release governance do
not yet support the words *certified*, *assured*, or *enterprise-ready*. There is
no TypeScript library implementation yet.

## Executive assessment

SkillTrustOps has a credible foundation: it is local-first for static analysis,
does not execute submitted skill content, produces redacted findings, binds
behavioral evidence to hashes, simulates tool calls in memory, and distinguishes
blocked from inconclusive results. The current repository has 85 passing tests,
passes Ruff on the library/test/backend sources, passes strict mypy, and builds a
Python wheel and source distribution.

Its present detection surface is narrow relative to current competitors and the
agent-skill threat model. Static analysis mainly covers structure, a small set of
secret formats, four PII types, Python `eval`/`exec`, selected shell invocation,
recursive `rm`, and download-to-shell. Behavioral testing has six built-in attack
families and five deterministic assertions. It evaluates a model's response to a
skill, not the complete skill package, repository, dependency graph, install
lifecycle, or real agent runtime. The deterministic reference target is a test
fixture, so a reference-target pass is not evidence that a real model or agent is
safe.

The defensible near-term positioning is:

> A local-first, best-effort pre-trust scanner and behavioral test harness for
> Agent Skills. It produces scoped evidence; it does not certify safety.

## What is ready and what is not

| Area | Current state | Publication implication |
| --- | --- | --- |
| Python packaging | `0.1.0` wheel and sdist build | Suitable for a preview after release hygiene work |
| TypeScript SDK | No TypeScript library/package; only a Vite web app | Do not announce a TypeScript SDK |
| Static safety | Local, deterministic, bounded single-file loading | Strong differentiator, but limited coverage |
| Skill format | Agent Skills frontmatter validation | Useful; must track spec and platform extensions |
| Behavioral tests | Synthetic records, in-memory tools, evidence hashes | Promising research/preview capability |
| Offline red team | Reference fixture plus deterministic assertions | Useful for harness QA, not model red teaming |
| Real red team | One OpenAI Responses API adapter | Not provider-neutral; non-deterministic and costly |
| Batch evaluation | One skill per command | Missing for 200-skill benchmark |
| Dataset | No versioned labeled corpus | Results cannot yet support accuracy claims |
| Metrics | Static scan duration per command only | Missing end-to-end, percentile, throughput, and cost data |
| Enterprise controls | No SBOM/signing/SARIF/security policy/release provenance shown | Blocks serious procurement conversations |

## Can red-team testing run without AI?

Yes, but only in two explicitly separated meanings:

1. **Deterministic security testing without an LLM:** mutate skills, scan known
   malicious/benign fixtures, validate authorization rules, replay recorded model
   traces, run canary assertions, and fuzz parsers and manifests. This should be
   the default reproducible benchmark and can measure scanner precision, recall,
   robustness, and speed.
2. **Behavioral red teaming of an AI agent:** this requires an actual model or a
   previously captured model trace. The current `resistant-demo` and
   `vulnerable-demo` targets only prove that the harness can recognize designed
   pass/fail paths. They do not predict how Claude, Codex, Copilot, or another
   runtime will behave.

Never combine reference-fixture results with real-model results in one safety
rate. Label the execution mode in every chart and artifact.

## Benchmark scope: 200 public skills and 500 labeled cases

The first public benchmark should evaluate **200 unique, real public skills** and
**500 labeled test cases**. It should not describe 500 cases as 500 skills.

### Corpus composition

Use a frozen, stratified snapshot rather than “top 200”:

| Stratum | Skills | Purpose |
| --- | ---: | --- |
| Matt Pocock and other high-visibility engineering collections | 25 | Popular real-world workflows and false-positive pressure |
| Tessl public registry packages | 50 | Registry-native format and package metadata |
| Anthropic/public reference skills | 20 | Specification and complex package patterns |
| Other established public repositories/registries | 65 | Ecosystem diversity across domains and authors |
| Security-sensitive skills (shell, browser, credentials, deployment) | 20 | High-risk benign and ambiguous behavior |
| Confirmed malicious or intentionally vulnerable fixtures | 20 | Recall and end-to-end failure validation |
| **Total** | **200** | |

Do not copy third-party skill bodies into a new repository indiscriminately.
Store a manifest containing source URL, repository, commit SHA, skill path,
retrieval time, declared license, content SHA-256, and redistribution decision.
Vendor content only when its license permits it; otherwise fetch an immutable
commit during corpus preparation or store a derived fixture that is independently
licensed. Deduplicate by normalized content hash and near-duplicate similarity.

### The 500-case dataset

Use 300 positive/risky cases and 200 benign/hard-negative cases. Every case needs
two independent annotations and adjudication on disagreement.

| Family | Positive | Benign | Examples |
| --- | ---: | ---: | --- |
| Prompt/goal injection | 55 | 35 | direct, indirect, role/authority, encoded, split instruction |
| Data exfiltration/credential access | 45 | 25 | environment, files, network, DNS/URL, clipboard-like flows |
| Dangerous execution/install lifecycle | 50 | 25 | shell, interpreters, hooks, package scripts, downloaded payloads |
| Permission/agency/tool misuse | 40 | 25 | excessive tools, destructive/financial/external actions, bypassed confirmation |
| Supply chain and package context | 35 | 25 | scripts, references, assets, symlinks, archives, dependencies, provenance |
| Persistence/memory/context poisoning | 25 | 20 | instruction-file edits, startup files, agent memory, cross-session changes |
| Obfuscation/parser evasion | 30 | 25 | Unicode, homoglyphs, HTML, base encodings, concatenation, malformed frontmatter |
| Privacy/secret formats | 20 | 20 | international identifiers and realistic placeholders |
| **Total** | **300** | **200** | |

The label schema should contain `case_id`, `source_type`, `license`, `family`,
`severity`, `ground_truth`, `evidence_span`, `expected_rules`, `platform`,
`annotators`, `adjudication`, and `notes`. Publish a dataset card describing
collection bias, exclusions, limitations, and intended/non-intended use.

### Required metrics

Report more than a pass percentage:

- Per-rule and macro/micro precision, recall, F1, false-positive rate, and
  false-negative rate with bootstrap 95% confidence intervals.
- Coverage rate: parsed, unsupported, scanner error, and intentionally skipped.
- Verdicts: `pass`, `needs_review`, `blocked`, and `inconclusive`. Avoid “okay,”
  which is not operationally defined.
- Runtime: cold-start and warm p50/p95/p99 latency, peak RSS, files/bytes scanned,
  throughput at concurrency 1/2/4/8, and full 200-skill wall time.
- Behavioral runs: provider/model/version, agent runtime, temperature/seed where
  supported, repetitions, attack-success rate, refusal false positives, tokens,
  latency, and monetary cost.
- Reproducibility: OS, architecture, CPU, memory, Python/Node versions, package
  version, policy hash, corpus version, and Git commit.

For the present machine, the benchmark header should say **MacBook Pro Mac14,9;
Apple M2 Pro; 10 cores (6 performance, 4 efficiency); 16 GB RAM; macOS 26.5.2;
arm64; Python 3.12.4**. Do not publish the device serial number or UUID.

Use at least five clean benchmark runs, randomize skill order, record thermal and
power state, warm up before warm measurements, and report medians and percentiles
rather than a single stopwatch result. Network/model latency must be charted
separately from local scanning.

## Proposed separate repository

Recommended name: **`skilltrust-bench`**. “Stress testing” is too generic and
undersells the reproducibility and dataset role.

```text
skilltrust-bench/
├── README.md
├── LICENSE
├── CITATION.cff
├── DATASET_CARD.md
├── SECURITY.md
├── corpus/
│   ├── sources.yaml
│   ├── snapshots.lock.json
│   └── licenses/
├── cases/
│   ├── schema.json
│   ├── benign/
│   ├── malicious/
│   └── mutations/
├── labels/
│   ├── annotations.jsonl
│   └── adjudicated.jsonl
├── runners/
│   ├── local_static.py
│   ├── behavioral.py
│   └── competitors.py
├── analysis/
│   ├── metrics.py
│   ├── statistics.py
│   └── charts.py
├── results/
│   └── <release>/<machine-profile>/
├── reports/
│   ├── benchmark.md
│   └── infographic.svg
└── .github/workflows/
```

The benchmark runner should invoke a stable public Python API, not scrape CLI
text. Results must be append-only JSONL/Parquet with a documented schema. The
infographic should be generated from those result files, never edited by hand.

## Product changes required before running the public benchmark

### P0: blockers

1. Replace safety/certification language with scoped, best-effort terminology.
   Rename `assured` to a less absolute verdict such as `passed_scope`, or make the
   exact assurance scope unavoidable in machine and human output.
2. Scan the complete skill directory safely: `SKILL.md`, scripts, references,
   assets, manifests, symlinks, archives, executable files, and dependency files.
   The current one-file boundary misses the most consequential package risks.
3. Add batch and library APIs with stable typed result schemas, explicit scanner
   errors, deterministic ordering, cancellation/timeouts, and concurrency limits.
4. Add prompt-injection, exfiltration, persistence, obfuscation, network, package
   lifecycle, dependency, permission, and cross-file dataflow rules. A few regexes
   cannot support broad “trust” claims.
5. Build and independently label the 500-case calibration set before scanning the
   200-skill corpus. Freeze the policy and tool version before evaluation.
6. Separate scanner correctness, skill risk, and agent behavior into different
   scores. A skill can be structurally valid, risky, useful, or safely handled by
   one runtime; these are not the same outcome.

### P1: needed for a credible public Python release

- Support Python 3.10 or 3.11 onward unless 3.12-only behavior is essential.
- Remove web-server dependencies from the minimal scanner install; expose API/UI
  extras separately.
- Add public API documentation, semantic-versioning policy, changelog, security
  disclosure policy, contribution guide, code of conduct, and maintainer/contact
  metadata.
- Publish SBOMs, hashes, signed release provenance, dependency scanning, secret
  scanning, pinned CI actions, and reproducible release automation with trusted
  publishing.
- Add SARIF, baseline/suppression files with justification and expiry, rule
  taxonomy/versioning, and exit-code contracts.
- Add Windows and Linux CI, Python version matrix, property/fuzz tests, malformed
  input tests, large-file/time/memory limits, and archive/symlink escape tests.
- Make output paths privacy-safe and add a data-retention/redaction model for
  behavioral transcripts.
- Fix repository-wide Ruff failures in `artifacts/product-video/render.py`, or
  exclude generated/media tooling with an explicit lint configuration.

### P2: enterprise and TypeScript readiness

- Define a language-neutral JSON Schema/OpenAPI contract first. Generate or
  implement Python and TypeScript clients against the same contract and shared
  conformance fixtures.
- Add policy packs mapped to OWASP Agentic/LLM risks, MITRE ATLAS, and enterprise
  control evidence without implying formal compliance certification.
- Add signed policy/rule packs, offline update bundles, audit logging, RBAC around
  exceptions, retention controls, and documented air-gapped operation.
- Run third-party security review and publish a threat model, abuse cases,
  remediation SLA, and vulnerability handling history.
- Provide deployment architecture, performance/capacity envelope, support model,
  data-processing terms, and provider-specific privacy details before approaching
  Singtel, StarHub, or Netflix.

## Competitive and community risk

The category already includes mature, well-funded open-source scanners. Cisco's
Skill Scanner combines pattern rules, behavioral dataflow, and LLM analysis and
exports SARIF. Snyk Agent Scan inventories multiple agent ecosystems and scans
skills and MCP components. SkillTester explicitly compares with-skill runs to a
matched no-skill baseline. SkillInject includes subtle and context-dependent
injections, not just obvious strings. A launch that claims “certification” from a
small regex set and reference fixtures will be compared unfavorably with these.

Likely community criticisms and the correct response:

| Criticism | Why it would be fair today | Required response |
| --- | --- | --- |
| “Security theater/certification washing” | `assured` can be read as universal | Narrow terminology and publish limitations prominently |
| “Regex scanner with a trust brand” | Core static coverage is currently small | Publish rule coverage and benchmark precision/recall |
| “Cherry-picked 200 skills” | No sampling/provenance protocol exists | Pre-register the corpus and publish immutable source SHAs |
| “Pass rate says nothing” | Ground truth and false negatives are unknown | Release the labeled 500-case calibration set and CIs |
| “The offline model test is fake” | Reference targets are designed fixtures | Call it harness self-test; never present it as agent safety |
| “You ignored files that execute” | Only one `SKILL.md` is accepted | Add whole-package, lifecycle, and dependency analysis |
| “Yet another vendor-locked LLM tool” | Live adapter is OpenAI-only | Add runtime/provider adapters and replayable traces |
| “Benchmark is not independent” | Maker evaluates own tool | Invite external annotations and competitor baselines |
| “Enterprise-ready claim is unsupported” | Governance and supply-chain controls are absent | Complete P1/P2 evidence and an external assessment |

## Go/no-go by audience

- **Open-source developer preview:** conditional go after P0 terminology/API work,
  release hygiene, and an initial labeled calibration report.
- **General Python package marketed as best-effort scanning:** go only after the
  500-case dataset demonstrates acceptable error rates and whole-package scanning
  exists.
- **TypeScript library:** no-go; it has not been designed or implemented.
- **Enterprise pilot with a security team:** possible later as a clearly scoped,
  non-production evaluation after P1, with customer data excluded.
- **Enterprise production or certification claim:** no-go until P2, external
  review, and multi-runtime benchmark evidence are complete.

## Infographic specification

Generate one SVG/PNG and an accessible HTML report from benchmark artifacts. It
should show:

1. Corpus provenance: 200 skills, source strata, licenses, and frozen date.
2. Outcome funnel: scanned, parse errors, pass, needs review, blocked,
   inconclusive—without implying that “pass” means safe.
3. Accuracy on 500 labeled cases: precision/recall/F1 with confidence intervals,
   plus false negatives by attack family.
4. Performance on the M2 Pro: cold/warm p50/p95/p99, throughput, peak memory, and
   total 200-skill wall time.
5. Behavioral results in a separate panel by real model/runtime and repetition;
   reference fixtures appear only as harness self-tests.
6. Scope/limitations footer, tool/policy/corpus versions, commit SHAs, and a link
   to machine-readable results.

## Evidence-based release sequence

1. **Threat model and terminology release:** define claims and non-claims.
2. **Scanner contract release:** batch Python API, result schema, whole-package
   reader, and stable rule taxonomy.
3. **Calibration release:** public 500-case dataset card, annotation agreement,
   accuracy report, and adversarial regression suite.
4. **Corpus benchmark release:** frozen 200-skill source manifest, performance,
   findings, manual triage, competitor baselines, and generated infographic.
5. **Python preview:** signed artifacts and documented stable API.
6. **Enterprise pilot:** external security review and controlled customer trial.
7. **TypeScript SDK:** only after the language-neutral contract stabilizes.

## Research basis

- Agent Skills specification: <https://agentskills.io/specification>
- Matt Pocock skills repository: <https://github.com/mattpocock/skills>
- Tessl skill creation and registry workflow:
  <https://tessl.io/registry/tessl-master/tessl-master/files/docs/create/creating-skills.md>
- Anthropic public skills: <https://github.com/anthropics/skills>
- Cisco AI Defense Skill Scanner:
  <https://github.com/cisco-ai-defense/skill-scanner>
- Snyk Agent Scan: <https://github.com/snyk/agent-scan>
- OWASP LLM06 Excessive Agency:
  <https://genai.owasp.org/llmrisk/llm062025-excessive-agency/>
- SkillTester: <https://arxiv.org/abs/2603.28815>
- SkillInject: <https://arxiv.org/abs/2602.20156>

These sources establish format expectations, public corpus candidates,
competitive baselines, and current evaluation/security methodology. Counts and
registry contents are time-sensitive and must be frozen by commit/version during
benchmark collection.
