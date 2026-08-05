# SkillTrustOps publication readiness and benchmark strategy

**Assessment date:** 2026-08-05  
**Decision:** **Publish only as a developer preview and pre-trust review tool.**
Whole-package scanning, scoped behavioral evidence, release controls, and a
reproducible benchmark now support that claim. They do not support calling a
skill certified safe or calling this release enterprise-ready. Independent
dataset review and an external security assessment remain release gates for
stronger claims.

## Executive assessment

SkillTrustOps is local-first for static analysis, does not execute submitted
skill content, produces redacted findings, binds behavioral evidence to hashes,
simulates tool calls in memory, and distinguishes blocked from inconclusive
results. It scans the complete bounded package: instructions, scripts,
references, assets, manifests, dependencies, archives, and links. Results can be
written as terminal output, JSON, or SARIF and compared through expiring
suppressions and fingerprinted baselines.

The deterministic reference target is still a test fixture. It proves the
harness and evidence pipeline work; it is not evidence that a real model or
agent is safe. The 500-case calibration corpus is also a constructed regression
suite whose second-review queue is public and incomplete. Its metrics must not be
presented as independently measured real-world detection accuracy.

The defensible near-term positioning is:

> A local-first, best-effort pre-trust scanner and behavioral test harness for
> Agent Skills. It produces scoped evidence; it does not certify safety.

## What is ready and what is not

| Area | Current state | Publication implication |
| --- | --- | --- |
| Python packaging | `0.1.0` wheel and sdist build | Suitable for a preview after release hygiene work |
| Static safety | Local, deterministic, bounded whole-package loading | Ready for preview use with documented limits |
| Skill format | Agent Skills frontmatter validation | Useful; must track spec and platform extensions |
| Behavioral tests | Synthetic records, in-memory tools, evidence hashes | Promising research/preview capability |
| Offline red team | Reference fixture plus deterministic assertions | Useful for harness QA, not model red teaming |
| Real red team | OpenAI and provider-neutral HTTPS adapters | Opt-in, non-deterministic, and separate from offline results |
| Batch evaluation | Recursive file/folder API and CLI with one policy and per-skill timings | Ready for deterministic static benchmarks |
| Dataset | 605 public skills locked by repository commit and per-skill hash | Reproducible performance corpus; not labeled accuracy ground truth |
| Metrics | End-to-end, per-skill/check latency, percentiles, throughput, findings, and container resources | Performance claims are supported; accuracy and live-model cost are not |
| Enterprise controls | SARIF, SBOM, provenance workflow, security/support policies | Useful foundation; external review and operational history remain absent |

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

## Release gate status

The lean whole-package benchmark has now run against all 605 locked skills. The
current raw results, checksums, and generated dashboard are under
`benchmarks/market-scan/results/library-2026-08-05`. The items below remain the
decision framework; implementation status is recorded explicitly.

### P0: blockers

1. **Implemented:** safety language is scoped and the behavioral success verdict
   is `passed_scope`.
2. **Implemented:** bounded scanning covers instructions, scripts, references,
   assets, manifests, links, archives, executables, and dependency files.
3. **Preview only:** the batch schema is versioned, but it is not promised as a
   stable 1.x contract and cancellation/concurrency remain future work.
4. **Implemented as deterministic first-pass rules:** injection, exfiltration,
   persistence, obfuscation, lifecycle, dependency, permission, and cross-file
   families. Novel semantic attacks remain a documented limitation.
5. **Incomplete:** 500 constructed cases and per-family metrics are published;
   the independent-review queue is intentionally blank and must be completed
   before an accuracy claim.
6. **Implemented in reporting:** scanner outcomes, package findings, and model
   behavior remain separate evidence surfaces.

### P1: needed for a credible public Python release

- Support Python 3.10 or 3.11 onward unless 3.12-only behavior is essential.
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
- Keep generated media and application UI code outside the Python library
  repository so the package quality gate covers the complete maintained source
  tree.

### P2: enterprise readiness

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
| “Security theater/certification washing” | `passed_scope` can be read as universal | Narrow terminology and publish limitations prominently |
| “Regex scanner with a trust brand” | Deterministic rules cannot understand every semantic attack | Publish rule scope, calibration limits, and independent review |
| “Cherry-picked public skills” | The 605-skill corpus is broad but not statistically representative | Keep immutable source SHAs and document sampling bias |
| “Pass rate says nothing” | Public-corpus ground truth and false negatives are unknown | Do not convert findings into accuracy or safety claims |
| “The offline model test is fake” | Reference targets are designed fixtures | Call it harness self-test; never present it as agent safety |
| “You ignored files that execute” | Whole-package rules are bounded and do not execute or fully resolve code | Publish limits and add deeper language-aware analysis over time |
| “Yet another vendor-locked LLM tool” | Generic HTTPS is neutral but its schema is intentionally small | Add documented adapters and replayable traces based on demand |
| “Benchmark is not independent” | Maker evaluates own tool | Invite external annotations and competitor baselines |
| “Enterprise-ready claim is unsupported” | Governance exists, but independent review and operating history do not | Keep preview positioning and complete P2 external assessment |

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
