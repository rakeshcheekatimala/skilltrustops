# Market scan analysis: engineering and product signals

## Result

The Python batch path scanned 605 public skills from eight repository snapshots
with zero scanner errors. Five runs took 1.899–1.997 seconds; median wall time was
1.915 seconds (315.93 skills/second). Across all runs, per-skill latency was 2.591
ms p50, 5.555 ms p95, 9.006 ms p99, and 32.151 ms maximum on the recorded M2 Pro.

The final run produced 298 no-finding results and 307 review-required results.
These outcomes are not ground truth. In particular, 239 unsupported-frontmatter
findings and 148 metadata-type findings show ecosystem compatibility gaps. The
154 email findings are also likely to contain documentation/example false
positives. Marketing “50.7% of skills are unsafe” from this run would be false.

## Repository outcomes

| Repository | Skills | No finding | Review | Median ms | Primary signal |
| --- | ---: | ---: | ---: | ---: | --- |
| mattpocock/skills | 35 | 15 | 20 | 0.978 | 20 unsupported-field findings |
| anthropics/skills | 18 | 13 | 5 | 2.252 | Mixed isolated findings; mixed licensing |
| addyosmani/agent-skills | 24 | 23 | 1 | 3.077 | One skill with security-pattern findings |
| NVIDIA/skills | 327 | 87 | 240 | 3.102 | Extension metadata dominates |
| obra/superpowers | 14 | 14 | 0 | 1.671 | No findings under this policy |
| jeffallan/claude-skills | 66 | 57 | 9 | 1.930 | Email-like strings dominate |
| daymade/claude-code-skills | 90 | 64 | 26 | 2.221 | Mixed format, privacy, and shell patterns |
| akin-ozer/cc-devops-skills | 31 | 25 | 6 | 3.229 | DevOps commands create high-risk benign pressure |

## Strongest differentiating product direction

Do not compete as “another prompt-injection scanner.” Stand out as the
**reproducible policy and evidence layer for skill portfolios**:

1. **Portfolio-native:** one policy, recursive discovery, deterministic ordering,
   per-skill timings, aggregate reports, baselines, and CI diffs.
2. **Honest decision model:** separate `compatible`, `finding`, `scanner_error`,
   `unsupported`, and `not_evaluated`; never turn uncertainty into a pass.
3. **Dialect-aware validation:** identify Agent Skills core plus Anthropic,
   Cursor, Tessl, NVIDIA, and other extensions. Unsupported metadata belongs in a
   compatibility result, not a security failure.
4. **Package context:** safely analyze scripts, references, assets, hooks,
   dependencies, symlinks, and cross-file flows. The current `SKILL.md`-only scan
   is a material limitation.
5. **Evidence integrity:** corpus commit, content hash, policy hash, rule-pack
   version, machine profile, timing, findings, suppressions, and adjudication in
   one stable schema.
6. **Calibrated findings:** contextual allowlists for example domains and
   documentation placeholders; confidence and evidence without exposing matched
   secrets; published precision/recall on the planned 500-case labeled dataset.
7. **Offline-first:** deterministic static and replay testing should work without
   an AI provider. Model behavioral testing must remain a separately labeled,
   optional layer.

## Backlash-prevention gates

Before a public security claim:

- Manually adjudicate a statistically meaningful stratified sample of findings,
  including every critical rule and at least 100 no-finding skills.
- Publish precision, recall, false-negative rate, and 95% confidence intervals on
  the independent 500-case dataset.
- Add whole-package scanning and adversarial parser/obfuscation regression tests.
- Compare against Cisco Skill Scanner and Snyk Agent Scan on identical immutable
  inputs, reporting unsupported/error outcomes fairly.
- Replace broad `passed` language in user-facing security summaries with
  `no findings under policy`, and reserve `blocked` for policy decisions.
- Publish limitations next to every chart, not only in a distant README.
- Invite external annotation and disclose conflicts: the tool author also built
  the benchmark.

The defensible public result today is performance and operational correctness:
**605 skills, zero scanner errors, median 1.915 seconds on the stated machine.**
It is not yet detector accuracy or proof of skill safety.

## Container resource result

All 605 skills completed in every tested container profile. The practical floor
tested was 0.25 CPU/1 GiB (10.621 seconds median), while 1 CPU/512 MiB completed
in 5.574 seconds median with less than 61 MB peak cgroup memory. The fastest
measured profile was 2 CPU/1 GiB at 4.848 seconds median, but improvement over one
CPU was modest because scanning is currently sequential.

Memory from 512 MiB to 3 GiB did not produce a reliable throughput improvement.
This is a positive deployment signal: the current scanner is lightweight. It is
also an experiment-design warning: other Docker workloads were active and
profiles ran sequentially, so small profile differences are noise. Use a quiet,
dedicated runner and interleaved profile order before publication.
