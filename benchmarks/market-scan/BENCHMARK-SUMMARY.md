# SkillTrustOps benchmark summary

## Result at a glance

This is the first benchmark of the lean Python 3.11 package with whole-package
security and privacy scanning enabled. It replaces the old scanner-only timing
claim; the historical artifacts remain available for comparison.

| Question | Measured result |
| --- | --- |
| Corpus | 605 public skills from 8 repositories at immutable commits |
| Integrity | 605 file hashes; combined fingerprint `58525efe…96f4b` |
| Completeness | 605 discovered, 605 scanned, 0 scanner errors |
| Findings | 137 passed policy; 468 require review; neither is a safety certificate |
| Smallest profile | 1 CPU / 512 MiB: 26.031 s median, 23.242 skills/s |
| Lowest CPU profile | 0.25 CPU / 1 GiB: 57.694 s median, 10.486 skills/s |
| Fastest measured | 1 CPU / 3 GiB: 24.342 s median, 24.854 skills/s |
| Peak container memory | 130 MB or less across all profiles |
| LLM or API key | Not used; timed containers had networking disabled |

## Docker comparison

| Controlled profile | Median for 605 | Throughput | p95/skill | Peak memory |
| --- | ---: | ---: | ---: | ---: |
| 0.25 CPU / 1 GiB | 57.694 s | 10.486/s | 309.123 ms | 126.3 MB |
| 0.50 CPU / 1 GiB | 32.008 s | 18.902/s | 182.529 ms | 129.0 MB |
| 1 CPU / 512 MiB | 26.031 s | 23.242/s | 124.572 ms | 127.3 MB |
| 1 CPU / 1 GiB | 25.484 s | 23.740/s | 122.571 ms | 123.7 MB |
| 1 CPU / 2 GiB | 24.904 s | 24.293/s | 121.859 ms | 124.3 MB |
| 1 CPU / 3 GiB | 24.342 s | 24.854/s | 121.438 ms | 124.6 MB |
| 2 CPU / 1 GiB | 25.398 s | 23.821/s | 114.670 ms | 124.4 MB |

Five complete runs were performed per profile. Results contain every skill,
check, finding, and timing. Other Docker workloads were active, profiles ran in
a fixed order, and the scanner is sequential. Treat small differences among the
1–2 CPU profiles as noise, not proof that added memory or CPU reduces speed.

## What the numbers prove

- Folder discovery, bounded package reading, lint, security, and privacy checks
  complete without a model provider in containers as small as 512 MiB.
- The report preserves one policy hash, rule-set version, per-skill results, and
  per-check timings across the corpus.
- The package stays well below the measured memory limits.

The numbers do **not** prove that 137 skills are safe or 468 are malicious. The
public corpus has no adjudicated ground truth. Accuracy metrics in
`../calibration/results.json` describe a constructed regression suite whose
independent review is incomplete; they are not real-world accuracy estimates.

## Reproduce and inspect

```bash
./benchmarks/market-scan/reproduce.sh
```

Open `index.html` for the interactive report. The latest raw run is in
`results/library-2026-08-05/`; verify it with `ARTIFACTS.sha256`. Use
`corpus.lock.json` and `sources.yaml` to reconstruct the exact inputs.
