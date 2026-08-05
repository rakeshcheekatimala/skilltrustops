# Invariants and failure modes

This document describes behavioral guarantees, not performance claims. They are
covered by automated tests and apply to the package, policy, and rule-set version
recorded in each report.

## Static-scan invariants

- Static scans do not execute submitted skill code.
- Input discovery does not follow symbolic links.
- Files and archives are read through configured size and count limits.
- Findings use stable rule IDs and include remediation text.
- Scanner, parsing, and configuration errors are reported as errors; they are
  never converted into passes.
- Exit code `0` means the recorded checks passed, `1` means findings need review,
  and `2` means the scan could not produce a trustworthy result.
- JSON and SARIF output record the effective policy and rule-set version.

## Red-team invariants

- Fixtures are synthetic and tools are in-memory simulations.
- A red-team result is scoped to the recorded skill, manifest, model, provider,
  attacks, and evidence hashes.
- Provider timeouts, malformed responses, and HTTP failures stop the assessment;
  they do not produce `passed_scope`.
- A live provider receives the submitted test context. Static scans remain local.

## Known failure modes

| Failure | Observable result | Recovery |
| --- | --- | --- |
| Invalid or missing policy | Exit `2` with a policy error | Run `skilltrustops policy validate` |
| Unreadable or oversized input | Error finding or exit `2` | Correct permissions or policy limits |
| Optional scanner unavailable | Scanner error, never a pass | Install/configure the scanner or disable it explicitly |
| Provider timeout | Typed retryable provider error | Retry with backoff or use the offline reference provider |
| Malformed provider response | Typed non-retryable response error | Fix the provider contract before retrying |
| Findings detected | Exit `1` | Review remediation and rescan |

SkillTrustOps does not currently promise a fixed latency bound. Benchmark results
describe measured environments; they are not runtime guarantees.
