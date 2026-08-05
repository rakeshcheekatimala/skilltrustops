# Exit codes and rule compatibility

| Code | Contract |
| ---: | --- |
| 0 | The requested check completed with no unsuppressed findings, or behavioral testing returned `passed_scope`. |
| 1 | Findings were reported, or behavioral testing returned `blocked`. |
| 2 | Configuration, input, provider, or scanner error prevented a reliable result. |
| 3 | Behavioral testing was `inconclusive`; it must never be converted into a pass. |

Every batch report contains `ruleset_version`. Within one rule-set version, a rule
ID retains its security meaning. New detections may be added in a minor rule-set
version. Removing a rule, changing its meaning, or changing a report schema
requires a documented compatibility change. Suppressions require a rule ID,
path, justification, and expiry; fingerprinted baselines suppress only the exact
reviewed finding.
