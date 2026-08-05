# Anti-patterns

## Do not treat a clean scan as permanent trust

`passed_scope` applies only to the recorded inputs, policy, rules, model, and
attacks. Rescan after any of them changes.

## Do not convert scanner errors into passes

Exit code `2` means no trustworthy decision was produced. Fail closed in CI and
surface the error to an operator.

## Do not scan a manifest while loading different files at runtime

Scan the exact package artifact that the agent will load. A clean source tree does
not attest to a separately built or downloaded archive.

## Do not send sensitive production data through red-team fixtures

Use synthetic records and canaries. Live model providers receive the test context
sent to them; static scanning is the local-only path.

## Do not hide findings behind a single score

Use rule IDs, evidence, policy hashes, and remediation. A score without those
inputs is not an auditable trust decision.

## Do not add suppressions without an owner and expiry

Suppressions are reviewed exceptions, not a way to make CI green. Keep their
scope narrow and remove them when the underlying risk is fixed.
