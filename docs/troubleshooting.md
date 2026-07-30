# Troubleshooting

## Policy file is not discovered

The automatic filename must be `skilltrustops.yaml`, `skilltrustops.yml`, or
`skilltrustops.json` at the current Git repository root. A file named
`policy.yaml` is not discovered automatically.

```bash
uv run skilltrustops policy validate --policy /absolute/path/to/policy.yaml
```

Use `--policy` explicitly for another filename or location.

## Multiple repository policies found

Keep exactly one conventional filename at the Git root, or select the intended
file with `--policy`. Do not keep both YAML and JSON discoverable copies.

## Policy validation rejects an unknown field

The schema is strict. Remove the unsupported field and consult
[Policy reference](policy-reference.md). In particular, `redteam.enabled` is not
valid; invoke `redteam run` to start behavioral testing.

## Security or privacy is “not configured”

Use `profile: recommended-v2` and include both complete `checks.security` and
`checks.privacy` blocks. Changing only the profile name from `recommended-v1`
does not create the required configuration.

## No adjacent red-team manifest was found

Place exactly one of these beside `SKILL.md`:

- `skilltrust-package.yaml`
- `skilltrust-package.yml`
- `skilltrust-package.json`

Or create it with:

```bash
uv run skilltrustops redteam init path/to/SKILL.md \
  --provider deterministic
```

## Generated manifest is stale

`SKILL.md` changed after generation. Regenerate the manifest, review every
security-relevant field, and approve the new draft. Do not copy the old source
hash into the new file.

## A clean run is still inconclusive

Common causes:

- `generation.requires_review` is still `true`;
- a provider call or assertion could not be evaluated;
- the sandbox probe failed or was unavailable; or
- Docker passed, but Docker is intentionally a non-certifying development
  boundary.

Read `decision_reasons` in `report.json` and the next steps in
`friendly-report.md`. Never promote `inconclusive` to `assured` manually.

## Docker or gVisor is unavailable

- Confirm Docker is installed and its daemon is running.
- For gVisor, use a Linux host whose Docker daemon is configured with the
  `runsc` runtime.
- Pin the gVisor probe image by digest.
- Review sandbox status and explanation in the generated report.

Sandbox failure prevents attacks from starting and returns exit code `3`.

## OpenAI authentication fails

Set `OPENAI_API_KEY` in the process environment or an uncommitted `.env` found
from the current repository. Existing process values take precedence. Do not
put the key in `skilltrustops.yaml` or `skilltrust-package.yaml`.

## Command accepts no directory

Phase 1 static commands accept one `SKILL.md` path and do not recurse:

```bash
uv run skilltrustops lint path/to/SKILL.md
```

Run the command once per skill in repository automation.

## Exit code reference

| Code | Meaning |
| --- | --- |
| `0` | Passed or `assured`. |
| `1` | Violations found or behavioral decision `blocked`. |
| `2` | Invalid command, policy, package, or scanner configuration. |
| `3` | Behavioral decision `inconclusive`. |

In CI, fail on every non-zero exit code.
