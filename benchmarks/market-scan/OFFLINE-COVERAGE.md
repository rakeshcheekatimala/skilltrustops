# Deterministic offline benchmark coverage

No benchmark command in this suite needs an LLM, `OPENAI_API_KEY`, or any model
provider. Network access is used only while reconstructing public source
snapshots and building the image. Every timed scan runs with Docker networking
disabled.

## Features exercised

| Feature | Evidence | Scope |
| --- | --- | --- |
| Public Python API | 97-test suite and Docker runner import `skilltrustops.scan` | File and folder entry points |
| Recursive discovery | 605 nested `SKILL.md` paths in the corpus lock | Regular, non-symlink files only |
| One policy per folder | Same policy SHA in every raw report | `recommended-v2` |
| Lint | Per-skill lint status, timing and findings | Agent Skills structure/frontmatter |
| Security | Per-skill security status, timing and findings | Full package, archives, links, dependencies, lifecycle, prompt and code risk |
| Privacy | Per-skill privacy status, timing and findings | Package-wide email, phone, US SSN and payment card patterns |
| Error separation | Unit tests plus batch schema | Scanner errors never become passes |
| Deterministic ordering | Unit test and corpus/result paths | Sorted relative paths |
| Per-skill timing | Every raw Docker profile, five observations per skill | Total plus lint/security/privacy |
| Policy provenance | Policy SHA-256 embedded in every report | Includes referenced config hashes |
| Corpus provenance | Source commits and 605 per-skill SHA-256 hashes | Reconstructable, not vendored |
| Resource constraints | Seven cgroup profiles | CPU, memory, network, filesystem and privileges |
| Artifact integrity | `ARTIFACTS.sha256` | All compressed raw result files |
| Python packaging | Wheel and sdist build successfully | Python 3.11 minimum; 3.11–3.13 CI |
| Deterministic red-team harness | Unit tests exercise resistant/vulnerable reference targets | Harness self-test, not real-model safety |

## `recommended-v2` defaults

### Lint

- Requires a readable, regular, non-symlink file named `SKILL.md`.
- Limits each skill file to 1 MiB and requires UTF-8.
- Parses YAML frontmatter and validates the Agent Skills specification.
- Validates name format/length and parent-directory match.
- Requires a description and instruction body.
- Validates supported top-level fields: `name`, `description`, `license`,
  `compatibility`, `metadata`, and experimental `allowed-tools`.

### Security

- Built-in, dependency-free secret scanner.
- Private-key headers, AWS access-key IDs, GitHub tokens, generic assigned
  credentials, and test canaries.
- Python code-fence AST checks for `eval`, `exec`, `os.system`, and subprocess
  calls using `shell=True`.
- Text checks for recursive/forced `rm` and `curl`/`wget` piped to a shell.
- Bounded whole-package inspection for prompt injection, obfuscation,
  persistence, exfiltration, permission abuse, lifecycle hooks, links, unsafe
  archives, unpinned dependencies, missing references, and cross-file risk.
- Findings redact matched values.

### Privacy

- Email addresses.
- Common phone-number format.
- US Social Security number format.
- 13–19 digit payment-card candidates validated with Luhn.

### Red-team sandbox defaults

The repository policy configures Docker, Alpine 3.20, 90-second timeout, 64
processes, 256 MiB, one CPU, UID/GID 65532 and 16 MiB tmpfs. These settings apply
only when `redteam run` is explicitly invoked. Static batch scanning does not
execute skills or start the red-team sandbox.

## Explicit non-coverage

Static rules use deterministic parsing, manifest checks, and pattern analysis.
They do not prove author intent, execute code, resolve the full transitive
dependency graph, or semantically understand every novel injection or
obfuscation. The benchmark does not measure whether a skill improves agent task
performance, and its public corpus is not labeled security ground truth.

The reference red-team models are transparent fixtures that prove harness
assertions and evidence paths. They are not substitutes for behavioral testing
of a real model. These limitations must stay next to public benchmark claims.
