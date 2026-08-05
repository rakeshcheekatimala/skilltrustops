# Project assurance

SkillTrustOps uses evidence-linked status checks instead of a self-issued
"secure" certificate. A green badge means that a named workflow completed for a
specific commit. Open the badge to inspect its run, inputs, logs, and retained
artifacts.

## Assurance gates

| Gate | Scope | Blocking behavior | Evidence |
| --- | --- | --- | --- |
| CI test matrix | Linux, macOS, Windows; Python 3.11, 3.12, 3.13 | Any failed test or coverage below 80% fails CI | Workflow logs and `coverage.xml` artifact |
| Quality | Ruff, strict mypy, documentation links, deterministic calibration | Any error or generated-data drift fails CI | Workflow logs and repository diff |
| Bandit 1.9.4 | Python source under `src/skilltrustops` | Any unsuppressed finding fails CI and release | Workflow logs; narrow suppressions include an inline reason and rule ID |
| [PyPA pip-audit](https://github.com/pypa/pip-audit) 2.10.1 | Fully pinned runtime dependency graph exported from `uv.lock` with hashes | Any known advisory fails CI and release | Workflow logs and the committed lockfile |
| [Snyk Open Source](https://docs.snyk.io/snyk-cli/commands/test) 1.1306.2 | Installed runtime graph exported from `uv.lock` | Any Snyk finding at low severity or above fails the Snyk workflow | Snyk workflow logs |
| [Snyk Code](https://docs.snyk.io/snyk-cli/commands/code-test) 1.1306.2 | Python source | Any Snyk finding at low severity or above fails the Snyk workflow | Snyk workflow logs and Snyk project |
| [CodeQL](https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning-with-codeql) | Python source with the `security-extended` query suite | Analysis failure fails the workflow; findings are reviewed in GitHub code scanning | Security tab and workflow logs |
| Package verification | Wheel, source archive, metadata, and isolated installs | Build, Twine, or either smoke test failure blocks CI and release | Downloadable package-assurance artifact |
| [OpenSSF Scorecard](https://github.com/ossf/scorecard-action) | Public repository and supply-chain practices | Reports posture; it is not a merge gate | Public Scorecard result and SARIF |
| Release provenance | Distributions and SPDX 2.3 SBOM | A failed attestation or publish step blocks the release | PyPI attestations and GitHub artifact attestations |

No vulnerability is ignored globally. A static-analysis false positive may be
suppressed only at the exact line, with the scanner rule ID and a reason that a
reviewer can challenge.

## Configure Snyk once

The Snyk credential is separate from the PyPI upload token. Never reuse or paste
a PyPI token into Snyk.

1. In Snyk, create a personal or service-account token and enable Snyk Code for
   the organization that will own this project.
2. In GitHub, open **Settings → Secrets and variables → Actions** and create a
   repository secret named `SNYK_TOKEN`.
3. Run the **Snyk Security** workflow manually once. Both `Snyk Open Source` and
   `Snyk Code` must pass before treating its badge as evidence.
4. Make `Snyk Security / Dependencies and Python source` a required status check
   in the default-branch ruleset.

The workflow deliberately fails when the secret is absent. Pull requests from
forks cannot receive repository secrets, so Snyk is skipped for those pull
requests; the credential-free Bandit, pip-audit, and CodeQL gates still run.
After a clean branch scan, `snyk monitor` registers the locked dependency
snapshot so Snyk can notify the project when its advisory data changes between
scheduled workflow runs.

Snyk does not consume this project's `uv.lock` directly. The workflow exports a
temporary, fully resolved requirements file and scans it after installing the
locked environment. That temporary file is never shipped in the Python package.

## Reproduce the core checks locally

```bash
uv sync --locked --extra dev
uv run pytest --cov=skilltrustops --cov-report=term-missing
uv run ruff check .
uv run mypy src

uvx --from bandit==1.9.4 bandit -r src/skilltrustops -q
uv export --locked --no-dev --no-emit-project \
  --format requirements-txt \
  --output-file /tmp/skilltrustops-audit-requirements.txt
uvx --from pip-audit==2.10.1 pip-audit \
  --disable-pip --require-hashes --progress-spinner off \
  --requirement /tmp/skilltrustops-audit-requirements.txt
```

After authenticating the Snyk CLI with your own Snyk account, reproduce the
vendor scan with:

```bash
uv sync --locked
uv export --locked --no-dev --no-emit-project --no-hashes \
  --format requirements-txt \
  --output-file /tmp/skilltrustops-snyk-requirements.txt
uv run --no-sync npx --yes snyk@1.1306.2 test \
  --file=/tmp/skilltrustops-snyk-requirements.txt \
  --package-manager=pip --command=python --severity-threshold=low
uv run --no-sync npx --yes snyk@1.1306.2 code test --severity-threshold=low
```

## Repository settings that make the evidence enforceable

Workflows alone can be bypassed by a maintainer unless the hosting controls
enforce them. Configure the default branch to:

- require pull requests and at least one independent review;
- dismiss stale approvals when code changes;
- require CI, Snyk, and CodeQL status checks before merge;
- require conversation resolution and prevent force pushes;
- enable Dependabot alerts and security updates;
- enable secret scanning and push protection; and
- allow private vulnerability reports.

OpenSSF Scorecard will expose missing repository-level controls. Apply for the
OpenSSF Best Practices badge only after completing its questionnaire and meeting
its criteria; do not display that badge before it has actually been awarded.

## What a green result does not prove

A passing run cannot establish that software has no vulnerabilities. It does not
cover vulnerabilities unknown to advisory databases, defects outside scanner
rules, the security of a consumer's deployment, or changes made after the
referenced commit. Formal certification and an independent penetration test are
separate activities. Report suspected vulnerabilities privately under
[`SECURITY.md`](../SECURITY.md).
