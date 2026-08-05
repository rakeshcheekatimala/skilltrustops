# Security policy

Do not open a public issue for a suspected vulnerability. Submit a report through
[GitHub private vulnerability reporting](https://github.com/rakeshcheekatimala/skilltrustops/security/advisories/new).
Include the affected version, reproducible input, impact, and whether untrusted
content was executed or disclosed.

Maintainers will acknowledge a report within three business days, provide an
initial assessment within seven business days, and coordinate disclosure after a
fix is available. Only the latest released minor version receives security fixes
during the `0.x` preview period.

SkillTrustOps is a best-effort pre-trust scanner. A clean result is not a security
guarantee. Never submit real secrets or personal data to live-model providers.

## Automated assurance

Repository pushes and same-repository pull requests are checked by CI, Bandit,
PyPA `pip-audit`, Snyk, and CodeQL workflows. Fork pull requests cannot receive
the Snyk secret, but the credential-free gates still run. Releases repeat the
unit, source-security, dependency, package-metadata, and isolated-install checks
before Trusted Publishing. They also produce an SPDX SBOM and GitHub
build-provenance attestations.

The status badges and their evidence are described in
[`docs/project-assurance.md`](docs/project-assurance.md). A successful scan means
that the named tools found no blocking issue in their documented scope at that
time. It does not cover undisclosed vulnerabilities, scanner blind spots,
compromised infrastructure, or deployments that differ from the locked inputs.
