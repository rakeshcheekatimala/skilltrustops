"""Built-in high-confidence secret and credential detection."""

import re
from dataclasses import dataclass

from skilltrustops.detectors.common import line_number
from skilltrustops.domain.findings import Finding, Severity
from skilltrustops.domain.skills import SkillFile


@dataclass(frozen=True, slots=True)
class SecretPattern:
    """One secret signature and its reporting metadata."""

    rule_id: str
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    remediation: str


SECRET_PATTERNS = (
    SecretPattern(
        rule_id="STO-SEC-001",
        name="private key",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        remediation=(
            "Remove the private key, rotate it, and load it from a secret store."
        ),
    ),
    SecretPattern(
        rule_id="STO-SEC-002",
        name="AWS access key ID",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        severity=Severity.CRITICAL,
        remediation="Revoke and rotate the AWS credential, then use a secret store.",
    ),
    SecretPattern(
        rule_id="STO-SEC-003",
        name="GitHub token",
        pattern=re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b"),
        severity=Severity.CRITICAL,
        remediation="Revoke the GitHub token and replace it with a runtime secret.",
    ),
)
GENERIC_CREDENTIAL_PATTERN = re.compile(
    r"""(?ix)
    \b(api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)\b
    \s*[:=]\s*
    ["']?([^\s"'`]{8,})["']?
    """
)
PLACEHOLDER_MARKERS = (
    "example",
    "placeholder",
    "changeme",
    "redacted",
    "your_",
    "your-",
    "${",
    "{{",
    "<",
)


class BuiltinSecretDetector:
    """Find common credentials while never returning their full values."""

    def scan(self, skill_file: SkillFile) -> tuple[Finding, ...]:
        """Scan text with deterministic signatures and redacted evidence."""
        findings: list[Finding] = []
        occupied: list[tuple[int, int]] = []

        for signature in SECRET_PATTERNS:
            for match in signature.pattern.finditer(skill_file.content):
                occupied.append(match.span())
                findings.append(
                    Finding(
                        rule_id=signature.rule_id,
                        severity=signature.severity,
                        message=f"Potential {signature.name} detected.",
                        evidence=(
                            f"{signature.name.capitalize()} detected at line "
                            f"{line_number(skill_file.content, match.start())}; "
                            "value redacted."
                        ),
                        remediation=signature.remediation,
                        location=(
                            f"{skill_file.path.name}:"
                            f"{line_number(skill_file.content, match.start())}"
                        ),
                    )
                )

        for match in GENERIC_CREDENTIAL_PATTERN.finditer(skill_file.content):
            if any(start <= match.start() < end for start, end in occupied):
                continue
            value = match.group(2)
            if any(marker in value.lower() for marker in PLACEHOLDER_MARKERS):
                continue
            credential_name = match.group(1)
            detected_line = line_number(skill_file.content, match.start())
            findings.append(
                Finding(
                    rule_id="STO-SEC-004",
                    severity=Severity.HIGH,
                    message="Potential hard-coded credential detected.",
                    evidence=(
                        f"Credential assigned to {credential_name!r} at line "
                        f"{detected_line}; value redacted."
                    ),
                    remediation=(
                        "Remove the credential, rotate it if real, and load it "
                        "from a secret store or environment variable."
                    ),
                    location=f"{skill_file.path.name}:{detected_line}",
                )
            )

        return tuple(findings)
