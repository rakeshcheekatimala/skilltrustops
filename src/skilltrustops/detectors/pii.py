"""Built-in deterministic PII detection with redacted evidence."""

import re

from skilltrustops.detectors.common import line_number
from skilltrustops.domain.findings import Finding, Severity
from skilltrustops.domain.skills import SkillFile
from skilltrustops.policies.models import PiiEntity

EMAIL_PATTERN = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
)
SSN_PATTERN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
PHONE_PATTERN = re.compile(
    r"(?<![\w\d])(?:\+\d{1,3}[\s.-]?)?"
    r"(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}(?!\d)"
)
CREDIT_CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


class BuiltinPiiDetector:
    """Detect selected PII entity types without exposing matched values."""

    def __init__(self, entities: tuple[PiiEntity, ...]) -> None:
        self._entities = frozenset(entities)

    def scan(self, skill_file: SkillFile) -> tuple[Finding, ...]:
        """Scan one skill file for enabled PII entities."""
        findings: list[Finding] = []

        if PiiEntity.EMAIL in self._entities:
            findings.extend(
                self._regex_findings(
                    skill_file,
                    EMAIL_PATTERN,
                    "STO-PRIV-001",
                    "Email address",
                    Severity.MEDIUM,
                    "Remove the email address or replace it with synthetic data.",
                )
            )

        if PiiEntity.SSN in self._entities:
            findings.extend(
                self._regex_findings(
                    skill_file,
                    SSN_PATTERN,
                    "STO-PRIV-002",
                    "US Social Security number",
                    Severity.HIGH,
                    "Remove the SSN and use clearly synthetic test data.",
                )
            )

        if PiiEntity.PHONE in self._entities:
            findings.extend(
                self._regex_findings(
                    skill_file,
                    PHONE_PATTERN,
                    "STO-PRIV-003",
                    "Phone number",
                    Severity.MEDIUM,
                    "Remove the phone number or replace it with synthetic data.",
                )
            )

        if PiiEntity.CREDIT_CARD in self._entities:
            for match in CREDIT_CARD_CANDIDATE.finditer(skill_file.content):
                digits = "".join(
                    character for character in match.group() if character.isdigit()
                )
                if not self._passes_luhn(digits):
                    continue
                findings.append(
                    self._finding(
                        skill_file,
                        match.start(),
                        "STO-PRIV-004",
                        "Payment card number",
                        Severity.CRITICAL,
                        "Remove the card number and use a documented test number.",
                    )
                )

        return tuple(findings)

    def _regex_findings(
        self,
        skill_file: SkillFile,
        pattern: re.Pattern[str],
        rule_id: str,
        entity_name: str,
        severity: Severity,
        remediation: str,
    ) -> list[Finding]:
        return [
            self._finding(
                skill_file,
                match.start(),
                rule_id,
                entity_name,
                severity,
                remediation,
            )
            for match in pattern.finditer(skill_file.content)
        ]

    @staticmethod
    def _finding(
        skill_file: SkillFile,
        offset: int,
        rule_id: str,
        entity_name: str,
        severity: Severity,
        remediation: str,
    ) -> Finding:
        detected_line = line_number(skill_file.content, offset)
        return Finding(
            rule_id=rule_id,
            severity=severity,
            message=f"Potential {entity_name.lower()} detected.",
            evidence=f"{entity_name} detected at line {detected_line}; value redacted.",
            remediation=remediation,
            location=f"{skill_file.path.name}:{detected_line}",
        )

    @staticmethod
    def _passes_luhn(digits: str) -> bool:
        if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
            return False
        total = 0
        parity = len(digits) % 2
        for index, character in enumerate(digits):
            value = int(character)
            if index % 2 == parity:
                value *= 2
                if value > 9:
                    value -= 9
            total += value
        return total % 10 == 0
