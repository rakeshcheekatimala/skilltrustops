"""SARIF 2.1.0 rendering for batch scan reports."""

from __future__ import annotations

from typing import Any

from skilltrustops.domain.findings import Finding
from skilltrustops.domain.reports import BatchScanReport

LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "error": "error",
    "warning": "warning",
}


def to_sarif(report: BatchScanReport) -> dict[str, Any]:
    """Return a self-contained SARIF log with relative artifact locations."""
    findings = [
        (skill.relative_path, finding)
        for skill in report.skills
        for check in skill.checks
        for finding in check.findings
    ]
    rule_ids = sorted({finding.rule_id for _, finding in findings})
    rules = [
        {
            "id": rule_id,
            "name": rule_id.replace("-", "_"),
            "shortDescription": {
                "text": next(
                    finding.message
                    for _, finding in findings
                    if finding.rule_id == rule_id
                )
            },
            "properties": {"rulesetVersion": report.ruleset_version},
        }
        for rule_id in rule_ids
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillTrustOps",
                        "version": report.tool_version,
                        "semanticVersion": report.tool_version,
                        "rules": rules,
                        "properties": {
                            "rulesetVersion": report.ruleset_version,
                            "policySha256": report.policy.sha256,
                        },
                    }
                },
                "results": [
                    _result(skill_path, finding) for skill_path, finding in findings
                ],
            }
        ],
    }


def _result(skill_path: str, finding: Finding) -> dict[str, Any]:
    location, line = _location(skill_path, finding.location)
    region = {"startLine": line} if line is not None else {}
    return {
        "ruleId": finding.rule_id,
        "level": LEVELS[finding.severity.value],
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": location},
                    **({"region": region} if region else {}),
                }
            }
        ],
        "properties": {
            "severity": finding.severity.value,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
        },
    }


def _location(skill_path: str, finding_location: str | None) -> tuple[str, int | None]:
    package = skill_path.removesuffix("SKILL.md")
    if not finding_location:
        return skill_path, None
    path, separator, candidate = finding_location.rpartition(":")
    line = int(candidate) if separator and candidate.isdigit() else None
    relative = path if line is not None else finding_location
    return f"{package}{relative}", line
