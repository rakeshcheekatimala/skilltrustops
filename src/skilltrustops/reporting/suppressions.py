"""Auditable, expiring finding suppressions and baselines."""

from __future__ import annotations

import fnmatch
import hashlib
from datetime import date
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from skilltrustops.domain.findings import Finding
from skilltrustops.domain.reports import (
    BatchCheckResult,
    BatchScanReport,
    BatchSkillResult,
    BatchSummary,
)


class Suppression(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(min_length=1)
    path: str = "*"
    justification: str = Field(min_length=12)
    expires: date
    finding_fingerprint: str | None = None


class SuppressionFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = 1
    suppressions: tuple[Suppression, ...]


def load_suppressions(path: Path) -> SuppressionFile:
    """Load a strict YAML suppression file and reject expired entries."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    loaded = SuppressionFile.model_validate(data)
    expired = [item for item in loaded.suppressions if item.expires < date.today()]
    if expired:
        rules = ", ".join(sorted({item.rule_id for item in expired}))
        raise ValueError(f"Expired suppressions must be reviewed: {rules}")
    return loaded


def fingerprint(skill_path: str, finding: Finding) -> str:
    value = "\0".join(
        (skill_path, finding.rule_id, finding.location or "", finding.message)
    )
    return hashlib.sha256(value.encode()).hexdigest()


def apply_suppressions(
    report: BatchScanReport, suppression_file: SuppressionFile
) -> BatchScanReport:
    """Return a report with only explicitly matched findings removed."""
    skills: list[BatchSkillResult] = []
    for skill in report.skills:
        checks: list[BatchCheckResult] = []
        for check in skill.checks:
            kept = tuple(
                finding
                for finding in check.findings
                if not _suppressed(skill.relative_path, finding, suppression_file)
            )
            status = "passed" if check.status == "failed" and not kept else check.status
            checks.append(
                check.model_copy(
                    update={
                        "findings": kept,
                        "finding_count": len(kept),
                        "status": status,
                    }
                )
            )
        skill_status = (
            "error"
            if any(check.status == "error" for check in checks)
            else "failed"
            if any(check.status == "failed" for check in checks)
            else "passed"
        )
        skills.append(
            skill.model_copy(update={"checks": tuple(checks), "status": skill_status})
        )
    return report.model_copy(
        update={
            "skills": tuple(skills),
            "summary": BatchSummary(
                discovered=len(skills),
                passed=sum(skill.status == "passed" for skill in skills),
                failed=sum(skill.status == "failed" for skill in skills),
                errors=sum(skill.status == "error" for skill in skills),
            ),
        }
    )


def baseline_document(report: BatchScanReport, expires: date) -> dict[str, object]:
    """Create a review-required suppression baseline from current findings."""
    return {
        "version": 1,
        "suppressions": [
            {
                "rule_id": finding.rule_id,
                "path": skill.relative_path,
                "finding_fingerprint": fingerprint(skill.relative_path, finding),
                "justification": "REPLACE WITH REVIEWED BUSINESS JUSTIFICATION",
                "expires": expires.isoformat(),
            }
            for skill in report.skills
            for check in skill.checks
            for finding in check.findings
        ],
    }


def _suppressed(skill_path: str, finding: Finding, loaded: SuppressionFile) -> bool:
    digest = fingerprint(skill_path, finding)
    return any(
        item.rule_id == finding.rule_id
        and fnmatch.fnmatch(skill_path, item.path)
        and (item.finding_fingerprint is None or item.finding_fingerprint == digest)
        for item in loaded.suppressions
    )
