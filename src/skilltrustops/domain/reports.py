"""Machine-readable report models."""

from typing import Literal

from pydantic import BaseModel, ConfigDict

from skilltrustops.domain.findings import Finding


class PolicyReference(BaseModel):
    """Reproducible provenance for the effective policy."""

    model_config = ConfigDict(frozen=True)

    profile: str
    source: str
    sha256: str


class LintReport(BaseModel):
    """Stable result returned by the lint application service."""

    model_config = ConfigDict(frozen=True)

    schema_version: Literal["1.1"] = "1.1"
    tool_version: str
    specification: Literal["https://agentskills.io/specification"] = (
        "https://agentskills.io/specification"
    )
    command: Literal["lint"] = "lint"
    target: str
    policy: PolicyReference
    passed: bool
    findings: tuple[Finding, ...]


class StaticScanReport(BaseModel):
    """Machine-readable deterministic security or privacy result."""

    model_config = ConfigDict(frozen=True)

    schema_version: Literal["1.2"] = "1.2"
    tool_version: str
    command: Literal["security", "privacy"]
    target: str
    policy: PolicyReference
    deterministic: Literal[True] = True
    duration_ms: float
    passed: bool
    findings: tuple[Finding, ...]


class BatchCheckResult(BaseModel):
    """One policy-selected check within a batch skill assessment."""

    model_config = ConfigDict(frozen=True)

    command: Literal["lint", "security", "privacy"]
    status: Literal["passed", "failed", "skipped", "error"]
    duration_ms: float
    finding_count: int = 0
    findings: tuple[Finding, ...] = ()
    error: str | None = None


class BatchSkillResult(BaseModel):
    """Aggregate deterministic result and timing for one discovered skill."""

    model_config = ConfigDict(frozen=True)

    skill: str
    relative_path: str
    status: Literal["passed", "failed", "error"]
    duration_ms: float
    checks: tuple[BatchCheckResult, ...]


class BatchSummary(BaseModel):
    """Outcome counts for one batch."""

    model_config = ConfigDict(frozen=True)

    discovered: int
    passed: int
    failed: int
    errors: int


class BatchScanReport(BaseModel):
    """Stable machine-readable report for a file or folder assessment."""

    model_config = ConfigDict(frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    tool_version: str
    ruleset_version: str
    command: Literal["scan"] = "scan"
    target: str
    policy: PolicyReference
    deterministic: Literal[True] = True
    duration_ms: float
    summary: BatchSummary
    skills: tuple[BatchSkillResult, ...]
