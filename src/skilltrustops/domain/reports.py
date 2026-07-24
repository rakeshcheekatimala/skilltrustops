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
