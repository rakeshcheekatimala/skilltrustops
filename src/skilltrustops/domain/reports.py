"""Machine-readable report models."""

from typing import Literal

from pydantic import BaseModel, ConfigDict

from skilltrustops.domain.findings import Finding


class LintReport(BaseModel):
    """Stable result returned by the lint application service."""

    model_config = ConfigDict(frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    tool_version: str
    specification: Literal["https://agentskills.io/specification"] = (
        "https://agentskills.io/specification"
    )
    command: Literal["lint"] = "lint"
    target: str
    passed: bool
    findings: tuple[Finding, ...]
