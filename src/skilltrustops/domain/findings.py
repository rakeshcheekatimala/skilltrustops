"""Finding models shared by all scanning engines."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Severity levels used by static analysis findings."""

    ERROR = "error"
    WARNING = "warning"


class Finding(BaseModel):
    """An actionable problem found while inspecting an untrusted skill."""

    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(min_length=1)
    severity: Severity
    message: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    remediation: str = Field(min_length=1)
    location: str | None = None
