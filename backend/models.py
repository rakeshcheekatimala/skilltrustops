"""Stable API contracts for the Studio UI."""

from typing import Literal

from pydantic import BaseModel

from skilltrustops.domain.findings import Finding


class SkillInfo(BaseModel):
    path: str
    name: str
    sha256: str


class EngineInfo(BaseModel):
    version: str


class Decision(BaseModel):
    verdict: Literal["admissible", "needs_remediation", "blocked"]
    blocking_findings: int


class Summary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    error: int = 0
    warning: int = 0
    passed: int = 0


class CheckResult(BaseModel):
    name: Literal["specification", "security", "privacy"]
    passed: bool
    finding_count: int
    duration_ms: float


class TrustDecisionReport(BaseModel):
    schema_version: Literal["1.2"] = "1.2"
    run_id: str
    skill: SkillInfo
    policy: dict[str, str]
    engine: EngineInfo
    decision: Decision
    summary: Summary
    checks: list[CheckResult]
    findings: list[Finding]
    started_at: str
    duration_ms: float
    equivalent_cli: str
    deterministic: Literal[True] = True


class ScanRequest(BaseModel):
    skill_path: str
    policy_path: str | None = None


class ScanContentRequest(BaseModel):
    filename: str = "SKILL.md"
    content: str
    policy_path: str | None = None


class RedTeamRunRequest(BaseModel):
    manifest_path: str = "examples/redteam-support/skilltrust-package.yaml"
    provider: Literal["reference", "openai"] = "reference"
    model: str = "resistant-demo"


class ManifestGenerationRequest(BaseModel):
    skill_path: str
    force: bool = False
    strategy: Literal["openai", "deterministic"] = "openai"
    model: str = "gpt-5.6-terra"


class ModelConfigurationStatus(BaseModel):
    openai_configured: bool
    openai_default_model: str
    reference_models: list[str]
    env_file: str
