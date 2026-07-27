"""Strict contracts for the Phase 1 reference red-team harness."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ToolEffect(StrEnum):
    READ = "read"
    WRITE = "write"
    EXTERNAL_COMMUNICATION = "external_communication"
    DESTRUCTIVE = "destructive"
    FINANCIAL = "financial"


class AttackFamily(StrEnum):
    DIRECT_INJECTION = "direct_injection"
    INDIRECT_DOCUMENT_INJECTION = "indirect_document_injection"
    SENSITIVE_DISCLOSURE = "sensitive_disclosure"
    UNAUTHORIZED_TOOL_CALL = "unauthorized_tool_call"
    CONFIRMATION_BYPASS = "confirmation_bypass"
    MULTI_TURN = "multi_turn"


class AssessmentDecision(StrEnum):
    ASSURED = "assured"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"


class AttemptOutcome(StrEnum):
    RESISTED = "resisted"
    ATTACK_SUCCEEDED = "attack_succeeded"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class ConfirmationPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    required: bool = False


class AuthorizationPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: Literal["any", "current_user"] = "any"
    resource_id_argument: str | None = None

    @model_validator(mode="after")
    def scoped_tools_need_resource_argument(self) -> AuthorizationPolicy:
        if self.scope == "current_user" and not self.resource_id_argument:
            raise ValueError("current_user authorization requires resource_id_argument")
        return self


class ToolSecurity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    effect: ToolEffect
    authorization: AuthorizationPolicy = AuthorizationPolicy()
    confirmation: ConfirmationPolicy = ConfirmationPolicy()
    sensitive_data_allowed: bool = False


class ToolDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=r"^[a-zA-Z][a-zA-Z0-9_-]{1,63}$")
    description: str = Field(min_length=1)
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None = None
    security: ToolSecurity

    @model_validator(mode="after")
    def require_object_input_schema(self) -> ToolDefinition:
        if self.input_schema.get("type") != "object":
            raise ValueError("tool input_schema.type must be 'object'")
        if not isinstance(self.input_schema.get("properties", {}), dict):
            raise ValueError("tool input_schema.properties must be an object")
        return self


class SyntheticRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_type: str
    resource_id: str
    owner_id: str
    fields: dict[str, Any]


class SyntheticFixture(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    current_user_id: str
    records: tuple[SyntheticRecord, ...] = ()
    canaries: dict[str, str] = {}


class ModelChoice(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: Literal["reference", "openai"] = "reference"
    name: str = Field(default="resistant-demo", min_length=1)
    temperature: Literal[0] = 0


class AttackTurn(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    channel: Literal["user", "document"]
    content: str
    trust: Literal["trusted", "untrusted"] = "untrusted"


class AttackCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    title: str
    family: AttackFamily
    severity: Literal["critical", "high", "medium"]
    objective: str
    turns: tuple[AttackTurn, ...]
    owasp: tuple[str, ...]
    mitre_atlas: tuple[str, ...]
    expected_forbidden_tools: tuple[str, ...] = ()
    forbidden_output_markers: tuple[str, ...] = ()


class ManifestGeneration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["draft", "approved"]
    method: Literal["deterministic", "openai"]
    generator_version: str
    source_skill_sha256: str
    requires_review: bool
    model: str | None = None


class PackageManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,63}$")
    version: str = Field(min_length=1)
    skill: str = "SKILL.md"
    description: str = Field(min_length=1)
    capabilities: tuple[
        Literal[
            "documents",
            "sensitive_data",
            "tools",
            "confirmations",
            "multi_turn",
        ],
        ...,
    ]
    tools: tuple[ToolDefinition, ...] = ()
    synthetic_fixture: SyntheticFixture
    attacks: tuple[AttackCase, ...] = ()
    generation: ManifestGeneration | None = None

    @model_validator(mode="after")
    def manifest_is_coherent(self) -> PackageManifest:
        if self.skill != "SKILL.md":
            raise ValueError("Phase 1 accepts exactly one file named SKILL.md")
        if self.tools and "tools" not in self.capabilities:
            raise ValueError("manifests with tools must declare the tools capability")
        names = [tool.name for tool in self.tools]
        if len(names) != len(set(names)):
            raise ValueError("tool names must be unique")
        attack_ids = [attack.id for attack in self.attacks]
        if len(attack_ids) != len(set(attack_ids)):
            raise ValueError("attack IDs must be unique")
        return self


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    arguments: dict[str, Any]


class ModelResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    content: str
    tool_calls: tuple[ToolCall, ...] = ()


class TraceEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sequence: int
    type: Literal[
        "message",
        "document",
        "model_output",
        "tool_call_attempted",
        "tool_call_blocked",
        "tool_call_simulated",
        "assertion",
    ]
    detail: dict[str, Any]


class AssertionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    passed: bool
    severity: Literal["critical", "high", "medium"]
    message: str
    evidence: str


class AttackAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case: AttackCase
    outcome: AttemptOutcome
    assertions: tuple[AssertionResult, ...]
    trace: tuple[TraceEvent, ...]
    output: str


class RedTeamSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    planned: int
    executed: int
    resisted: int
    attack_succeeded: int
    inconclusive: int


class EvidenceReference(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    directory: str
    manifest: str
    report: str
    inspect_log: str


class RedTeamReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    run_id: str
    started_at: str
    package_name: str
    package_version: str
    package_sha256: str
    skill_sha256: str
    manifest_sha256: str
    model: ModelChoice
    harness: Literal["skilltrust-reference-harness"] = "skilltrust-reference-harness"
    harness_version: str
    decision: AssessmentDecision
    decision_reasons: tuple[str, ...]
    summary: RedTeamSummary
    attempts: tuple[AttackAttempt, ...]
    evidence: EvidenceReference | None = None
    deterministic_assertions: Literal[True] = True
    model_execution_deterministic: bool
