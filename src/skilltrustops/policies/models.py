"""Strict policy models shared by YAML and JSON configurations."""

from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, StrictBool, model_validator


class ProfileName(StrEnum):
    """Immutable built-in policy profile names."""

    RECOMMENDED_V1 = "recommended-v1"
    RECOMMENDED_V2 = "recommended-v2"


class LintRuleset(StrEnum):
    """Lint rulesets available in the current release."""

    AGENT_SKILLS_SPECIFICATION = "agent-skills-specification"


class SecretEngine(StrEnum):
    """Secret-scanning engines implemented in this release."""

    BUILTIN = "builtin"


class DangerousCodeEngine(StrEnum):
    """Dangerous-code engines implemented in this release."""

    AST = "ast"


class PiiEngine(StrEnum):
    """PII engines implemented in this release."""

    BUILTIN = "builtin"


class PiiEntity(StrEnum):
    """PII entity types supported by the built-in engine."""

    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"


class LintCheckPolicy(BaseModel):
    """Configuration for the Phase 1 lint check."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: StrictBool = True
    ruleset: LintRuleset = LintRuleset.AGENT_SKILLS_SPECIFICATION


class SecretsPolicy(BaseModel):
    """Secret-scanner configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: StrictBool = True
    engine: SecretEngine = SecretEngine.BUILTIN


class DangerousCodePolicy(BaseModel):
    """Dangerous-code scanner configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: StrictBool = True
    engine: DangerousCodeEngine = DangerousCodeEngine.AST
    block_eval: StrictBool = True
    block_destructive_shell: StrictBool = True
    block_remote_pipe: StrictBool = True


class SecurityCheckPolicy(BaseModel):
    """Deterministic security-check configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: StrictBool = True
    secrets: SecretsPolicy
    dangerous_code: DangerousCodePolicy


class PiiPolicy(BaseModel):
    """PII scanner configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: StrictBool = True
    engine: PiiEngine = PiiEngine.BUILTIN
    entities: tuple[PiiEntity, ...] = (
        PiiEntity.EMAIL,
        PiiEntity.PHONE,
        PiiEntity.SSN,
        PiiEntity.CREDIT_CARD,
    )


class PrivacyCheckPolicy(BaseModel):
    """Deterministic privacy-check configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: StrictBool = True
    pii: PiiPolicy


class ChecksPolicy(BaseModel):
    """Checks implemented by the current policy schema."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    lint: LintCheckPolicy
    security: SecurityCheckPolicy | None = None
    privacy: PrivacyCheckPolicy | None = None


class SkillTrustPolicy(BaseModel):
    """Versioned repository policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1]
    profile: ProfileName
    checks: ChecksPolicy

    @model_validator(mode="after")
    def checks_match_profile(self) -> Self:
        """Prevent profiles from claiming checks they do not define."""
        has_static_checks = (
            self.checks.security is not None and self.checks.privacy is not None
        )
        if self.profile is ProfileName.RECOMMENDED_V1:
            if self.checks.security is not None or self.checks.privacy is not None:
                raise ValueError(
                    "recommended-v1 supports only lint; use recommended-v2 "
                    "for security and privacy"
                )
        elif not has_static_checks:
            raise ValueError(
                "recommended-v2 requires both security and privacy check policies"
            )
        return self
