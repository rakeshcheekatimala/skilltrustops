"""Strict policy models shared by YAML and JSON configurations."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, StrictBool


class LintRuleset(StrEnum):
    """Lint rulesets available in the current release."""

    AGENT_SKILLS_SPECIFICATION = "agent-skills-specification"


class LintCheckPolicy(BaseModel):
    """Configuration for the Phase 1 lint check."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: StrictBool = True
    ruleset: LintRuleset = LintRuleset.AGENT_SKILLS_SPECIFICATION


class ChecksPolicy(BaseModel):
    """Checks implemented by the current policy schema."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    lint: LintCheckPolicy


class SkillTrustPolicy(BaseModel):
    """Versioned repository policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1]
    profile: Literal["recommended-v1"]
    checks: ChecksPolicy
