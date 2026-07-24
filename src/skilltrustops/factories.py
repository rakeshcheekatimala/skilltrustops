"""Composition factories that map policy choices to replaceable engines."""

from typing import assert_never

from skilltrustops.adapters.filesystem import SafeSkillFileLoader
from skilltrustops.engines.base import LintEngine
from skilltrustops.engines.structure import StructureEngine
from skilltrustops.parsers.front_matter import FrontMatterParser
from skilltrustops.policies.models import LintCheckPolicy, LintRuleset
from skilltrustops.rules.agent_skills import AgentSkillsSpecificationRules


def build_lint_engine(policy: LintCheckPolicy) -> LintEngine:
    """Build the lint engine selected by the effective policy."""
    match policy.ruleset:
        case LintRuleset.AGENT_SKILLS_SPECIFICATION:
            rules = AgentSkillsSpecificationRules()
        case unsupported:
            assert_never(unsupported)

    return StructureEngine(
        loader=SafeSkillFileLoader(),
        parser=FrontMatterParser(),
        rules=rules,
    )
