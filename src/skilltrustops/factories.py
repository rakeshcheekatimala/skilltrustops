"""Composition factories that map policy choices to replaceable engines."""

from typing import assert_never

from skilltrustops.adapters.filesystem import SafeSkillFileLoader
from skilltrustops.detectors.dangerous_code import AstDangerousCodeDetector
from skilltrustops.detectors.pii import BuiltinPiiDetector
from skilltrustops.detectors.secrets import BuiltinSecretDetector
from skilltrustops.engines.base import LintEngine
from skilltrustops.engines.content import ContentDetector, ContentScanEngine
from skilltrustops.engines.structure import StructureEngine
from skilltrustops.parsers.front_matter import FrontMatterParser
from skilltrustops.policies.models import (
    DangerousCodeEngine,
    LintCheckPolicy,
    LintRuleset,
    PiiEngine,
    PrivacyCheckPolicy,
    SecretEngine,
    SecurityCheckPolicy,
)
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


def build_security_engine(policy: SecurityCheckPolicy) -> LintEngine:
    """Build deterministic security detectors selected by policy."""
    detectors: list[ContentDetector] = []

    if policy.secrets.enabled:
        match policy.secrets.engine:
            case SecretEngine.BUILTIN:
                detectors.append(BuiltinSecretDetector())
            case unsupported_secret_engine:
                assert_never(unsupported_secret_engine)

    if policy.dangerous_code.enabled:
        match policy.dangerous_code.engine:
            case DangerousCodeEngine.AST:
                detectors.append(AstDangerousCodeDetector(policy.dangerous_code))
            case unsupported_code_engine:
                assert_never(unsupported_code_engine)

    return ContentScanEngine(
        loader=SafeSkillFileLoader(rule_prefix="STO-INPUT"),
        detectors=tuple(detectors),
    )


def build_privacy_engine(policy: PrivacyCheckPolicy) -> LintEngine:
    """Build deterministic privacy detectors selected by policy."""
    detectors: list[ContentDetector] = []

    if policy.pii.enabled:
        match policy.pii.engine:
            case PiiEngine.BUILTIN:
                detectors.append(BuiltinPiiDetector(policy.pii.entities))
            case unsupported_pii_engine:
                assert_never(unsupported_pii_engine)

    return ContentScanEngine(
        loader=SafeSkillFileLoader(rule_prefix="STO-INPUT"),
        detectors=tuple(detectors),
    )
