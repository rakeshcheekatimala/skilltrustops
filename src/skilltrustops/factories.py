"""Composition factories that map policy choices to replaceable engines."""

from pathlib import Path
from typing import assert_never

from skilltrustops.adapters.filesystem import SafeSkillFileLoader
from skilltrustops.adapters.gitleaks import GitleaksSecretDetector
from skilltrustops.detectors.dangerous_code import AstDangerousCodeDetector
from skilltrustops.detectors.package import (
    PackagePrivacyDetector,
    PackageSecurityDetector,
)
from skilltrustops.detectors.pii import BuiltinPiiDetector
from skilltrustops.detectors.secrets import BuiltinSecretDetector
from skilltrustops.engines.base import LintEngine
from skilltrustops.engines.content import ContentDetector, ContentScanEngine
from skilltrustops.engines.errors import ScannerError
from skilltrustops.engines.structure import StructureEngine
from skilltrustops.parsers.front_matter import FrontMatterParser
from skilltrustops.policies.models import (
    DangerousCodeEngine,
    GitleaksSecretScannerPolicy,
    LintCheckPolicy,
    LintRuleset,
    PiiEngine,
    PrivacyCheckPolicy,
    SecurityCheckPolicy,
)
from skilltrustops.policies.paths import (
    TrustedPolicyPathError,
    resolve_trusted_policy_file,
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


def build_security_engine(
    policy: SecurityCheckPolicy,
    policy_root: Path,
) -> LintEngine:
    """Build deterministic security detectors selected by policy."""
    detectors: list[ContentDetector] = []

    if policy.secrets.enabled:
        for scanner in policy.secrets.scanners:
            if not scanner.enabled:
                continue
            if scanner.engine == "builtin":
                detectors.append(BuiltinSecretDetector())
            elif isinstance(scanner, GitleaksSecretScannerPolicy):
                config_path: Path | None = None
                if scanner.config is not None:
                    try:
                        config_path = resolve_trusted_policy_file(
                            policy_root,
                            scanner.config,
                        )
                    except TrustedPolicyPathError as error:
                        raise ScannerError(
                            f"Invalid Gitleaks config: {error}"
                        ) from error
                detectors.append(
                    GitleaksSecretDetector(
                        timeout_seconds=scanner.timeout_seconds,
                        config_path=config_path,
                    )
                )
            else:
                assert_never(scanner)

    if policy.dangerous_code.enabled:
        match policy.dangerous_code.engine:
            case DangerousCodeEngine.AST:
                detectors.append(AstDangerousCodeDetector(policy.dangerous_code))
            case unsupported_code_engine:
                assert_never(unsupported_code_engine)

    detectors.append(PackageSecurityDetector())

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
                detectors.append(PackagePrivacyDetector(policy.pii.entities))
            case unsupported_pii_engine:
                assert_never(unsupported_pii_engine)

    return ContentScanEngine(
        loader=SafeSkillFileLoader(rule_prefix="STO-INPUT"),
        detectors=tuple(detectors),
    )
