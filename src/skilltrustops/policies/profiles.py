"""Built-in, immutable policy profiles."""

from skilltrustops.policies.models import (
    BuiltinSecretScannerPolicy,
    ChecksPolicy,
    DangerousCodeEngine,
    DangerousCodePolicy,
    LintCheckPolicy,
    LintRuleset,
    PiiEngine,
    PiiEntity,
    PiiPolicy,
    PrivacyCheckPolicy,
    ProfileName,
    SecretsPolicy,
    SecurityCheckPolicy,
    SkillTrustPolicy,
)


def recommended_v1() -> SkillTrustPolicy:
    """Return the secure default profile for the lint-only release."""
    return SkillTrustPolicy(
        version=1,
        profile=ProfileName.RECOMMENDED_V1,
        checks=ChecksPolicy(
            lint=LintCheckPolicy(
                enabled=True,
                ruleset=LintRuleset.AGENT_SKILLS_SPECIFICATION,
            )
        ),
    )


def recommended_v2() -> SkillTrustPolicy:
    """Return the deterministic lint, security, and privacy profile."""
    return SkillTrustPolicy(
        version=1,
        profile=ProfileName.RECOMMENDED_V2,
        checks=ChecksPolicy(
            lint=LintCheckPolicy(
                enabled=True,
                ruleset=LintRuleset.AGENT_SKILLS_SPECIFICATION,
            ),
            security=SecurityCheckPolicy(
                enabled=True,
                secrets=SecretsPolicy(
                    enabled=True,
                    scanners=(BuiltinSecretScannerPolicy(enabled=True),),
                ),
                dangerous_code=DangerousCodePolicy(
                    enabled=True,
                    engine=DangerousCodeEngine.AST,
                    block_eval=True,
                    block_destructive_shell=True,
                    block_remote_pipe=True,
                ),
            ),
            privacy=PrivacyCheckPolicy(
                enabled=True,
                pii=PiiPolicy(
                    enabled=True,
                    engine=PiiEngine.BUILTIN,
                    entities=(
                        PiiEntity.EMAIL,
                        PiiEntity.PHONE,
                        PiiEntity.SSN,
                        PiiEntity.CREDIT_CARD,
                    ),
                ),
            ),
        ),
    )
