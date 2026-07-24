"""Built-in, immutable policy profiles."""

from skilltrustops.policies.models import (
    ChecksPolicy,
    LintCheckPolicy,
    LintRuleset,
    SkillTrustPolicy,
)


def recommended_v1() -> SkillTrustPolicy:
    """Return the secure default profile for the lint-only release."""
    return SkillTrustPolicy(
        version=1,
        profile="recommended-v1",
        checks=ChecksPolicy(
            lint=LintCheckPolicy(
                enabled=True,
                ruleset=LintRuleset.AGENT_SKILLS_SPECIFICATION,
            )
        ),
    )
