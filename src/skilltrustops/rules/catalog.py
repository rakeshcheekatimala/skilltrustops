"""Human-readable explanations for stable public rule IDs."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RuleExplanation:
    rule_id: str
    title: str
    why_dangerous: str
    recommended_fix: str
    references: tuple[tuple[str, str], ...]


RULES = {
    "STO-SEC-103": RuleExplanation(
        rule_id="STO-SEC-103",
        title="Unsafe subprocess execution",
        why_dangerous=(
            "A shell parses metacharacters and expansions before the child process "
            "runs. If any part of the command is influenced by untrusted input, an "
            "attacker may execute an unintended command."
        ),
        recommended_fix=(
            "Pass a fixed executable and validated argument array to subprocess.run, "
            "leave shell=False, and apply an allowlist to user-controlled values."
        ),
        references=(
            (
                "Python subprocess security considerations",
                "https://docs.python.org/3/library/subprocess.html#security-considerations",
            ),
            (
                "OWASP Command Injection",
                "https://owasp.org/www-community/attacks/Command_Injection",
            ),
            ("MITRE CWE-78", "https://cwe.mitre.org/data/definitions/78.html"),
        ),
    ),
    "STO-PKG-200": RuleExplanation(
        rule_id="STO-PKG-200",
        title="Prompt-injection or authority override",
        why_dangerous=(
            "Instructions that claim higher authority can redirect an agent away "
            "from its reviewed policy when untrusted content is treated as commands."
        ),
        recommended_fix=(
            "Remove the override instruction or isolate it as labeled test data that "
            "the runtime cannot interpret as trusted instructions."
        ),
        references=(
            (
                "OWASP LLM01 Prompt Injection",
                "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
            ),
            ("MITRE ATLAS AML.T0051", "https://atlas.mitre.org/techniques/AML.T0051"),
        ),
    ),
    "STO-SEC-001": RuleExplanation(
        rule_id="STO-SEC-001",
        title="Secret-like credential detected",
        why_dangerous=(
            "A committed credential can grant unintended access and may remain in "
            "repository history after the visible value is removed."
        ),
        recommended_fix=(
            "Revoke and rotate the credential, remove it from the package and history, "
            "and load future values from an approved secret store."
        ),
        references=(
            (
                "OWASP Secrets Management",
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            ),
        ),
    ),
    "STO-PRIV-001": RuleExplanation(
        rule_id="STO-PRIV-001",
        title="Email address detected",
        why_dangerous=(
            "Personal data embedded in a skill can be copied into logs, prompts, model "
            "provider requests, or published packages."
        ),
        recommended_fix=(
            "Replace real personal data with a synthetic example and define retention "
            "and consent controls for runtime inputs."
        ),
        references=(
            (
                "OWASP Logging guidance",
                "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
            ),
        ),
    ),
}


def explain_rule(rule_id: str) -> RuleExplanation | None:
    """Return the stable explanation for a public rule ID."""
    return RULES.get(rule_id.upper())
