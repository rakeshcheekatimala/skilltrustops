"""Deterministic engineering-debt reports derived from scan evidence."""

from collections import Counter

from skilltrustops.domain.findings import Finding
from skilltrustops.domain.reports import BatchScanReport


def to_debt_markdown(report: BatchScanReport) -> str:
    """Render prioritized, stable Markdown without inventing a numeric score."""
    findings = sorted(
        (
            (skill.relative_path, finding)
            for skill in report.skills
            for check in skill.checks
            for finding in check.findings
        ),
        key=lambda item: (
            _severity_rank(item[1]),
            item[1].rule_id,
            item[0],
            item[1].location or "",
        ),
    )
    severity_counts = Counter(finding.severity.value for _, finding in findings)
    rule_counts = Counter(finding.rule_id for _, finding in findings)
    lines = [
        "# SkillTrustOps Engineering Debt Report",
        "",
        f"Policy: `{report.policy.profile}` (`{report.policy.sha256}`)",
        f"Ruleset: `{report.ruleset_version}`",
        "",
        "## Outcome",
        "",
        f"- Skills scanned: {report.summary.discovered}",
        f"- Skills requiring work: {report.summary.failed}",
        f"- Scanner errors: {report.summary.errors}",
        f"- Findings: {len(findings)}",
        "",
        "## Findings by severity",
        "",
    ]
    for severity in ("critical", "high", "medium", "low", "error", "warning"):
        lines.append(f"- {severity}: {severity_counts[severity]}")
    lines.extend(["", "## Repeated rules", ""])
    if rule_counts:
        for rule_id, count in sorted(
            rule_counts.items(), key=lambda item: (-item[1], item[0])
        ):
            lines.append(f"- `{rule_id}`: {count}")
    else:
        lines.append("No findings.")
    lines.extend(["", "## Prioritized remediation", ""])
    if not findings:
        lines.append("No remediation is currently required for the recorded scope.")
    for index, (skill_path, finding) in enumerate(findings, 1):
        location = finding.location or skill_path
        lines.extend(
            [
                f"### {index}. {finding.rule_id}: {finding.message}",
                "",
                f"- Severity: `{finding.severity.value}`",
                f"- Skill: `{skill_path}`",
                f"- Location: `{location}`",
                f"- Evidence: {finding.evidence}",
                f"- Recommended fix: {finding.remediation}",
                "",
            ]
        )
    lines.extend(
        [
            "## Scope",
            "",
            "This report is evidence from the recorded policy and ruleset, not a",
            "permanent certification. Rescan after the package or policy changes.",
            "",
        ]
    )
    return "\n".join(lines)


def _severity_rank(finding: Finding) -> int:
    return {
        "critical": 0,
        "high": 1,
        "error": 2,
        "medium": 3,
        "warning": 4,
        "low": 5,
    }[finding.severity.value]
