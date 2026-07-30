"""Plain-English red-team report generation from deterministic evidence."""

from __future__ import annotations

from skilltrustops.redteam.models import (
    AssessmentDecision,
    AttemptOutcome,
    FriendlyIssue,
    FriendlyReport,
    RedTeamReport,
)


def build_friendly_report(report: RedTeamReport) -> FriendlyReport:
    failed = [
        attempt
        for attempt in report.attempts
        if attempt.outcome is AttemptOutcome.ATTACK_SUCCEEDED
    ]
    issues = tuple(_friendly_issue(attempt) for attempt in failed)
    if report.decision is AssessmentDecision.BLOCKED:
        headline = "This skill needs security fixes"
        summary = (
            f"We found {len(issues)} behavior"
            f"{'s' if len(issues) != 1 else ''} that an attacker could trigger. "
            "Do not approve this version until the issues below are fixed."
        )
    elif report.decision is AssessmentDecision.ASSURED:
        headline = "No issue was found in this test scope"
        summary = (
            f"The skill resisted all {report.summary.executed} attacks that were run. "
            "This is a scoped result, not a guarantee against every future attack."
        )
    elif report.sandbox.status == "passed" and not report.sandbox.certifying:
        headline = "The skill passed, but the sandbox is not strong enough"
        summary = (
            f"The skill resisted all {report.summary.executed} attacks. Docker "
            "provided useful development isolation, but this result cannot be "
            "called assured until the same tests pass with gVisor and a "
            "digest-pinned image."
        )
    else:
        headline = "The test could not provide a final answer"
        summary = "Some required evidence is missing or still needs human review."

    sandbox = report.sandbox
    sandbox_summary = {
        "passed": (
            f"The {sandbox.provider} sandbox exited successfully. "
            + (
                "It qualifies as a certifying isolation boundary."
                if sandbox.certifying
                else "It is development isolation and does not qualify for assurance."
            )
        ),
        "failed": "The sandbox exited, but one or more isolation checks failed.",
        "unavailable": sandbox.explanation,
        "not_requested": sandbox.explanation,
    }[sandbox.status]

    next_steps: list[str] = []
    if issues:
        next_steps.append(
            "Fix each behavior listed below, then generate and run tests again."
        )
    if sandbox.status == "unavailable":
        next_steps.append("Start or install the selected sandbox runtime, then rerun.")
    if sandbox.status == "passed" and not sandbox.certifying:
        next_steps.append(
            "Use gVisor with a digest-pinned image for certifying isolation."
        )
    if any("draft" in reason.lower() for reason in report.decision_reasons):
        next_steps.append("Review and approve the generated manifest before assurance.")
    if not next_steps:
        next_steps.append(
            "Keep the evidence bundle and rerun after any skill or policy change."
        )

    return FriendlyReport(
        headline=headline,
        summary=summary,
        sandbox_summary=sandbox_summary,
        issues=issues,
        next_steps=tuple(next_steps),
        scope_note=(
            "This report covers the exact SKILL.md, manifest, model, attack suite, "
            "fake tools, synthetic data, and sandbox configuration recorded in the "
            "evidence. Submitted package code was not executed in Phase 1."
        ),
    )


def _friendly_issue(attempt: object) -> FriendlyIssue:
    from skilltrustops.redteam.models import AttackAttempt

    if not isinstance(attempt, AttackAttempt):
        raise TypeError("Unexpected attack attempt")
    failures = [assertion for assertion in attempt.assertions if not assertion.passed]
    evidence = "; ".join(assertion.evidence for assertion in failures)
    family = attempt.case.family.value.replace("_", " ")
    return FriendlyIssue(
        id=attempt.case.id,
        title=attempt.case.title,
        what_happened=f"The {family} test succeeded. {evidence}",
        why_it_matters=(
            "An untrusted user or document could influence behavior that the skill "
            "was expected to prevent."
        ),
        how_to_fix=(
            "Strengthen the SKILL.md trust boundary for this behavior, keep untrusted "
            "content as data, and rerun the same test."
        ),
        policies=tuple(dict.fromkeys((*attempt.case.owasp, *attempt.case.mitre_atlas))),
    )


def render_friendly_markdown(report: RedTeamReport) -> str:
    friendly = report.friendly_report or build_friendly_report(report)
    lines = [
        f"# {friendly.headline}",
        "",
        friendly.summary,
        "",
        "## Sandbox",
        "",
        friendly.sandbox_summary,
        "",
        "## Issues",
        "",
    ]
    if not friendly.issues:
        lines.append("No confirmed behavioral security issue was recorded.")
    for issue in friendly.issues:
        lines.extend(
            [
                f"### {issue.id}: {issue.title}",
                "",
                f"**What happened:** {issue.what_happened}",
                "",
                f"**Why it matters:** {issue.why_it_matters}",
                "",
                f"**How to fix it:** {issue.how_to_fix}",
                "",
                "**Policies:** " + ", ".join(issue.policies),
                "",
            ]
        )
    lines.extend(["## What to do next", ""])
    lines.extend(f"- {step}" for step in friendly.next_steps)
    lines.extend(["", "## Scope", "", friendly.scope_note, ""])
    return "\n".join(lines)
