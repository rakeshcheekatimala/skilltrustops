"""Evidence coverage matrix derived from deterministic scan results."""

from dataclasses import dataclass
from typing import Literal

from skilltrustops.domain.findings import Finding
from skilltrustops.domain.reports import BatchScanReport

ControlStatus = Literal["passed", "failed", "error", "not_assessed"]


@dataclass(frozen=True, slots=True)
class EvidenceControl:
    name: str
    status: ControlStatus
    evidence: str


def certification_controls(report: BatchScanReport) -> tuple[EvidenceControl, ...]:
    """Report only coverage supported by evidence in the supplied scan."""
    findings = tuple(
        finding
        for skill in report.skills
        for check in skill.checks
        for finding in check.findings
    )
    return (
        _static_control(
            report, findings, "Prompt Injection", "security", {"STO-PKG-200"}
        ),
        _static_control(
            report,
            findings,
            "Secret Leakage",
            "security",
            {
                "STO-SEC-001",
                "STO-SEC-002",
                "STO-SEC-003",
                "STO-SEC-004",
                "STO-SEC-GL-001",
                "RT-006",
            },
        ),
        _unsupported(
            "Unsafe Tool Calls", "Run scan with --redteam and a reviewed manifest."
        ),
        _static_control(
            report,
            findings,
            "Dangerous Shell",
            "security",
            {"STO-SEC-101", "STO-SEC-102", "STO-SEC-103"},
        ),
        _static_control(
            report, findings, "Network Access", "security", {"STO-PKG-203"}
        ),
        _prefix_control(report, findings, "PII Leakage", "privacy", "STO-PRIV-"),
        _unsupported(
            "Hallucination Risk",
            "No deterministic hallucination evaluator is implemented.",
        ),
        _unsupported(
            "Sandbox Escape", "No certifying sandbox assessment is in this scan."
        ),
        _unsupported(
            "MCP Compatibility", "No MCP compatibility contract is implemented."
        ),
        _prefix_control(report, findings, "Skill Metadata", "lint", "STO-LINT-"),
        _unsupported(
            "SPDX License", "License syntax is not yet validated against the SPDX list."
        ),
        _unsupported(
            "OWASP LLM", "Framework mappings require reviewed red-team evidence."
        ),
        _unsupported(
            "MITRE ATLAS", "Framework mappings require reviewed red-team evidence."
        ),
        _unsupported("CIS AI Controls", "No CIS AI control mapping is implemented."),
    )


def _static_control(
    report: BatchScanReport,
    findings: tuple[Finding, ...],
    name: str,
    command: str,
    rule_ids: set[str],
) -> EvidenceControl:
    return _control(
        report,
        name,
        command,
        tuple(finding for finding in findings if finding.rule_id in rule_ids),
    )


def _prefix_control(
    report: BatchScanReport,
    findings: tuple[Finding, ...],
    name: str,
    command: str,
    prefix: str,
) -> EvidenceControl:
    return _control(
        report,
        name,
        command,
        tuple(finding for finding in findings if finding.rule_id.startswith(prefix)),
    )


def _control(
    report: BatchScanReport,
    name: str,
    command: str,
    relevant: tuple[Finding, ...],
) -> EvidenceControl:
    statuses = [
        check.status
        for skill in report.skills
        for check in skill.checks
        if check.command == command
    ]
    if not statuses or all(status == "skipped" for status in statuses):
        return _unsupported(name, f"The {command} check was not run.")
    if any(status == "error" for status in statuses):
        return EvidenceControl(name, "error", f"The {command} check did not complete.")
    if relevant:
        ids = ", ".join(sorted({finding.rule_id for finding in relevant}))
        return EvidenceControl(name, "failed", f"Findings: {ids}")
    return EvidenceControl(
        name, "passed", f"No matching findings under {command} rules."
    )


def _unsupported(name: str, reason: str) -> EvidenceControl:
    return EvidenceControl(name, "not_assessed", reason)
