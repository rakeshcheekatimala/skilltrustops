"""Command-line entry point for SkillTrustOps."""

import json
import os
import shutil
import sys
from dataclasses import asdict
from datetime import date, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn, TypedDict

import typer
import yaml
from rich.console import Console
from rich.table import Table

from skilltrustops.api import scan as scan_target
from skilltrustops.domain.reports import BatchScanReport, LintReport, StaticScanReport
from skilltrustops.engines.errors import ScannerError
from skilltrustops.factories import (
    build_lint_engine,
    build_privacy_engine,
    build_security_engine,
)
from skilltrustops.policies.loader import LoadedPolicy, PolicyError, PolicyLoader
from skilltrustops.policies.models import ProfileName
from skilltrustops.policies.writer import (
    PolicyFileFormat,
    PolicyWriteError,
    PolicyWriter,
)
from skilltrustops.redteam.generator import RedTeamManifestGenerator
from skilltrustops.redteam.loader import RedTeamPackageError
from skilltrustops.redteam.service import RedTeamService
from skilltrustops.redteam.targets import (
    GenericHTTPModelTarget,
    ModelTarget,
    OpenAIModelTarget,
    ReferenceModelTarget,
)
from skilltrustops.reporting.certification import certification_controls
from skilltrustops.reporting.debt import to_debt_markdown
from skilltrustops.reporting.sarif import to_sarif
from skilltrustops.reporting.suppressions import (
    apply_suppressions,
    baseline_document,
    load_suppressions,
)
from skilltrustops.rules.catalog import explain_rule
from skilltrustops.sandbox.providers import provider_from_policy
from skilltrustops.services.batch import BatchScanError, BatchScanService
from skilltrustops.services.lint import LintService
from skilltrustops.services.local_env import load_discovered_env
from skilltrustops.services.static_scan import StaticScanService

app = typer.Typer(
    name="skilltrustops",
    help="Review AI agent skills locally before they are trusted.",
    no_args_is_help=True,
)
console = Console()
policy_app = typer.Typer(help="Generate and validate repository policies.")
app.add_typer(policy_app, name="policy")
redteam_app = typer.Typer(
    help="Run behavioral attacks in the Phase 1 reference harness."
)
app.add_typer(redteam_app, name="redteam", hidden=True)


class OutputFormat(StrEnum):
    """Supported lint report renderers."""

    TERMINAL = "terminal"
    JSON = "json"


class BatchOutputFormat(StrEnum):
    TERMINAL = "terminal"
    JSON = "json"
    SARIF = "sarif"


class ModelProvider(StrEnum):
    REFERENCE = "reference"
    OPENAI = "openai"
    GENERIC_HTTP = "generic-http"


class SandboxProviderName(StrEnum):
    NONE = "none"
    DOCKER = "docker"
    GVISOR = "gvisor"


class ManifestGenerationProvider(StrEnum):
    DETERMINISTIC = "deterministic"
    OPENAI = "openai"


class DiagnosticCheck(TypedDict):
    ok: bool
    detail: str
    required: bool


@redteam_app.command("init")
def redteam_init(
    skill_path: Annotated[
        Path,
        typer.Argument(help="Path to one SKILL.md file."),
    ],
    force: Annotated[
        bool,
        typer.Option("--force", help="Replace an existing generated manifest."),
    ] = False,
    provider: Annotated[
        ManifestGenerationProvider,
        typer.Option("--provider", help="Behavioral test generation strategy."),
    ] = ManifestGenerationProvider.DETERMINISTIC,
    model: Annotated[
        str,
        typer.Option("--model", help="OpenAI model used to propose attack cases."),
    ] = "gpt-5.6-terra",
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Report output format."),
    ] = OutputFormat.TERMINAL,
) -> None:
    """Generate a deterministic, review-required red-team manifest draft."""
    load_discovered_env(Path.cwd())
    try:
        result = RedTeamManifestGenerator().write(
            skill_path,
            force=force,
            strategy=provider.value,
            model=model,
        )
    except RedTeamPackageError as error:
        console.print(f"[bold red]REDTEAM ERROR[/bold red] {error}")
        raise typer.Exit(code=2) from error
    if output_format is OutputFormat.JSON:
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))
    else:
        console.print(
            f"[bold green]GENERATED DRAFT[/bold green] {result.manifest_path}"
        )
        console.print(
            "Capabilities: " + ", ".join(result.inferred_capabilities) + "\n"
            "Review the manifest and set generation.status to approved with "
            "requires_review: false before assurance."
        )


@app.callback()
def main() -> None:
    """Run local, static trust checks for AI agent skills."""


@app.command("doctor", hidden=True)
def doctor(
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Diagnostic output format."),
    ] = OutputFormat.TERMINAL,
) -> None:
    """Check the local installation without reading or printing secret values."""
    policy_path = next(
        (
            candidate
            for candidate in (
                Path.cwd() / "skilltrustops.yaml",
                Path.cwd() / "skilltrustops.yml",
                Path.cwd() / "skilltrustops.json",
            )
            if candidate.is_file() and not candidate.is_symlink()
        ),
        None,
    )
    python_version = (
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )
    checks: dict[str, DiagnosticCheck] = {
        "python": {
            "ok": sys.version_info >= (3, 11),
            "detail": python_version,
            "required": True,
        },
        "policy": {
            "ok": policy_path is not None,
            "detail": str(policy_path) if policy_path else "not found; run policy init",
            "required": False,
        },
        "gitleaks": {
            "ok": shutil.which("gitleaks") is not None,
            "detail": "available" if shutil.which("gitleaks") else "not installed",
            "required": False,
        },
        "docker": {
            "ok": shutil.which("docker") is not None,
            "detail": "available" if shutil.which("docker") else "not installed",
            "required": False,
        },
        "openai_credentials": {
            "ok": bool(os.getenv("OPENAI_API_KEY")),
            "detail": "configured" if os.getenv("OPENAI_API_KEY") else "not configured",
            "required": False,
        },
    }
    ready = all(check["ok"] for check in checks.values() if check["required"])
    report = {"ready": ready, "checks": checks}
    if output_format is OutputFormat.JSON:
        typer.echo(json.dumps(report, indent=2))
    else:
        table = Table(title="SkillTrustOps diagnostics")
        table.add_column("Check")
        table.add_column("Status")
        table.add_column("Detail")
        for name, check in checks.items():
            status = (
                "PASS" if check["ok"] else ("FAIL" if check["required"] else "OPTIONAL")
            )
            table.add_row(name, status, str(check["detail"]))
        console.print(table)
        message = "Core scanning is ready." if ready else "Core scanning is not ready."
        console.print(message)
    if not ready:
        raise typer.Exit(code=2)


@app.command("scan")
def scan_command(
    target: Annotated[
        Path,
        typer.Argument(help="One SKILL.md or a folder containing multiple skills."),
    ],
    policy_path: Annotated[
        Path | None,
        typer.Option("--policy", help="One YAML or JSON policy for the batch."),
    ] = None,
    output_format: Annotated[
        BatchOutputFormat,
        typer.Option("--format", help="Report output format."),
    ] = BatchOutputFormat.TERMINAL,
    suppressions_path: Annotated[
        Path | None,
        typer.Option(
            "--suppressions",
            help="Reviewed YAML suppressions with justification and expiry.",
        ),
    ] = None,
    write_baseline: Annotated[
        Path | None,
        typer.Option(
            "--write-baseline",
            help="Write current findings as a review-required suppression draft.",
        ),
    ] = None,
    security_enabled: Annotated[
        bool,
        typer.Option("--security/--no-security", help="Enable security checks."),
    ] = True,
    privacy_enabled: Annotated[
        bool,
        typer.Option("--privacy/--no-privacy", help="Enable privacy checks."),
    ] = True,
    redteam_enabled: Annotated[
        bool,
        typer.Option(
            "--redteam",
            help="Run reviewed adjacent manifests with the offline reference model.",
        ),
    ] = False,
    benchmark: Annotated[
        bool,
        typer.Option(
            "--benchmark",
            help="Replay the deterministic scan and verify identical evidence.",
        ),
    ] = False,
    metrics: Annotated[
        bool,
        typer.Option(
            "--metrics",
            help="Include nondeterministic wall-clock timing in the report.",
        ),
    ] = False,
    debt_report: Annotated[
        Path | None,
        typer.Option(
            "--debt-report",
            help="Write a deterministic Markdown engineering-debt report.",
        ),
    ] = None,
) -> None:
    """Run the opinionated deterministic quality gate for one or more skills."""
    try:
        if benchmark and metrics:
            raise ValueError("--benchmark and --metrics cannot be combined")
        if redteam_enabled and output_format is not BatchOutputFormat.TERMINAL:
            raise ValueError("--redteam currently requires terminal output")
        report = scan_target(
            target,
            policy_path=policy_path,
            include_timing=metrics,
            security=security_enabled,
            privacy=privacy_enabled,
        )
        if write_baseline is not None:
            document = baseline_document(report, date.today() + timedelta(days=30))
            write_baseline.write_text(
                yaml.safe_dump(document, sort_keys=False), encoding="utf-8"
            )
        if suppressions_path is not None:
            report = apply_suppressions(report, load_suppressions(suppressions_path))
        if debt_report is not None:
            debt_report.write_text(to_debt_markdown(report), encoding="utf-8")
        if benchmark:
            replay = scan_target(
                target,
                policy_path=policy_path,
                include_timing=False,
                security=security_enabled,
                privacy=privacy_enabled,
            )
            if suppressions_path is not None:
                replay = apply_suppressions(
                    replay, load_suppressions(suppressions_path)
                )
            canonical = report.model_copy(
                update={"duration_ms": 0.0}, deep=True
            ).model_dump_json()
            replay_canonical = replay.model_dump_json()
            if canonical != replay_canonical:
                raise ValueError("Deterministic replay produced different evidence")
    except (BatchScanError, OSError, PolicyError, ValueError) as error:
        console.print(f"[bold red]SCAN ERROR[/bold red] {error}")
        raise typer.Exit(code=2) from error
    if output_format is BatchOutputFormat.JSON:
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2))
    elif output_format is BatchOutputFormat.SARIF:
        typer.echo(json.dumps(to_sarif(report), indent=2))
    else:
        _render_batch_report(report, show_metrics=metrics)
        if benchmark:
            console.print("[bold green]PASS[/bold green] Deterministic replay")
        if debt_report is not None:
            console.print(f"[dim]Engineering debt report: {debt_report}[/dim]")
    redteam_exit = _run_scan_redteam(target) if redteam_enabled else 0
    if report.summary.errors:
        raise typer.Exit(code=2)
    if report.summary.failed:
        raise typer.Exit(code=1)
    if redteam_exit:
        raise typer.Exit(code=redteam_exit)


@app.command("certify")
def certify(
    target: Annotated[
        Path,
        typer.Argument(help="One SKILL.md or a folder containing multiple skills."),
    ] = Path("."),
    policy_path: Annotated[
        Path | None,
        typer.Option("--policy", help="Repository policy for the evidence scan."),
    ] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Evidence matrix output format."),
    ] = OutputFormat.TERMINAL,
) -> None:
    """Show an evidence matrix without claiming unassessed controls passed."""
    try:
        report = scan_target(target, policy_path=policy_path)
    except (BatchScanError, OSError, PolicyError, ValueError) as error:
        console.print(f"[bold red]CERTIFY ERROR[/bold red] {error}")
        raise typer.Exit(code=2) from error
    controls = certification_controls(report)
    if output_format is OutputFormat.JSON:
        typer.echo(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "scope": {
                        "target": report.target,
                        "policy_sha256": report.policy.sha256,
                        "ruleset_version": report.ruleset_version,
                    },
                    "controls": [asdict(control) for control in controls],
                    "certificate_issued": False,
                },
                indent=2,
            )
        )
    else:
        table = Table(title="SkillTrustOps evidence matrix")
        table.add_column("Status")
        table.add_column("Control")
        table.add_column("Evidence")
        symbols = {
            "passed": "[green]✓ PASSED[/green]",
            "failed": "[red]✗ FAILED[/red]",
            "error": "[red]! ERROR[/red]",
            "not_assessed": "[yellow]— NOT ASSESSED[/yellow]",
        }
        for control in controls:
            table.add_row(symbols[control.status], control.name, control.evidence)
        console.print(table)
        console.print(
            "[bold]No blanket certificate was issued.[/bold] "
            "Only recorded controls are marked passed."
        )
    if any(control.status == "error" for control in controls):
        raise typer.Exit(code=2)
    if any(control.status == "failed" for control in controls):
        raise typer.Exit(code=1)


@app.command("explain")
def explain(
    rule_id: Annotated[
        str,
        typer.Argument(help="Stable finding ID, for example STO-SEC-103."),
    ],
    report_path: Annotated[
        Path | None,
        typer.Option(
            "--report",
            help="Optional scan JSON used to include observed evidence and locations.",
        ),
    ] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Explanation output format."),
    ] = OutputFormat.TERMINAL,
) -> None:
    """Explain why a finding matters and how to fix it."""
    rule = explain_rule(rule_id)
    if rule is None:
        console.print(f"[bold red]UNKNOWN RULE[/bold red] {rule_id.upper()}")
        raise typer.Exit(code=2)
    observed: list[dict[str, str | None]] = []
    if report_path is not None:
        try:
            report = BatchScanReport.model_validate_json(
                report_path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as error:
            console.print(f"[bold red]REPORT ERROR[/bold red] {error}")
            raise typer.Exit(code=2) from error
        observed = [
            {
                "skill": skill.relative_path,
                "location": finding.location,
                "evidence": finding.evidence,
            }
            for skill in report.skills
            for check in skill.checks
            for finding in check.findings
            if finding.rule_id == rule.rule_id
        ]
    payload = {
        "rule_id": rule.rule_id,
        "title": rule.title,
        "observed": observed,
        "why_dangerous": rule.why_dangerous,
        "recommended_fix": rule.recommended_fix,
        "references": [{"title": title, "url": url} for title, url in rule.references],
    }
    if output_format is OutputFormat.JSON:
        typer.echo(json.dumps(payload, indent=2))
        return
    console.print(f"[bold]{rule.rule_id}: {rule.title}[/bold]")
    if observed:
        console.print("\n[bold]Observed evidence[/bold]")
        for item in observed:
            console.print(
                f"- {item['skill']}:{item['location'] or 'unknown'} — "
                f"{item['evidence']}"
            )
    console.print(f"\n[bold]Why dangerous[/bold]\n{rule.why_dangerous}")
    console.print(f"\n[bold]Recommended fix[/bold]\n{rule.recommended_fix}")
    console.print("\n[bold]References[/bold]")
    for title, url in rule.references:
        console.print(f"- {title}: {url}")


def _run_scan_redteam(target: Path) -> int:
    """Run adjacent reviewed manifests with the deterministic reference target."""
    try:
        _, skill_paths = BatchScanService.discover(target)
        reports = [
            RedTeamService(Path(".skilltrustops/redteam-runs")).run(
                skill_path,
                ReferenceModelTarget("resistant-demo"),
            )
            for skill_path in skill_paths
        ]
    except (BatchScanError, RedTeamPackageError, OSError, ValueError) as error:
        console.print(f"[bold red]REDTEAM ERROR[/bold red] {error}")
        return 2
    exit_code = 0
    for report in reports:
        color = {
            "passed_scope": "green",
            "blocked": "red",
            "inconclusive": "yellow",
        }[report.decision.value]
        console.print(
            f"[bold {color}]{report.decision.value.upper()}[/bold {color}] "
            f"red-team {report.package_name}@{report.package_version}"
        )
        if report.decision.value == "blocked":
            exit_code = max(exit_code, 1)
        elif report.decision.value == "inconclusive":
            exit_code = max(exit_code, 3)
    return exit_code


@app.command("hook", hidden=True)
def hook_command(
    target: Annotated[
        Path,
        typer.Argument(help="Skill file or directory checked by a Git hook."),
    ] = Path("."),
    policy_path: Annotated[
        Path | None,
        typer.Option("--policy", help="Repository policy used by the hook."),
    ] = None,
) -> None:
    """Fail a pre-commit or pre-push hook when a skill needs review."""
    try:
        report = scan_target(target, policy_path=policy_path, include_timing=True)
    except (BatchScanError, OSError, PolicyError, ValueError) as error:
        console.print(f"[bold red]HOOK ERROR[/bold red] {error}")
        raise typer.Exit(code=2) from error
    console.print(
        f"SkillTrustOps: {report.summary.discovered} scanned, "
        f"{report.summary.passed} passed, {report.summary.failed} need review, "
        f"{report.summary.errors} errors ({report.duration_ms:.1f} ms)"
    )
    if report.summary.errors:
        raise typer.Exit(code=2)
    if report.summary.failed:
        console.print(
            "[bold red]Git operation stopped.[/bold red] Run "
            f"'skilltrustops scan {target}' for findings."
        )
        raise typer.Exit(code=1)


@app.command(hidden=True)
def lint(
    skill_path: Annotated[
        Path,
        typer.Argument(help="Path to one untrusted SKILL.md file."),
    ],
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Report output format."),
    ] = OutputFormat.TERMINAL,
    policy_path: Annotated[
        Path | None,
        typer.Option("--policy", help="Explicit YAML or JSON policy path."),
    ] = None,
) -> None:
    """Validate a skill's required files and metadata without executing it."""
    loaded_policy = _load_policy(policy_path)
    if not loaded_policy.policy.checks.lint.enabled:
        console.print(
            "[bold red]POLICY ERROR[/bold red] The lint check is disabled. "
            "Enable checks.lint.enabled before running lint."
        )
        raise typer.Exit(code=2)

    engine = build_lint_engine(loaded_policy.policy.checks.lint)
    report = LintService(engine).run(skill_path, loaded_policy.reference)

    if output_format is OutputFormat.JSON:
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2))
    else:
        _render_terminal(report)

    if not report.passed:
        raise typer.Exit(code=1)


@app.command(hidden=True)
def security(
    skill_path: Annotated[
        Path,
        typer.Argument(help="Path to one untrusted SKILL.md file."),
    ],
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Report output format."),
    ] = OutputFormat.TERMINAL,
    policy_path: Annotated[
        Path | None,
        typer.Option("--policy", help="Explicit YAML or JSON policy path."),
    ] = None,
) -> None:
    """Scan for secrets and dangerous code without executing the skill."""
    loaded_policy = _load_policy(policy_path)
    security_policy = loaded_policy.policy.checks.security
    if security_policy is None:
        _policy_command_error("security", loaded_policy)
    if not security_policy.enabled:
        _disabled_check_error("security")

    try:
        engine = build_security_engine(
            security_policy,
            loaded_policy.base_dir,
        )
        report = StaticScanService(engine, "security").run(
            skill_path,
            loaded_policy.reference,
        )
    except ScannerError as error:
        _scanner_error(error)
    _output_static_report(report, output_format)


@app.command(hidden=True)
def privacy(
    skill_path: Annotated[
        Path,
        typer.Argument(help="Path to one untrusted SKILL.md file."),
    ],
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Report output format."),
    ] = OutputFormat.TERMINAL,
    policy_path: Annotated[
        Path | None,
        typer.Option("--policy", help="Explicit YAML or JSON policy path."),
    ] = None,
) -> None:
    """Scan for configured PII entities without uploading skill content."""
    loaded_policy = _load_policy(policy_path)
    privacy_policy = loaded_policy.policy.checks.privacy
    if privacy_policy is None:
        _policy_command_error("privacy", loaded_policy)
    if not privacy_policy.enabled:
        _disabled_check_error("privacy")

    engine = build_privacy_engine(privacy_policy)
    try:
        report = StaticScanService(engine, "privacy").run(
            skill_path,
            loaded_policy.reference,
        )
    except ScannerError as error:
        _scanner_error(error)
    _output_static_report(report, output_format)


@redteam_app.command("run")
def redteam_run(
    manifest_path: Annotated[
        Path,
        typer.Argument(help="Path to one declarative skilltrust-package manifest."),
    ],
    provider: Annotated[
        ModelProvider,
        typer.Option("--provider", help="Model provider used by the harness."),
    ] = ModelProvider.REFERENCE,
    model: Annotated[
        str,
        typer.Option(
            "--model",
            help="Reference profile or OpenAI model ID.",
        ),
    ] = "resistant-demo",
    endpoint: Annotated[
        str | None,
        typer.Option(
            "--endpoint", help="HTTPS endpoint for the generic-http provider."
        ),
    ] = None,
    # The default below is an environment-variable name, not a credential value.
    token_env: Annotated[
        str,
        typer.Option(
            "--token-env", help="Environment variable containing a provider token."
        ),
    ] = "SKILLTRUSTOPS_PROVIDER_TOKEN",  # nosec B107
    sandbox: Annotated[
        SandboxProviderName | None,
        typer.Option("--sandbox", help="Override configured isolation provider."),
    ] = None,
    sandbox_image: Annotated[
        str | None,
        typer.Option("--sandbox-image", help="Override configured probe image."),
    ] = None,
    policy_path: Annotated[
        Path | None,
        typer.Option("--policy", help="Repository configuration and policy."),
    ] = None,
    evidence_dir: Annotated[
        Path,
        typer.Option("--evidence-dir", help="Directory for immutable run evidence."),
    ] = Path(".skilltrustops/redteam-runs"),
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Report output format."),
    ] = OutputFormat.TERMINAL,
) -> None:
    """Test one SKILL.md with generated tools and synthetic records."""
    load_discovered_env(Path.cwd())
    loaded_policy = _load_policy(policy_path)
    try:
        target: ModelTarget
        if provider is ModelProvider.OPENAI:
            target = OpenAIModelTarget(model)
        elif provider is ModelProvider.GENERIC_HTTP:
            if endpoint is None:
                raise ValueError("--endpoint is required for generic-http")
            target = GenericHTTPModelTarget(model, endpoint, token_env=token_env)
        else:
            target = ReferenceModelTarget(model)
        sandbox_provider = provider_from_policy(
            loaded_policy.policy.redteam.sandbox,
            provider_override=sandbox.value if sandbox is not None else None,
            image_override=sandbox_image,
        )
        report = RedTeamService(evidence_dir).run(
            manifest_path, target, sandbox_provider
        )
    except (RedTeamPackageError, ValueError) as error:
        console.print(f"[bold red]REDTEAM ERROR[/bold red] {error}")
        raise typer.Exit(code=2) from error
    if output_format is OutputFormat.JSON:
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2))
    else:
        color = {
            "passed_scope": "green",
            "blocked": "red",
            "inconclusive": "yellow",
        }[report.decision.value]
        console.print(
            f"[bold {color}]{report.decision.value.upper()}[/bold {color}] "
            f"{report.package_name}@{report.package_version}"
        )
        console.print(
            f"Model: {report.model.provider}/{report.model.name}; "
            f"resisted {report.summary.resisted}/{report.summary.executed}"
        )
        if report.evidence:
            console.print(f"[dim]Evidence: {report.evidence.directory}[/dim]")
            console.print(
                f"[dim]Friendly report: {report.evidence.friendly_report}[/dim]"
            )
        console.print(
            f"Sandbox: {report.sandbox.provider}/{report.sandbox.runtime} "
            f"({report.sandbox.status})"
        )
        failures = [
            attempt
            for attempt in report.attempts
            if attempt.outcome.value == "attack_succeeded"
        ]
        if failures:
            table = Table(show_header=True, header_style="bold")
            table.add_column("Case")
            table.add_column("Family")
            table.add_column("Failure")
            for attempt in failures:
                failed = next(
                    assertion.message
                    for assertion in attempt.assertions
                    if not assertion.passed
                )
                table.add_row(attempt.case.id, attempt.case.family.value, failed)
            console.print(table)
    if report.decision.value != "passed_scope":
        raise typer.Exit(code=1 if report.decision.value == "blocked" else 3)


@policy_app.command("init")
def policy_init(
    output_format: Annotated[
        PolicyFileFormat,
        typer.Option("--format", help="Policy file format."),
    ] = PolicyFileFormat.YAML,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Destination policy path."),
    ] = None,
    profile: Annotated[
        ProfileName,
        typer.Option("--profile", help="Built-in policy profile."),
    ] = ProfileName.RECOMMENDED_V2,
) -> None:
    """Generate a built-in policy profile without overwriting files."""
    destination = output or Path(
        "skilltrustops.json"
        if output_format is PolicyFileFormat.JSON
        else "skilltrustops.yaml"
    )
    try:
        written = PolicyWriter().write(destination, output_format, profile)
    except PolicyWriteError as error:
        console.print(f"[bold red]POLICY ERROR[/bold red] {error}")
        raise typer.Exit(code=2) from error
    console.print(f"[bold green]CREATED[/bold green] {written.absolute()}")


@policy_app.command("validate")
def policy_validate(
    policy_path: Annotated[
        Path | None,
        typer.Option("--policy", help="Explicit YAML or JSON policy path."),
    ] = None,
) -> None:
    """Validate an explicit or discovered policy."""
    loaded = _load_policy(policy_path)
    console.print(
        f"[bold green]VALID[/bold green] {loaded.reference.source}\n"
        f"Profile: {loaded.reference.profile}\n"
        f"SHA-256: {loaded.reference.sha256}"
    )


def _load_policy(policy_path: Path | None) -> LoadedPolicy:
    try:
        return PolicyLoader().load(policy_path, Path.cwd())
    except PolicyError as error:
        console.print(f"[bold red]POLICY ERROR[/bold red] {error}")
        raise typer.Exit(code=2) from error


def _policy_command_error(command: str, loaded_policy: LoadedPolicy) -> NoReturn:
    console.print(
        f"[bold red]POLICY ERROR[/bold red] The {command} check is not configured "
        f"by profile {loaded_policy.policy.profile.value!r}."
    )
    raise typer.Exit(code=2)


def _disabled_check_error(command: str) -> NoReturn:
    console.print(
        f"[bold red]POLICY ERROR[/bold red] The {command} check is disabled. "
        f"Enable checks.{command}.enabled before running {command}."
    )
    raise typer.Exit(code=2)


def _scanner_error(error: ScannerError) -> NoReturn:
    console.print(f"[bold red]SCANNER ERROR[/bold red] {error}")
    raise typer.Exit(code=2) from error


def _output_static_report(
    report: StaticScanReport,
    output_format: OutputFormat,
) -> None:
    if output_format is OutputFormat.JSON:
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2))
    else:
        _render_static_report(report)
    if not report.passed:
        raise typer.Exit(code=1)


def _render_terminal(report: LintReport) -> None:
    if report.passed:
        console.print(f"[bold green]PASS[/bold green] {report.target}")
        console.print(
            f"[dim]Policy: {report.policy.profile} ({report.policy.source})[/dim]"
        )
        return

    console.print(f"[bold red]FAIL[/bold red] {report.target}")
    console.print(
        f"[dim]Policy: {report.policy.profile} ({report.policy.source})[/dim]"
    )
    table = Table(show_header=True, header_style="bold")
    table.add_column("Rule")
    table.add_column("Finding")
    table.add_column("Evidence")
    table.add_column("Remediation")
    for finding in report.findings:
        table.add_row(
            finding.rule_id,
            finding.message,
            finding.evidence,
            finding.remediation,
        )
    console.print(table)


def _render_static_report(report: StaticScanReport) -> None:
    status = (
        "[bold green]PASS[/bold green]"
        if report.passed
        else "[bold red]FAIL[/bold red]"
    )
    console.print(f"{status} {report.command} {report.target}")
    console.print(
        f"[dim]Policy: {report.policy.profile} ({report.policy.source}); "
        f"{report.duration_ms:.3f} ms[/dim]"
    )
    if report.passed:
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Rule")
    table.add_column("Severity")
    table.add_column("Finding")
    table.add_column("Evidence")
    table.add_column("Remediation")
    for finding in report.findings:
        table.add_row(
            finding.rule_id,
            finding.severity.value,
            finding.message,
            finding.evidence,
            finding.remediation,
        )


def _render_batch_report(
    report: BatchScanReport, *, show_metrics: bool = False
) -> None:
    table = Table(show_header=True, header_style="bold")
    table.add_column("Skill")
    table.add_column("Path")
    table.add_column("Status")
    table.add_column("Findings", justify="right")
    if show_metrics:
        table.add_column("Time (ms)", justify="right")
    for skill in report.skills:
        findings = sum(check.finding_count for check in skill.checks)
        row = [
            skill.skill,
            skill.relative_path,
            skill.status.upper(),
            str(findings),
        ]
        if show_metrics:
            row.append(f"{skill.duration_ms:.3f}")
        table.add_row(*row)
    console.print(table)
    console.print(
        f"Scanned {report.summary.discovered} skill(s): "
        f"{report.summary.passed} passed, {report.summary.failed} failed, "
        f"{report.summary.errors} errors"
        + (f" in {report.duration_ms:.3f} ms" if show_metrics else "")
    )
    console.print(
        f"[dim]Policy: {report.policy.profile} ({report.policy.source}); "
        f"SHA-256: {report.policy.sha256}[/dim]"
    )
    console.print(table)
