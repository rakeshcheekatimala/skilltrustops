"""Command-line entry point for SkillTrustOps."""

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console
from rich.table import Table

from skilltrustops.domain.reports import LintReport, StaticScanReport
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
from skilltrustops.services.lint import LintService
from skilltrustops.services.static_scan import StaticScanService

app = typer.Typer(
    name="skilltrustops",
    help="Review AI agent skills locally before they are trusted.",
    no_args_is_help=True,
)
console = Console()
policy_app = typer.Typer(help="Generate and validate repository policies.")
app.add_typer(policy_app, name="policy")


class OutputFormat(StrEnum):
    """Supported lint report renderers."""

    TERMINAL = "terminal"
    JSON = "json"


@app.callback()
def main() -> None:
    """Run local, static trust checks for AI agent skills."""


@app.command()
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


@app.command()
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

    engine = build_security_engine(security_policy)
    report = StaticScanService(engine, "security").run(
        skill_path,
        loaded_policy.reference,
    )
    _output_static_report(report, output_format)


@app.command()
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
    report = StaticScanService(engine, "privacy").run(
        skill_path,
        loaded_policy.reference,
    )
    _output_static_report(report, output_format)


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
    console.print(table)
