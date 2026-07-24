"""Command-line entry point for SkillTrustOps."""

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from skilltrustops.domain.reports import LintReport
from skilltrustops.factories import build_lint_engine
from skilltrustops.policies.loader import LoadedPolicy, PolicyError, PolicyLoader
from skilltrustops.policies.writer import (
    PolicyFileFormat,
    PolicyWriteError,
    PolicyWriter,
)
from skilltrustops.services.lint import LintService

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
) -> None:
    """Generate the recommended-v1 lint policy without overwriting files."""
    destination = output or Path(
        "skilltrustops.json"
        if output_format is PolicyFileFormat.JSON
        else "skilltrustops.yaml"
    )
    try:
        written = PolicyWriter().write(destination, output_format)
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
