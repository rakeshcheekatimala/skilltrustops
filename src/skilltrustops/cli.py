"""Command-line entry point for SkillTrustOps."""

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from skilltrustops.adapters.filesystem import SafeSkillFileLoader
from skilltrustops.domain.reports import LintReport
from skilltrustops.engines.structure import StructureEngine
from skilltrustops.parsers.front_matter import FrontMatterParser
from skilltrustops.rules.agent_skills import AgentSkillsSpecificationRules
from skilltrustops.services.lint import LintService

app = typer.Typer(
    name="skilltrustops",
    help="Review AI agent skills locally before they are trusted.",
    no_args_is_help=True,
)
console = Console()


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
) -> None:
    """Validate a skill's required files and metadata without executing it."""
    engine = StructureEngine(
        loader=SafeSkillFileLoader(),
        parser=FrontMatterParser(),
        rules=AgentSkillsSpecificationRules(),
    )
    report = LintService(engine).run(skill_path)

    if output_format is OutputFormat.JSON:
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2))
    else:
        _render_terminal(report)

    if not report.passed:
        raise typer.Exit(code=1)


def _render_terminal(report: LintReport) -> None:
    if report.passed:
        console.print(f"[bold green]PASS[/bold green] {report.target}")
        return

    console.print(f"[bold red]FAIL[/bold red] {report.target}")
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
