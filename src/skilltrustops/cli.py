"""Command-line entry point for SkillTrustOps."""

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer
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
from skilltrustops.redteam.targets import OpenAIModelTarget, ReferenceModelTarget
from skilltrustops.sandbox.providers import provider_from_policy
from skilltrustops.services.batch import BatchScanError
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
app.add_typer(redteam_app, name="redteam")


class OutputFormat(StrEnum):
    """Supported lint report renderers."""

    TERMINAL = "terminal"
    JSON = "json"


class ModelProvider(StrEnum):
    REFERENCE = "reference"
    OPENAI = "openai"


class SandboxProviderName(StrEnum):
    NONE = "none"
    DOCKER = "docker"
    GVISOR = "gvisor"


class ManifestGenerationProvider(StrEnum):
    OPENAI = "openai"
    DETERMINISTIC = "deterministic"


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
    ] = ManifestGenerationProvider.OPENAI,
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
        OutputFormat,
        typer.Option("--format", help="Report output format."),
    ] = OutputFormat.TERMINAL,
) -> None:
    """Apply one policy and report deterministic per-skill timings."""
    try:
        report = scan_target(target, policy_path=policy_path)
    except (BatchScanError, PolicyError) as error:
        console.print(f"[bold red]SCAN ERROR[/bold red] {error}")
        raise typer.Exit(code=2) from error
    if output_format is OutputFormat.JSON:
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2))
    else:
        _render_batch_report(report)
    if report.summary.errors:
        raise typer.Exit(code=2)
    if report.summary.failed:
        raise typer.Exit(code=1)


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
        target = (
            OpenAIModelTarget(model)
            if provider is ModelProvider.OPENAI
            else ReferenceModelTarget(model)
        )
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
            "assured": "green",
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
    if report.decision.value != "assured":
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


def _render_batch_report(report: BatchScanReport) -> None:
    table = Table(show_header=True, header_style="bold")
    table.add_column("Skill")
    table.add_column("Path")
    table.add_column("Status")
    table.add_column("Findings", justify="right")
    table.add_column("Time (ms)", justify="right")
    for skill in report.skills:
        findings = sum(check.finding_count for check in skill.checks)
        table.add_row(
            skill.skill,
            skill.relative_path,
            skill.status.upper(),
            str(findings),
            f"{skill.duration_ms:.3f}",
        )
    console.print(table)
    console.print(
        f"Scanned {report.summary.discovered} skill(s): "
        f"{report.summary.passed} passed, {report.summary.failed} failed, "
        f"{report.summary.errors} errors in {report.duration_ms:.3f} ms"
    )
    console.print(
        f"[dim]Policy: {report.policy.profile} ({report.policy.source}); "
        f"SHA-256: {report.policy.sha256}[/dim]"
    )
    console.print(table)
