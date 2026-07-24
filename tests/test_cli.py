import json
from pathlib import Path

from typer.testing import CliRunner

from skilltrustops.cli import app

runner = CliRunner()


def create_valid_skill(tmp_path: Path) -> Path:
    skill_path = tmp_path / "example-skill"
    skill_path.mkdir()
    skill_file = skill_path / "SKILL.md"
    skill_file.write_text(
        "---\n"
        "name: example-skill\n"
        "description: Reviews an example skill safely.\n"
        "---\n"
        "# Instructions\n"
        "Review the provided input.\n",
        encoding="utf-8",
    )
    return skill_file


def test_lint_passes_valid_skill(tmp_path: Path) -> None:
    result = runner.invoke(app, ["lint", str(create_valid_skill(tmp_path))])

    assert result.exit_code == 0
    assert "PASS" in result.stdout


def test_lint_fails_invalid_skill(tmp_path: Path) -> None:
    result = runner.invoke(app, ["lint", str(tmp_path / "SKILL.md")])

    assert result.exit_code == 1
    assert "STO-LINT-001" in result.stdout
    assert "Remediation" in result.stdout


def test_lint_emits_machine_readable_json(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["lint", str(create_valid_skill(tmp_path)), "--format", "json"],
    )

    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["schema_version"] == "1.0"
    assert report["specification"] == "https://agentskills.io/specification"
    assert report["command"] == "lint"
    assert report["passed"] is True
    assert report["findings"] == []
