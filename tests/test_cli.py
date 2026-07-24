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
    assert report["schema_version"] == "1.1"
    assert report["specification"] == "https://agentskills.io/specification"
    assert report["command"] == "lint"
    assert report["policy"]["profile"] == "recommended-v1"
    assert len(report["policy"]["sha256"]) == 64
    assert report["passed"] is True
    assert report["findings"] == []


def test_lint_accepts_explicit_json_policy(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "version": 1,
                "profile": "recommended-v1",
                "checks": {
                    "lint": {
                        "enabled": True,
                        "ruleset": "agent-skills-specification",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "lint",
            str(create_valid_skill(tmp_path)),
            "--policy",
            str(policy_path),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["policy"]["source"] == str(policy_path.absolute())


def test_lint_refuses_to_claim_pass_when_disabled(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "version: 1\n"
        "profile: recommended-v1\n"
        "checks:\n"
        "  lint:\n"
        "    enabled: false\n"
        "    ruleset: agent-skills-specification\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["lint", str(create_valid_skill(tmp_path)), "--policy", str(policy_path)],
    )

    assert result.exit_code == 2
    assert "lint check is disabled" in result.stdout


def test_policy_init_generates_yaml_without_overwrite(tmp_path: Path) -> None:
    destination = tmp_path / "skilltrustops.yaml"

    first = runner.invoke(
        app,
        ["policy", "init", "--output", str(destination)],
    )
    second = runner.invoke(
        app,
        ["policy", "init", "--output", str(destination)],
    )

    assert first.exit_code == 0
    assert destination.exists()
    assert second.exit_code == 2
    assert "was not overwritten" in second.stdout


def test_policy_init_generates_json(tmp_path: Path) -> None:
    destination = tmp_path / "skilltrustops.json"

    result = runner.invoke(
        app,
        [
            "policy",
            "init",
            "--format",
            "json",
            "--output",
            str(destination),
        ],
    )

    assert result.exit_code == 0
    generated = json.loads(destination.read_text(encoding="utf-8"))
    assert generated["profile"] == "recommended-v1"
    assert generated["checks"]["lint"]["enabled"] is True
