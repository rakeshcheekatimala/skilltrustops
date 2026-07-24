import json
from pathlib import Path

from typer.testing import CliRunner

from skilltrustops.cli import app
from skilltrustops.policies.profiles import recommended_v2

runner = CliRunner()


def create_skill(tmp_path: Path, body: str) -> Path:
    skill_dir = tmp_path / "risky-skill"
    skill_dir.mkdir()
    skill_path = skill_dir / "SKILL.md"
    skill_path.write_text(
        "---\n"
        "name: risky-skill\n"
        "description: Exercises deterministic static scanning locally.\n"
        "---\n"
        f"{body}\n",
        encoding="utf-8",
    )
    return skill_path


def test_security_command_fails_on_secret_without_exposing_it(tmp_path: Path) -> None:
    secret = "ghp_" + ("a" * 36)
    skill_path = create_skill(tmp_path, f"token = {secret}")

    result = runner.invoke(
        app,
        ["security", str(skill_path), "--format", "json"],
    )

    assert result.exit_code == 1
    assert secret not in result.stdout
    report = json.loads(result.stdout)
    assert report["command"] == "security"
    assert report["deterministic"] is True
    assert report["passed"] is False
    assert report["findings"][0]["severity"] == "critical"


def test_privacy_command_fails_on_pii_without_exposing_it(tmp_path: Path) -> None:
    email = "person" + "@example.com"
    skill_path = create_skill(tmp_path, f"Contact: {email}")

    result = runner.invoke(
        app,
        ["privacy", str(skill_path), "--format", "json"],
    )

    assert result.exit_code == 1
    assert email not in result.stdout
    report = json.loads(result.stdout)
    assert report["command"] == "privacy"
    assert report["passed"] is False
    assert report["findings"][0]["rule_id"] == "STO-PRIV-001"


def test_security_and_privacy_pass_clean_skill(tmp_path: Path) -> None:
    skill_path = create_skill(tmp_path, "Summarize the supplied document.")

    security_result = runner.invoke(app, ["security", str(skill_path)])
    privacy_result = runner.invoke(app, ["privacy", str(skill_path)])

    assert security_result.exit_code == 0
    assert privacy_result.exit_code == 0
    assert "PASS security" in security_result.stdout
    assert "PASS privacy" in privacy_result.stdout


def test_security_requires_v2_policy(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "version: 1\n"
        "profile: recommended-v1\n"
        "checks:\n"
        "  lint:\n"
        "    enabled: true\n"
        "    ruleset: agent-skills-specification\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "security",
            str(create_skill(tmp_path, "Safe instructions.")),
            "--policy",
            str(policy_path),
        ],
    )

    assert result.exit_code == 2
    assert "not configured" in result.stdout


def test_security_refuses_to_claim_pass_when_disabled(tmp_path: Path) -> None:
    policy_data = recommended_v2().model_dump(mode="json")
    checks = policy_data["checks"]
    assert isinstance(checks, dict)
    security = checks["security"]
    assert isinstance(security, dict)
    security["enabled"] = False
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy_data), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "security",
            str(create_skill(tmp_path, "Safe instructions.")),
            "--policy",
            str(policy_path),
        ],
    )

    assert result.exit_code == 2
    assert "security check is disabled" in result.stdout
