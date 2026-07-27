import json
import subprocess
from pathlib import Path

import pytest

import skilltrustops.adapters.gitleaks as gitleaks_module
from skilltrustops.adapters.gitleaks import GitleaksSecretDetector
from skilltrustops.domain.skills import SkillFile
from skilltrustops.engines.errors import ScannerError


def skill_file(content: str) -> SkillFile:
    return SkillFile(path=Path("SKILL.md"), content=content)


def test_gitleaks_maps_findings_without_exposing_sensitive_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "sensitive-" + "credential-" + "value"
    captured_command: list[str] = []
    captured_options: dict[str, object] = {}
    config_path = tmp_path / "gitleaks.toml"
    config_path.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
    monkeypatch.setenv("GITLEAKS_CONFIG", "/untrusted/config.toml")
    monkeypatch.setenv("GITLEAKS_CONFIG_TOML", "untrusted config")

    def fake_run(
        command: list[str],
        **options: object,
    ) -> subprocess.CompletedProcess[str]:
        captured_command.extend(command)
        captured_options.update(options)
        report_path = Path(command[command.index("--report-path") + 1])
        report_path.write_text(
            json.dumps(
                [
                    {
                        "RuleID": "generic-api-key",
                        "Description": "Generic API Key",
                        "StartLine": 7,
                        "Secret": secret,
                        "Match": f"token={secret}",
                        "Line": f"token={secret}",
                    }
                ]
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 1, "", "")

    monkeypatch.setattr(gitleaks_module.subprocess, "run", fake_run)

    findings = GitleaksSecretDetector(
        executable="/usr/local/bin/gitleaks",
        config_path=config_path,
    ).scan(skill_file(f"token={secret}"))
    rendered = "\n".join(
        " ".join(
            (
                finding.message,
                finding.evidence,
                finding.remediation,
                finding.location or "",
            )
        )
        for finding in findings
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "STO-SEC-GL-001"
    assert secret not in rendered
    assert captured_command[1] == "stdin"
    assert "--redact=100" in captured_command
    assert "--ignore-gitleaks-allow" in captured_command
    assert captured_command[captured_command.index("--config") + 1] == str(config_path)
    assert "SKILL.md" not in captured_command
    assert captured_options["input"] == f"token={secret}"
    assert captured_options["shell"] is False
    environment = captured_options["env"]
    assert isinstance(environment, dict)
    assert "GITLEAKS_CONFIG" not in environment
    assert "GITLEAKS_CONFIG_TOML" not in environment


def test_gitleaks_returns_no_findings_on_success_without_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        command: list[str],
        **options: object,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(gitleaks_module.subprocess, "run", fake_run)

    findings = GitleaksSecretDetector(executable="gitleaks").scan(
        skill_file("Safe content.")
    )

    assert findings == ()


def test_gitleaks_fails_when_binary_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gitleaks_module.shutil, "which", lambda _: None)

    with pytest.raises(ScannerError, match="not installed"):
        GitleaksSecretDetector().scan(skill_file("content"))


def test_gitleaks_rejects_exit_one_without_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        command: list[str],
        **options: object,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 1, "", "")

    monkeypatch.setattr(gitleaks_module.subprocess, "run", fake_run)

    with pytest.raises(ScannerError, match="without a JSON report"):
        GitleaksSecretDetector(executable="gitleaks").scan(skill_file("content"))


def test_gitleaks_rejects_malformed_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        command: list[str],
        **options: object,
    ) -> subprocess.CompletedProcess[str]:
        report_path = Path(command[command.index("--report-path") + 1])
        report_path.write_text("{broken", encoding="utf-8")
        return subprocess.CompletedProcess(command, 1, "", "")

    monkeypatch.setattr(gitleaks_module.subprocess, "run", fake_run)

    with pytest.raises(ScannerError, match="invalid JSON report"):
        GitleaksSecretDetector(executable="gitleaks").scan(skill_file("content"))
