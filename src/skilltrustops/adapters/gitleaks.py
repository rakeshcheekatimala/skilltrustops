"""Safe adapter for the optional local Gitleaks CLI."""

from __future__ import annotations

import json
import os
import re
import shutil

# The adapter executes a resolved binary with an argument array and no shell.
import subprocess  # nosec B404
from pathlib import Path
from tempfile import TemporaryDirectory

from skilltrustops.domain.findings import Finding, Severity
from skilltrustops.domain.skills import SkillFile
from skilltrustops.engines.errors import ScannerError

GITLEAKS_TIMEOUT_SECONDS = 30


class GitleaksSecretDetector:
    """Scan bounded skill text with Gitleaks without exposing secret values."""

    def __init__(
        self,
        executable: str | None = None,
        timeout_seconds: int = GITLEAKS_TIMEOUT_SECONDS,
        config_path: Path | None = None,
    ) -> None:
        self._executable = executable
        self._timeout_seconds = timeout_seconds
        self._config_path = config_path

    def scan(self, skill_file: SkillFile) -> tuple[Finding, ...]:
        """Stream skill content to Gitleaks and parse its redacted JSON report."""
        executable = self._executable or shutil.which("gitleaks")
        if executable is None:
            raise ScannerError(
                "Gitleaks is selected by policy but is not installed or not on PATH. "
                "Install Gitleaks or enable the built-in secret scanner."
            )

        with TemporaryDirectory(prefix="skilltrustops-gitleaks-") as temp_dir:
            report_path = Path(temp_dir) / "report.json"
            command = [
                executable,
                "stdin",
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
                "--redact=100",
                "--ignore-gitleaks-allow",
                "--no-banner",
                "--no-color",
                "--log-level",
                "error",
                "--exit-code",
                "1",
                "--timeout",
                str(self._timeout_seconds),
            ]
            if self._config_path is not None:
                command.extend(("--config", str(self._config_path)))

            environment = os.environ.copy()
            environment.pop("GITLEAKS_CONFIG", None)
            environment.pop("GITLEAKS_CONFIG_TOML", None)
            try:
                # The command is an argument array; shell execution is disabled.
                completed = subprocess.run(  # nosec B603
                    command,
                    input=skill_file.content,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout_seconds + 1,
                    check=False,
                    shell=False,
                    env=environment,
                )
            except subprocess.TimeoutExpired as error:
                raise ScannerError(
                    f"Gitleaks exceeded the {self._timeout_seconds}-second timeout."
                ) from error
            except OSError as error:
                raise ScannerError(f"Gitleaks could not be started: {error}") from error

            if completed.returncode not in {0, 1}:
                raise ScannerError(
                    f"Gitleaks failed with exit code {completed.returncode}. "
                    "No scan result was accepted."
                )

            if not report_path.exists():
                if completed.returncode == 0:
                    return ()
                raise ScannerError(
                    "Gitleaks returned exit code 1 without a JSON report. "
                    "No scan result was accepted."
                )

            findings = self._parse_report(report_path, skill_file)
            if completed.returncode == 1 and not findings:
                raise ScannerError(
                    "Gitleaks returned exit code 1 without parseable findings. "
                    "No scan result was accepted."
                )
            return findings

    def _parse_report(
        self,
        report_path: Path,
        skill_file: SkillFile,
    ) -> tuple[Finding, ...]:
        try:
            raw_report: object = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ScannerError("Gitleaks produced an invalid JSON report.") from error

        if not isinstance(raw_report, list):
            raise ScannerError("Gitleaks JSON report must contain a list of findings.")

        findings: list[Finding] = []
        for item in raw_report:
            if not isinstance(item, dict):
                raise ScannerError("Gitleaks JSON report contains an invalid finding.")

            upstream_rule = self._safe_text(item.get("RuleID"), "unknown")
            start_line = self._safe_line(item.get("StartLine"))
            findings.append(
                Finding(
                    rule_id="STO-SEC-GL-001",
                    severity=Severity.CRITICAL,
                    message="Gitleaks detected a potential secret.",
                    evidence=(
                        f"Gitleaks rule {upstream_rule!r} matched at line "
                        f"{start_line}; secret, match, and source line redacted."
                    ),
                    remediation=(
                        "Remove and rotate the secret, then load it from an "
                        "approved secret store at runtime."
                    ),
                    location=f"{skill_file.path.name}:{start_line}",
                )
            )

        return tuple(findings)

    @staticmethod
    def _safe_text(value: object, fallback: str) -> str:
        if not isinstance(value, str) or not value.strip():
            return fallback
        cleaned = re.sub(r"[^A-Za-z0-9._-]", "-", value.strip())[:120]
        return cleaned or fallback

    @staticmethod
    def _safe_line(value: object) -> int:
        if isinstance(value, int) and value > 0:
            return value
        return 1
