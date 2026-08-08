"""Deterministic file-or-folder scanning with per-skill timings."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from time import perf_counter
from typing import Literal

from skilltrustops import __version__
from skilltrustops.domain.reports import (
    BatchCheckResult,
    BatchScanReport,
    BatchSkillResult,
    BatchSummary,
    LintReport,
    StaticScanReport,
)
from skilltrustops.engines.errors import ScannerError
from skilltrustops.factories import (
    build_lint_engine,
    build_privacy_engine,
    build_security_engine,
)
from skilltrustops.policies.loader import LoadedPolicy
from skilltrustops.services.lint import LintService
from skilltrustops.services.static_scan import StaticScanService

MAX_BATCH_SKILLS = 10_000
IGNORED_DISCOVERY_DIRECTORIES = frozenset({".git", ".hg", ".svn"})


class BatchScanError(ValueError):
    """Raised when a batch target cannot be discovered safely."""


class BatchScanService:
    """Apply one loaded policy to every SKILL.md under a target."""

    def run(self, target: Path, loaded_policy: LoadedPolicy) -> BatchScanReport:
        started = perf_counter()
        root, skill_paths = self.discover(target)
        results = tuple(
            self._scan_skill(path, root, loaded_policy) for path in skill_paths
        )
        return BatchScanReport(
            tool_version=__version__,
            target=str(target.absolute()),
            policy=loaded_policy.reference,
            duration_ms=self._elapsed_ms(started),
            summary=BatchSummary(
                discovered=len(results),
                passed=sum(result.status == "passed" for result in results),
                failed=sum(result.status == "failed" for result in results),
                errors=sum(result.status == "error" for result in results),
            ),
            skills=results,
        )

    @staticmethod
    def discover(target: Path) -> tuple[Path, tuple[Path, ...]]:
        absolute = target.absolute()
        if absolute.is_symlink():
            raise BatchScanError(f"Batch target must not be a symbolic link: {target}")
        if absolute.is_file():
            if absolute.name != "SKILL.md":
                raise BatchScanError("A file target must be named SKILL.md")
            return absolute.parent, (absolute,)
        if not absolute.exists():
            raise BatchScanError(f"Batch target does not exist: {target}")
        if not absolute.is_dir():
            raise BatchScanError(f"Batch target is not a file or directory: {target}")

        paths = tuple(
            sorted(
                (
                    path
                    for path in absolute.rglob("SKILL.md")
                    if not path.is_symlink()
                    and path.is_file()
                    and not IGNORED_DISCOVERY_DIRECTORIES.intersection(
                        path.relative_to(absolute).parts[:-1]
                    )
                ),
                key=lambda path: path.relative_to(absolute).as_posix(),
            )
        )
        if not paths:
            raise BatchScanError(f"No SKILL.md files found under: {target}")
        if len(paths) > MAX_BATCH_SKILLS:
            raise BatchScanError(
                f"Found {len(paths)} skills; maximum is {MAX_BATCH_SKILLS}"
            )
        return absolute, paths

    def _scan_skill(
        self,
        skill_path: Path,
        root: Path,
        loaded: LoadedPolicy,
    ) -> BatchSkillResult:
        started = perf_counter()
        checks: list[BatchCheckResult] = []
        policy = loaded.policy

        if policy.checks.lint.enabled:
            checks.append(
                self._run_check(
                    "lint",
                    lambda: LintService(build_lint_engine(policy.checks.lint)).run(
                        skill_path, loaded.reference
                    ),
                )
            )
        else:
            checks.append(self._skipped("lint"))

        security = policy.checks.security
        if security is not None and security.enabled:
            checks.append(
                self._run_check(
                    "security",
                    lambda: StaticScanService(
                        build_security_engine(security, loaded.base_dir), "security"
                    ).run(skill_path, loaded.reference),
                )
            )
        else:
            checks.append(self._skipped("security"))

        privacy = policy.checks.privacy
        if privacy is not None and privacy.enabled:
            checks.append(
                self._run_check(
                    "privacy",
                    lambda: StaticScanService(
                        build_privacy_engine(privacy), "privacy"
                    ).run(skill_path, loaded.reference),
                )
            )
        else:
            checks.append(self._skipped("privacy"))

        status: Literal["passed", "failed", "error"] = (
            "error"
            if any(check.status == "error" for check in checks)
            else "failed"
            if any(check.status == "failed" for check in checks)
            else "passed"
        )
        return BatchSkillResult(
            skill=skill_path.parent.name,
            relative_path=skill_path.relative_to(root).as_posix(),
            status=status,
            duration_ms=self._elapsed_ms(started),
            checks=tuple(checks),
        )

    def _run_check(
        self,
        command: Literal["lint", "security", "privacy"],
        operation: Callable[[], LintReport | StaticScanReport],
    ) -> BatchCheckResult:
        started = perf_counter()
        try:
            report = operation()
            if not isinstance(report, (LintReport, StaticScanReport)):
                raise TypeError("Unexpected check report")
            return BatchCheckResult(
                command=command,
                status="passed" if report.passed else "failed",
                duration_ms=self._elapsed_ms(started),
                finding_count=len(report.findings),
                findings=report.findings,
            )
        except ScannerError as error:
            return BatchCheckResult(
                command=command,
                status="error",
                duration_ms=self._elapsed_ms(started),
                error=str(error),
            )

    @staticmethod
    def _skipped(
        command: Literal["lint", "security", "privacy"],
    ) -> BatchCheckResult:
        return BatchCheckResult(
            command=command,
            status="skipped",
            duration_ms=0.0,
        )

    @staticmethod
    def _elapsed_ms(started: float) -> float:
        return round((perf_counter() - started) * 1000, 3)
