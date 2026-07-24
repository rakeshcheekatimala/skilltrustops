"""Application service for deterministic security and privacy scanning."""

from pathlib import Path
from time import perf_counter
from typing import Literal

from skilltrustops import __version__
from skilltrustops.domain.reports import PolicyReference, StaticScanReport
from skilltrustops.engines.base import LintEngine


class StaticScanService:
    """Run one policy-selected deterministic scan."""

    def __init__(
        self,
        engine: LintEngine,
        command: Literal["security", "privacy"],
    ) -> None:
        self._engine = engine
        self._command = command

    def run(self, skill_path: Path, policy: PolicyReference) -> StaticScanReport:
        """Inspect one untrusted skill and return a reproducible report."""
        started = perf_counter()
        findings = self._engine.scan(skill_path)
        duration_ms = (perf_counter() - started) * 1000
        return StaticScanReport(
            tool_version=__version__,
            command=self._command,
            target=str(skill_path.absolute()),
            policy=policy,
            duration_ms=round(duration_ms, 3),
            passed=not findings,
            findings=findings,
        )
