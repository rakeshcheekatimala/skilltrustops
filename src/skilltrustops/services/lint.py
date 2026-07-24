"""Application service for structural linting."""

from pathlib import Path

from skilltrustops import __version__
from skilltrustops.domain.reports import LintReport
from skilltrustops.engines.base import LintEngine


class LintService:
    """Coordinate linting independently from CLI presentation."""

    def __init__(self, engine: LintEngine) -> None:
        self._engine = engine

    def run(self, skill_path: Path) -> LintReport:
        """Inspect a skill and return a serializable report."""
        findings = self._engine.scan(skill_path)
        return LintReport(
            tool_version=__version__,
            target=str(skill_path.absolute()),
            passed=not findings,
            findings=findings,
        )
