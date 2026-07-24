"""Composable engine for deterministic content detectors."""

from pathlib import Path
from typing import Protocol

from skilltrustops.domain.findings import Finding
from skilltrustops.domain.skills import SkillFile
from skilltrustops.engines.base import SkillFileLoader


class ContentDetector(Protocol):
    """Contract implemented by a deterministic content detector."""

    def scan(self, skill_file: SkillFile) -> tuple[Finding, ...]:
        """Return findings without executing skill content."""
        ...


class ContentScanEngine:
    """Load an untrusted skill once and apply configured detectors."""

    def __init__(
        self,
        loader: SkillFileLoader,
        detectors: tuple[ContentDetector, ...],
    ) -> None:
        self._loader = loader
        self._detectors = detectors

    def scan(self, skill_path: Path) -> tuple[Finding, ...]:
        """Run every configured detector against one bounded skill file."""
        loaded = self._loader.load(skill_path)
        if loaded.skill_file is None:
            return loaded.findings

        findings: list[Finding] = []
        for detector in self._detectors:
            findings.extend(detector.scan(loaded.skill_file))
        return tuple(findings)
