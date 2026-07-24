"""Interfaces implemented by scanning engines."""

from pathlib import Path
from typing import Protocol

from skilltrustops.domain.findings import Finding
from skilltrustops.domain.skills import LoadResult, ParsedSkill, ParseResult, SkillFile


class SkillFileLoader(Protocol):
    """Contract for bounded access to one untrusted skill file."""

    def load(self, skill_path: Path) -> LoadResult:
        """Load a skill file without executing or interpreting its contents."""
        ...


class SkillParser(Protocol):
    """Contract for converting skill text into a data-only representation."""

    def parse(self, skill_file: SkillFile) -> ParseResult:
        """Parse a loaded skill file as data."""
        ...


class SkillRuleSet(Protocol):
    """Contract for validating a parsed skill against one specification."""

    def validate(self, skill: ParsedSkill) -> tuple[Finding, ...]:
        """Return specification findings for a data-only skill."""
        ...


class LintEngine(Protocol):
    """Contract for engines that validate a skill without executing it."""

    def scan(self, skill_path: Path) -> tuple[Finding, ...]:
        """Return all structural findings for a skill."""
        ...
