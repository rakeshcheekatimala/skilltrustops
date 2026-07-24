"""Orchestration engine for static structure validation."""

from pathlib import Path

from skilltrustops.domain.findings import Finding
from skilltrustops.engines.base import SkillFileLoader, SkillParser, SkillRuleSet


class StructureEngine:
    """Compose replaceable loading, parsing, and specification-rule adapters."""

    def __init__(
        self,
        loader: SkillFileLoader,
        parser: SkillParser,
        rules: SkillRuleSet,
    ) -> None:
        self._loader = loader
        self._parser = parser
        self._rules = rules

    def scan(self, skill_path: Path) -> tuple[Finding, ...]:
        """Validate one skill file without executing its contents."""
        loaded = self._loader.load(skill_path)
        if loaded.skill_file is None:
            return loaded.findings

        parsed = self._parser.parse(loaded.skill_file)
        if parsed.skill is None:
            return parsed.findings

        return self._rules.validate(parsed.skill)
