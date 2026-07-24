"""Internal data structures for safely loaded and parsed skill files."""

from dataclasses import dataclass
from pathlib import Path

from skilltrustops.domain.findings import Finding


@dataclass(frozen=True, slots=True)
class SkillFile:
    """UTF-8 text loaded from one untrusted skill file."""

    path: Path
    content: str


@dataclass(frozen=True, slots=True)
class ParsedSkill:
    """Data-only representation of a skill; it contains no executable behavior."""

    path: Path
    metadata: dict[object, object]
    body: str


@dataclass(frozen=True, slots=True)
class LoadResult:
    """Result of crossing the untrusted filesystem boundary."""

    skill_file: SkillFile | None
    findings: tuple[Finding, ...] = ()


@dataclass(frozen=True, slots=True)
class ParseResult:
    """Result of parsing a loaded skill as data."""

    skill: ParsedSkill | None
    findings: tuple[Finding, ...] = ()
