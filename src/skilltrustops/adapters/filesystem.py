"""Bounded, non-executing access to an untrusted skill file."""

from pathlib import Path

from skilltrustops.domain.findings import Finding, Severity
from skilltrustops.domain.skills import LoadResult, SkillFile

MAX_SKILL_FILE_BYTES = 1024 * 1024


class SafeSkillFileLoader:
    """Load exactly one regular SKILL.md file under strict limits."""

    def __init__(self, rule_prefix: str = "STO-LINT") -> None:
        self._rule_prefix = rule_prefix

    def load(self, skill_path: Path) -> LoadResult:
        """Read one file as UTF-8 without following symbolic links."""
        if skill_path.is_symlink():
            return self._failure(
                self._rule_id("002"),
                "Skill file must not be a symbolic link.",
                f"Skill path is a symbolic link: {skill_path}",
                "Inspect a regular SKILL.md file instead of a symbolic link.",
            )

        if not skill_path.exists():
            return self._failure(
                self._rule_id("001"),
                "Skill file does not exist.",
                f"Path not found: {skill_path}",
                "Provide the path to an existing SKILL.md file.",
            )

        if not skill_path.is_file():
            return self._failure(
                self._rule_id("003"),
                "Skill path is not a regular file.",
                f"Expected one file but received: {skill_path}",
                "Pass a SKILL.md file directly, or use the batch scan API/command "
                "for recursive directory discovery.",
            )

        if skill_path.name != "SKILL.md":
            return self._failure(
                self._rule_id("004"),
                "Skill file must be named SKILL.md.",
                f"Received filename: {skill_path.name!r}",
                "Rename the file to SKILL.md.",
            )

        try:
            size = skill_path.stat().st_size
        except OSError as error:
            return self._read_failure(error)

        if size > MAX_SKILL_FILE_BYTES:
            return self._failure(
                self._rule_id("007"),
                "SKILL.md exceeds the maximum allowed size.",
                f"SKILL.md is {size} bytes; limit is {MAX_SKILL_FILE_BYTES} bytes.",
                "Reduce SKILL.md to 1 MiB or less.",
            )

        try:
            content = skill_path.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            return self._failure(
                self._rule_id("008"),
                "SKILL.md is not valid UTF-8.",
                f"UTF-8 decoding failed at byte {error.start}.",
                "Save SKILL.md as UTF-8 text.",
            )
        except OSError as error:
            return self._read_failure(error)

        return LoadResult(skill_file=SkillFile(path=skill_path, content=content))

    def _rule_id(self, suffix: str) -> str:
        return f"{self._rule_prefix}-{suffix}"

    @staticmethod
    def _failure(
        rule_id: str,
        message: str,
        evidence: str,
        remediation: str,
    ) -> LoadResult:
        return LoadResult(
            skill_file=None,
            findings=(
                Finding(
                    rule_id=rule_id,
                    severity=Severity.ERROR,
                    message=message,
                    evidence=evidence,
                    remediation=remediation,
                    location=None,
                ),
            ),
        )

    def _read_failure(self, error: OSError) -> LoadResult:
        return self._failure(
            self._rule_id("009"),
            "SKILL.md could not be read safely.",
            f"Read failed: {error}",
            "Ensure SKILL.md is a readable regular file and retry.",
        )
