"""Safe YAML front-matter parsing for skill files."""

import yaml

from skilltrustops.domain.findings import Finding, Severity
from skilltrustops.domain.skills import ParsedSkill, ParseResult, SkillFile


class FrontMatterParser:
    """Parse metadata with PyYAML's non-executing safe loader."""

    def parse(self, skill_file: SkillFile) -> ParseResult:
        """Split one loaded skill into YAML metadata and Markdown body."""
        lines = skill_file.content.splitlines()
        if not lines or lines[0].strip() != "---":
            return self._failure(
                "STO-LINT-010",
                "SKILL.md must start with YAML front matter.",
                "The first line is not the '---' delimiter.",
                "Add YAML front matter at the start of SKILL.md.",
                "SKILL.md:1",
            )

        closing_index = next(
            (
                index
                for index, line in enumerate(lines[1:], start=1)
                if line.strip() == "---"
            ),
            None,
        )
        if closing_index is None:
            return self._failure(
                "STO-LINT-011",
                "YAML front matter is not closed.",
                "No closing '---' delimiter was found.",
                "Add a closing '---' delimiter before the Markdown body.",
                "SKILL.md",
            )

        yaml_text = "\n".join(lines[1:closing_index])
        body = "\n".join(lines[closing_index + 1 :])
        try:
            loaded: object = yaml.safe_load(yaml_text)
        except yaml.YAMLError as error:
            return self._failure(
                "STO-LINT-012",
                "YAML front matter is invalid.",
                f"Safe YAML parsing failed: {error}",
                "Correct the YAML syntax in the front matter.",
                "SKILL.md",
            )

        if not isinstance(loaded, dict):
            return self._failure(
                "STO-LINT-013",
                "YAML front matter must be a mapping.",
                f"Parsed front matter type: {type(loaded).__name__}",
                "Use key-value metadata such as 'name:' and 'description:'.",
                "SKILL.md",
            )

        metadata: dict[object, object] = loaded
        return ParseResult(
            skill=ParsedSkill(
                path=skill_file.path,
                metadata=metadata,
                body=body,
            )
        )

    @staticmethod
    def _failure(
        rule_id: str,
        message: str,
        evidence: str,
        remediation: str,
        location: str,
    ) -> ParseResult:
        return ParseResult(
            skill=None,
            findings=(
                Finding(
                    rule_id=rule_id,
                    severity=Severity.ERROR,
                    message=message,
                    evidence=evidence,
                    remediation=remediation,
                    location=location,
                ),
            ),
        )
