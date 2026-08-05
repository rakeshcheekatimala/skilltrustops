"""Compliance rules for https://agentskills.io/specification."""

import unicodedata

from skilltrustops.domain.findings import Finding, Severity
from skilltrustops.domain.skills import ParsedSkill

SPECIFICATION_URL = "https://agentskills.io/specification"
MAX_NAME_LENGTH = 64
MAX_DESCRIPTION_LENGTH = 1024
MAX_COMPATIBILITY_LENGTH = 500
ALLOWED_FIELDS = frozenset(
    {
        "name",
        "description",
        "license",
        "compatibility",
        "metadata",
        "allowed-tools",
    }
)


class AgentSkillsSpecificationRules:
    """Validate parsed metadata against the Agent Skills specification."""

    def validate(self, skill: ParsedSkill) -> tuple[Finding, ...]:
        """Return every structural compliance failure for one parsed skill."""
        findings: list[Finding] = []
        findings.extend(self._validate_top_level_fields(skill.metadata))
        findings.extend(self._validate_name(skill))
        findings.extend(self._validate_description(skill.metadata))
        findings.extend(self._validate_optional_fields(skill.metadata))

        if not skill.body.strip():
            findings.append(
                self._finding(
                    "STO-LINT-017",
                    "SKILL.md has no instruction body.",
                    "Only YAML front matter was found.",
                    "Add Markdown instructions after the closing '---' delimiter.",
                )
            )

        return tuple(findings)

    def _validate_top_level_fields(
        self, metadata: dict[object, object]
    ) -> list[Finding]:
        unexpected = [key for key in metadata if key not in ALLOWED_FIELDS]
        if not unexpected:
            return []

        rendered = ", ".join(sorted(repr(key) for key in unexpected))
        return [
            self._finding(
                "STO-LINT-021",
                "Front matter contains unsupported fields.",
                f"Unexpected fields: {rendered}.",
                "Move extension data under 'metadata' or remove unsupported fields.",
            )
        ]

    def _validate_name(self, skill: ParsedSkill) -> list[Finding]:
        name = skill.metadata.get("name")
        if not isinstance(name, str) or not name.strip():
            return [
                self._finding(
                    "STO-LINT-014",
                    "Skill metadata requires a non-empty string name.",
                    f"Received name: {name!r}",
                    "Add a non-empty 'name' string to the YAML front matter.",
                )
            ]

        findings: list[Finding] = []
        normalized_name = unicodedata.normalize("NFKC", name.strip())

        if len(normalized_name) > MAX_NAME_LENGTH:
            findings.append(
                self._finding(
                    "STO-LINT-019",
                    "Skill name exceeds the specification limit.",
                    f"Name length is {len(normalized_name)}; maximum is "
                    f"{MAX_NAME_LENGTH} characters.",
                    f"Shorten the skill name to {MAX_NAME_LENGTH} characters or fewer.",
                )
            )

        format_problems: list[str] = []
        if normalized_name != normalized_name.lower():
            format_problems.append("contains uppercase characters")
        if normalized_name.startswith("-") or normalized_name.endswith("-"):
            format_problems.append("starts or ends with a hyphen")
        if "--" in normalized_name:
            format_problems.append("contains consecutive hyphens")
        valid_characters = all(
            character.isalnum() or character == "-" for character in normalized_name
        )
        if not valid_characters:
            format_problems.append(
                "contains characters other than letters, digits, or hyphens"
            )

        if format_problems:
            findings.append(
                self._finding(
                    "STO-LINT-015",
                    "Skill name does not follow the required format.",
                    f"Name {normalized_name!r} " + "; ".join(format_problems) + ".",
                    "Use lowercase alphanumeric characters and single internal "
                    "hyphens.",
                )
            )

        directory_name = unicodedata.normalize("NFKC", skill.path.parent.name)
        if normalized_name != directory_name:
            findings.append(
                self._finding(
                    "STO-LINT-016",
                    "Skill name must match its parent directory name.",
                    f"Metadata name {normalized_name!r} differs from "
                    f"directory {skill.path.parent.name!r}.",
                    "Rename the parent directory or update the metadata name.",
                )
            )

        return findings

    def _validate_description(self, metadata: dict[object, object]) -> list[Finding]:
        description = metadata.get("description")
        if not isinstance(description, str) or not description.strip():
            return [
                self._finding(
                    "STO-LINT-018",
                    "Skill metadata requires a non-empty string description.",
                    f"Received description: {description!r}",
                    "Describe what the skill does and when to use it.",
                )
            ]

        if len(description) > MAX_DESCRIPTION_LENGTH:
            return [
                self._finding(
                    "STO-LINT-020",
                    "Skill description exceeds the specification limit.",
                    f"Description length is {len(description)}; maximum is "
                    f"{MAX_DESCRIPTION_LENGTH} characters.",
                    f"Shorten the description to {MAX_DESCRIPTION_LENGTH} "
                    "characters or fewer.",
                )
            ]

        return []

    def _validate_optional_fields(
        self, metadata: dict[object, object]
    ) -> list[Finding]:
        findings: list[Finding] = []

        if "license" in metadata:
            license_value = metadata["license"]
            if not isinstance(license_value, str) or not license_value.strip():
                findings.append(
                    self._finding(
                        "STO-LINT-022",
                        "Optional license must be a non-empty string.",
                        f"Received license: {license_value!r}",
                        "Use a license name or a bundled license-file reference.",
                    )
                )

        if "compatibility" in metadata:
            compatibility = metadata["compatibility"]
            if not isinstance(compatibility, str) or not compatibility.strip():
                findings.append(
                    self._finding(
                        "STO-LINT-023",
                        "Optional compatibility must be a non-empty string.",
                        f"Received compatibility: {compatibility!r}",
                        "Remove the field or describe the environment requirements.",
                    )
                )
            elif len(compatibility) > MAX_COMPATIBILITY_LENGTH:
                findings.append(
                    self._finding(
                        "STO-LINT-023",
                        "Compatibility exceeds the specification limit.",
                        f"Compatibility length is {len(compatibility)}; maximum is "
                        f"{MAX_COMPATIBILITY_LENGTH} characters.",
                        f"Shorten compatibility to {MAX_COMPATIBILITY_LENGTH} "
                        "characters or fewer.",
                    )
                )

        if "metadata" in metadata:
            extension_metadata = metadata["metadata"]
            if not isinstance(extension_metadata, dict):
                findings.append(
                    self._finding(
                        "STO-LINT-024",
                        "Optional metadata must be a key-value mapping.",
                        f"Received metadata type: {type(extension_metadata).__name__}.",
                        "Use a mapping containing string keys and string values.",
                    )
                )
            else:
                invalid_entries = [
                    (key, value)
                    for key, value in extension_metadata.items()
                    if not isinstance(key, str) or not isinstance(value, str)
                ]
                if invalid_entries:
                    rendered = ", ".join(
                        f"{key!r}: {value!r}" for key, value in invalid_entries
                    )
                    findings.append(
                        self._finding(
                            "STO-LINT-024",
                            "Optional metadata keys and values must be strings.",
                            f"Invalid metadata entries: {rendered}.",
                            "Convert every metadata key and value to a string.",
                        )
                    )

        if "allowed-tools" in metadata:
            allowed_tools = metadata["allowed-tools"]
            if not isinstance(allowed_tools, str) or not allowed_tools.strip():
                findings.append(
                    self._finding(
                        "STO-LINT-025",
                        "Experimental allowed-tools must be a non-empty string.",
                        f"Received allowed-tools: {allowed_tools!r}",
                        "Use a space-separated string of pre-approved tools.",
                    )
                )

        return findings

    @staticmethod
    def _finding(
        rule_id: str,
        message: str,
        evidence: str,
        remediation: str,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            severity=Severity.ERROR,
            message=message,
            evidence=evidence,
            remediation=remediation,
            location="SKILL.md",
        )
