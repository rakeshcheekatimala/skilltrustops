from pathlib import Path

import pytest

from skilltrustops.adapters.filesystem import (
    MAX_SKILL_FILE_BYTES,
    SafeSkillFileLoader,
)
from skilltrustops.engines.structure import StructureEngine
from skilltrustops.parsers.front_matter import FrontMatterParser
from skilltrustops.rules.agent_skills import (
    MAX_COMPATIBILITY_LENGTH,
    MAX_DESCRIPTION_LENGTH,
    MAX_NAME_LENGTH,
    AgentSkillsSpecificationRules,
)


def engine() -> StructureEngine:
    return StructureEngine(
        loader=SafeSkillFileLoader(),
        parser=FrontMatterParser(),
        rules=AgentSkillsSpecificationRules(),
    )


def scan(
    tmp_path: Path,
    content: str,
    directory_name: str = "example-skill",
) -> set[str]:
    skill_path = tmp_path / directory_name
    skill_path.mkdir()
    skill_file = skill_path / "SKILL.md"
    skill_file.write_text(content, encoding="utf-8")
    return {finding.rule_id for finding in engine().scan(skill_file)}


def valid_content(name: str = "example-skill") -> str:
    return (
        "---\n"
        f"name: {name}\n"
        "description: Reviews an example skill safely.\n"
        "---\n"
        "\n"
        "# Instructions\n"
        "\n"
        "Review the provided input.\n"
    )


def test_valid_skill_passes(tmp_path: Path) -> None:
    assert scan(tmp_path, valid_content()) == set()


@pytest.mark.parametrize(
    ("path_setup", "expected_rule"),
    [
        ("missing", "STO-LINT-001"),
        ("directory", "STO-LINT-003"),
        ("wrong_name", "STO-LINT-004"),
    ],
)
def test_invalid_skill_file_paths(
    tmp_path: Path, path_setup: str, expected_rule: str
) -> None:
    skill_path = tmp_path / "SKILL.md"
    if path_setup == "directory":
        skill_path.mkdir()
    elif path_setup == "wrong_name":
        skill_path = tmp_path / "skill.md"
        skill_path.write_text(valid_content(), encoding="utf-8")

    findings = engine().scan(skill_path)

    assert {finding.rule_id for finding in findings} == {expected_rule}


def test_rejects_symlinked_skill_file(tmp_path: Path) -> None:
    outside = tmp_path / "outside.md"
    outside.write_text(valid_content(), encoding="utf-8")
    skill_path = tmp_path / "SKILL.md"
    skill_path.symlink_to(outside)

    assert engine().scan(skill_path)[0].rule_id == "STO-LINT-002"


def test_rejects_oversized_skill_file(tmp_path: Path) -> None:
    skill_path = tmp_path / "SKILL.md"
    skill_path.write_bytes(b"x" * (MAX_SKILL_FILE_BYTES + 1))

    assert engine().scan(skill_path)[0].rule_id == "STO-LINT-007"


def test_rejects_non_utf8_skill_file(tmp_path: Path) -> None:
    skill_path = tmp_path / "SKILL.md"
    skill_path.write_bytes(b"\xff\xfe")

    assert engine().scan(skill_path)[0].rule_id == "STO-LINT-008"


@pytest.mark.parametrize(
    ("content", "expected_rule"),
    [
        ("# No metadata\n", "STO-LINT-010"),
        ("---\nname: example-skill\n", "STO-LINT-011"),
        ("---\nname: [broken\n---\nBody\n", "STO-LINT-012"),
        ("---\n- name\n- description\n---\nBody\n", "STO-LINT-013"),
    ],
)
def test_rejects_invalid_front_matter(
    tmp_path: Path, content: str, expected_rule: str
) -> None:
    assert scan(tmp_path, content) == {expected_rule}


def test_reports_all_metadata_and_body_problems(tmp_path: Path) -> None:
    content = "---\nname: Bad_Name\ndescription: short\n---\n"

    assert scan(tmp_path, content) == {
        "STO-LINT-015",
        "STO-LINT-016",
        "STO-LINT-017",
    }


def test_requires_name(tmp_path: Path) -> None:
    content = (
        "---\n"
        "description: This description is long enough to be useful.\n"
        "---\n"
        "Instructions.\n"
    )

    assert scan(tmp_path, content) == {"STO-LINT-014"}


def test_accepts_one_character_description(tmp_path: Path) -> None:
    content = "---\nname: example-skill\ndescription: x\n---\nInstructions.\n"

    assert scan(tmp_path, content) == set()


def test_rejects_name_over_64_characters(tmp_path: Path) -> None:
    name = "a" * (MAX_NAME_LENGTH + 1)
    content = valid_content(name)

    assert scan(tmp_path, content, directory_name=name) == {"STO-LINT-019"}


@pytest.mark.parametrize("name", ["Bad-Name", "-bad", "bad-", "bad--name", "bad_name"])
def test_rejects_invalid_name_formats(tmp_path: Path, name: str) -> None:
    content = valid_content(name)

    assert "STO-LINT-015" in scan(tmp_path, content, directory_name=name)


def test_rejects_description_over_1024_characters(tmp_path: Path) -> None:
    description = "x" * (MAX_DESCRIPTION_LENGTH + 1)
    content = (
        f"---\nname: example-skill\ndescription: {description}\n---\nInstructions.\n"
    )

    assert scan(tmp_path, content) == {"STO-LINT-020"}


def test_rejects_unknown_top_level_fields(tmp_path: Path) -> None:
    content = valid_content().replace(
        "---\n\n# Instructions",
        "owner: example\n---\n\n# Instructions",
    )

    assert scan(tmp_path, content) == {"STO-LINT-021"}


def test_accepts_specification_optional_fields(tmp_path: Path) -> None:
    content = (
        "---\n"
        "name: example-skill\n"
        "description: Reviews an example skill safely.\n"
        "license: Apache-2.0\n"
        "compatibility: Requires Python 3.12 or newer\n"
        "metadata:\n"
        "  author: example-org\n"
        '  version: "1.0"\n'
        "allowed-tools: Read Bash(git:*)\n"
        "---\n"
        "Instructions.\n"
    )

    assert scan(tmp_path, content) == set()


@pytest.mark.parametrize(
    ("field", "value", "expected_rule"),
    [
        ("license", "[]", "STO-LINT-022"),
        ("compatibility", "[]", "STO-LINT-023"),
        ("metadata", "[]", "STO-LINT-024"),
        ("allowed-tools", "[]", "STO-LINT-025"),
    ],
)
def test_rejects_invalid_optional_field_types(
    tmp_path: Path,
    field: str,
    value: str,
    expected_rule: str,
) -> None:
    content = valid_content().replace(
        "---\n\n# Instructions",
        f"{field}: {value}\n---\n\n# Instructions",
    )

    assert scan(tmp_path, content) == {expected_rule}


def test_rejects_compatibility_over_500_characters(tmp_path: Path) -> None:
    compatibility = "x" * (MAX_COMPATIBILITY_LENGTH + 1)
    content = valid_content().replace(
        "---\n\n# Instructions",
        f"compatibility: {compatibility}\n---\n\n# Instructions",
    )

    assert scan(tmp_path, content) == {"STO-LINT-023"}


def test_rejects_non_string_extension_metadata(tmp_path: Path) -> None:
    content = valid_content().replace(
        "---\n\n# Instructions",
        "metadata:\n  version: 1\n---\n\n# Instructions",
    )

    assert scan(tmp_path, content) == {"STO-LINT-024"}


def test_each_finding_has_evidence_and_remediation(tmp_path: Path) -> None:
    skill_path = tmp_path / "SKILL.md"

    finding = engine().scan(skill_path)[0]

    assert finding.evidence
    assert finding.remediation
