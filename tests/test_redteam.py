import json
from pathlib import Path

import pytest

from skilltrustops.redteam.generator import RedTeamManifestGenerator
from skilltrustops.redteam.loader import RedTeamPackageError, RedTeamPackageLoader
from skilltrustops.redteam.models import AssessmentDecision
from skilltrustops.redteam.service import RedTeamService
from skilltrustops.redteam.targets import ReferenceModelTarget

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples/redteam-support/skilltrust-package.yaml"
CANARY_SKILL = ROOT / "examples/red-team-canary/SKILL.md"


def test_phase_one_manifest_loads_one_skill_and_tools() -> None:
    package = RedTeamPackageLoader().load(MANIFEST)

    assert package.manifest.name == "redteam-support"
    assert package.manifest.skill == "SKILL.md"
    assert {tool.name for tool in package.manifest.tools} == {
        "search_customer",
        "send_email",
    }
    assert len(package.package_sha256) == 64


def test_skill_path_discovers_its_adjacent_manifest() -> None:
    package = RedTeamPackageLoader().load(MANIFEST.parent / "SKILL.md")

    assert package.manifest.name == "redteam-support"


def test_generator_creates_hash_bound_review_required_draft(tmp_path: Path) -> None:
    skill = tmp_path / "SKILL.md"
    skill.write_text(CANARY_SKILL.read_text(encoding="utf-8"), encoding="utf-8")

    result = RedTeamManifestGenerator().write(skill, strategy="deterministic")
    package = RedTeamPackageLoader().load(skill)

    assert Path(result.manifest_path).is_file()
    assert package.manifest.generation is not None
    assert package.manifest.generation.requires_review is True
    assert "sensitive_data" in package.manifest.capabilities


def test_resistant_reference_model_produces_assured_evidence(tmp_path: Path) -> None:
    report = RedTeamService(tmp_path).run(
        MANIFEST, ReferenceModelTarget("resistant-demo")
    )

    assert report.decision is AssessmentDecision.ASSURED
    assert report.summary.attack_succeeded == 0
    assert report.summary.resisted == report.summary.planned
    assert report.evidence is not None
    evidence_manifest = json.loads(
        Path(report.evidence.manifest).read_text(encoding="utf-8")
    )
    assert evidence_manifest["package_sha256"] == report.package_sha256
    assert Path(report.evidence.inspect_log).read_text(encoding="utf-8")


def test_vulnerable_reference_model_is_blocked_with_tool_evidence(
    tmp_path: Path,
) -> None:
    report = RedTeamService(tmp_path).run(
        MANIFEST, ReferenceModelTarget("vulnerable-demo")
    )

    assert report.decision is AssessmentDecision.BLOCKED
    assert report.summary.attack_succeeded > 0
    confirmation = next(
        attempt
        for attempt in report.attempts
        if attempt.case.id == "STO-RT-CONFIRM-001"
    )
    assert any(event.type == "tool_call_attempted" for event in confirmation.trace)
    assert any(
        event.type == "tool_call_blocked"
        and event.detail["reason"] == "missing_confirmation"
        for event in confirmation.trace
    )


def test_manifest_cannot_point_outside_package(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        "schema_version: '1.0'\n"
        "name: test-package\n"
        "version: '1'\n"
        "skill: ../SKILL.md\n"
        "description: test\n"
        "capabilities: []\n"
        "synthetic_fixture:\n"
        "  current_user_id: user\n",
        encoding="utf-8",
    )

    with pytest.raises(RedTeamPackageError):
        RedTeamPackageLoader().load(manifest)
