import pytest
from fastapi import HTTPException

from backend.main import demo, redteam_config, redteam_demo, scan_content
from backend.models import ScanContentRequest
from skilltrustops.redteam.models import AssessmentDecision


def test_demo_returns_explainable_decision() -> None:
    report = demo()
    assert report.schema_version == "1.2"
    assert report.decision.verdict in {"blocked", "needs_remediation"}
    assert report.skill.sha256
    assert report.checks
    assert sum(report.summary.model_dump().values()) >= len(report.findings)


def test_browser_selected_skill_content_can_be_scanned() -> None:
    report = scan_content(
        ScanContentRequest(
            filename="SKILL.md",
            content="---\nname: demo\ndescription: demo skill\n---\n# Demo\n",
        )
    )
    assert report.skill.path == "SKILL.md"


def test_browser_selected_file_must_be_skill_md() -> None:
    with pytest.raises(HTTPException) as error:
        scan_content(ScanContentRequest(filename="notes.md", content="hello"))
    assert error.value.status_code == 400


def test_redteam_demo_explains_assured_and_blocked_paths() -> None:
    assured = redteam_demo("resistant-demo")
    blocked = redteam_demo("vulnerable-demo")

    assert assured.decision is AssessmentDecision.ASSURED
    assert blocked.decision is AssessmentDecision.BLOCKED
    assert blocked.summary.attack_succeeded > 0
    assert blocked.evidence is not None


def test_redteam_config_does_not_expose_api_key() -> None:
    status = redteam_config()

    assert isinstance(status.openai_configured, bool)
    assert status.openai_default_model
    assert "resistant-demo" in status.reference_models
    assert "api_key" not in status.model_dump()
