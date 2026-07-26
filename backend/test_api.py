import pytest
from fastapi import HTTPException

from backend.main import demo, scan_content
from backend.models import ScanContentRequest


def test_demo_returns_explainable_decision() -> None:
    report = demo()
    assert report.schema_version == "1.2"
    assert report.decision.verdict in {"blocked", "needs_remediation"}
    assert report.skill.sha256
    assert report.checks


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
