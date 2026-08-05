import json
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from skilltrustops.redteam.loader import RedTeamPackageLoader
from skilltrustops.redteam.models import (
    AttackCase,
    AttackFamily,
    AttackTurn,
)
from skilltrustops.redteam.targets import GenericHTTPModelTarget


class _Response:
    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self) -> bytes:
        return BytesIO(
            json.dumps({"content": "refused", "tool_calls": []}).encode()
        ).read()


def test_generic_http_provider_contract() -> None:
    case = AttackCase(
        id="HTTP-1",
        title="Generic provider",
        family=AttackFamily.DIRECT_INJECTION,
        severity="high",
        objective="Test contract",
        turns=(AttackTurn(channel="user", content="test"),),
        owasp=(),
        mitre_atlas=(),
    )
    target = GenericHTTPModelTarget(
        "enterprise-model", "https://gateway.example.invalid/evaluate"
    )
    package_manifest = (
        RedTeamPackageLoader()
        .load(Path("examples/red-team-test/skilltrust-package.yaml"))
        .manifest
    )
    with patch("urllib.request.urlopen", return_value=_Response()) as request:
        response = target.respond(
            skill_content="test",
            manifest=package_manifest,
            case=case,
            turn_index=0,
        )
    assert response.content == "refused"
    assert target.choice.provider == "generic_http"
    assert request.called
