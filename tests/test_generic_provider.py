import json
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import pytest

from skilltrustops.redteam.loader import RedTeamPackageLoader
from skilltrustops.redteam.models import (
    AttackCase,
    AttackFamily,
    AttackTurn,
)
from skilltrustops.redteam.targets import (
    GenericHTTPModelTarget,
    ProviderHTTPError,
    ProviderResponseError,
    ProviderTimeoutError,
)


class _Response:
    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self) -> bytes:
        return BytesIO(
            json.dumps({"content": "refused", "tool_calls": []}).encode()
        ).read()


class _MalformedResponse(_Response):
    def read(self) -> bytes:
        return b"not-json"


def _target_and_request() -> tuple[GenericHTTPModelTarget, dict[str, object]]:
    case = AttackCase(
        id="HTTP-FAILURE",
        title="Generic provider failure",
        family=AttackFamily.DIRECT_INJECTION,
        severity="high",
        objective="Test failure contract",
        turns=(AttackTurn(channel="user", content="test"),),
        owasp=(),
        mitre_atlas=(),
    )
    manifest = (
        RedTeamPackageLoader()
        .load(Path("examples/red-team-test/skilltrust-package.yaml"))
        .manifest
    )
    target = GenericHTTPModelTarget(
        "enterprise-model", "https://gateway.example.invalid/evaluate"
    )
    request = {
        "skill_content": "test",
        "manifest": manifest,
        "case": case,
        "turn_index": 0,
    }
    return target, request


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


def test_generic_provider_rejects_malformed_payload() -> None:
    target, request = _target_and_request()

    with (
        patch("urllib.request.urlopen", return_value=_MalformedResponse()),
        pytest.raises(ProviderResponseError) as caught,
    ):
        target.respond(**request)  # type: ignore[arg-type]

    assert caught.value.code == "provider_invalid_response"
    assert caught.value.retryable is False
    assert caught.value.__cause__ is not None


@pytest.mark.parametrize(
    "failure",
    [TimeoutError("slow provider"), URLError(TimeoutError("socket timeout"))],
)
def test_generic_provider_exposes_retryable_timeout(failure: Exception) -> None:
    target, request = _target_and_request()

    with (
        patch("urllib.request.urlopen", side_effect=failure),
        pytest.raises(ProviderTimeoutError) as caught,
    ):
        target.respond(**request)  # type: ignore[arg-type]

    assert caught.value.code == "provider_timeout"
    assert caught.value.retryable is True
    assert "backoff" in caught.value.recovery_hint


def test_generic_provider_exposes_http_status_and_retryability() -> None:
    target, request = _target_and_request()
    failure = HTTPError(
        "https://gateway.example.invalid/evaluate",
        503,
        "unavailable",
        {},
        BytesIO(b"try later"),
    )

    with (
        patch("urllib.request.urlopen", side_effect=failure),
        pytest.raises(ProviderHTTPError) as caught,
    ):
        target.respond(**request)  # type: ignore[arg-type]

    assert caught.value.status_code == 503
    assert caught.value.retryable is True
