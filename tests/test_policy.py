import json
from pathlib import Path

import pytest

from skilltrustops.policies.loader import PolicyError, PolicyLoader
from skilltrustops.policies.profiles import recommended_v2


def policy_data(*, lint_enabled: bool = True) -> dict[str, object]:
    return {
        "version": 1,
        "profile": "recommended-v1",
        "checks": {
            "lint": {
                "enabled": lint_enabled,
                "ruleset": "agent-skills-specification",
            }
        },
    }


def v2_policy_data() -> dict[str, object]:
    return recommended_v2().model_dump(mode="json")


def test_uses_builtin_profile_when_repository_has_no_policy(tmp_path: Path) -> None:
    loaded = PolicyLoader().load(None, tmp_path)

    assert loaded.policy.profile == "recommended-v2"
    assert loaded.policy.checks.lint.enabled is True
    assert loaded.policy.checks.security is not None
    assert loaded.policy.checks.privacy is not None
    assert loaded.reference.source == "builtin:recommended-v2"
    assert len(loaded.reference.sha256) == 64


def test_discovers_policy_only_at_repository_root(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    nested = tmp_path / "nested"
    nested.mkdir()
    policy_path = tmp_path / "skilltrustops.yaml"
    policy_path.write_text(
        "version: 1\n"
        "profile: recommended-v1\n"
        "checks:\n"
        "  lint:\n"
        "    enabled: true\n"
        "    ruleset: agent-skills-specification\n",
        encoding="utf-8",
    )

    loaded = PolicyLoader().load(None, nested)

    assert loaded.reference.source == str(policy_path.absolute())


def test_yaml_and_json_produce_same_effective_policy_hash(tmp_path: Path) -> None:
    yaml_path = tmp_path / "policy.yaml"
    yaml_path.write_text(
        "version: 1\n"
        "profile: recommended-v1\n"
        "checks:\n"
        "  lint:\n"
        "    enabled: true\n"
        "    ruleset: agent-skills-specification\n",
        encoding="utf-8",
    )
    json_path = tmp_path / "policy.json"
    json_path.write_text(json.dumps(policy_data()), encoding="utf-8")

    yaml_policy = PolicyLoader().load(yaml_path, tmp_path)
    json_policy = PolicyLoader().load(json_path, tmp_path)

    assert yaml_policy.policy == json_policy.policy
    assert yaml_policy.reference.sha256 == json_policy.reference.sha256


def test_rejects_unimplemented_future_checks(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        "version: 1\n"
        "profile: recommended-v1\n"
        "checks:\n"
        "  lint:\n"
        "    enabled: true\n"
        "    ruleset: agent-skills-specification\n"
        "  review:\n"
        "    enabled: true\n",
        encoding="utf-8",
    )

    with pytest.raises(PolicyError, match="review"):
        PolicyLoader().load(path, tmp_path)


def test_recommended_v2_requires_security_and_privacy(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        "version: 1\n"
        "profile: recommended-v2\n"
        "checks:\n"
        "  lint:\n"
        "    enabled: true\n"
        "    ruleset: agent-skills-specification\n",
        encoding="utf-8",
    )

    with pytest.raises(PolicyError, match="requires both security and privacy"):
        PolicyLoader().load(path, tmp_path)


def test_recommended_v1_rejects_static_checks(tmp_path: Path) -> None:
    data = recommended_v2().model_dump(mode="json")
    data["profile"] = "recommended-v1"
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(PolicyError, match="recommended-v1 supports only lint"):
        PolicyLoader().load(path, tmp_path)


def test_rejects_ambiguous_repository_policies(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "skilltrustops.yaml").write_text("{}", encoding="utf-8")
    (tmp_path / "skilltrustops.json").write_text("{}", encoding="utf-8")

    with pytest.raises(PolicyError, match="Multiple repository policies"):
        PolicyLoader().load(None, tmp_path)


def test_rejects_symlinked_policy(tmp_path: Path) -> None:
    target = tmp_path / "target.yaml"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "policy.yaml"
    link.symlink_to(target)

    with pytest.raises(PolicyError, match="symbolic link"):
        PolicyLoader().load(link, tmp_path)


def test_discovery_does_not_ignore_broken_policy_symlink(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "skilltrustops.yaml").symlink_to(tmp_path / "missing.yaml")

    with pytest.raises(PolicyError, match="symbolic link"):
        PolicyLoader().load(None, tmp_path)


def test_policy_hash_includes_enabled_gitleaks_config(tmp_path: Path) -> None:
    config_dir = tmp_path / ".skilltrustops"
    config_dir.mkdir()
    config_path = config_dir / "gitleaks.toml"
    config_path.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
    data = v2_policy_data()
    checks = data["checks"]
    assert isinstance(checks, dict)
    security = checks["security"]
    assert isinstance(security, dict)
    secrets = security["secrets"]
    assert isinstance(secrets, dict)
    secrets["scanners"] = [
        {
            "engine": "gitleaks",
            "enabled": True,
            "timeout_seconds": 30,
            "config": ".skilltrustops/gitleaks.toml",
        }
    ]
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(data), encoding="utf-8")

    first_hash = PolicyLoader().load(policy_path, tmp_path).reference.sha256
    config_path.write_text(
        "[extend]\nuseDefault = true\n# changed\n",
        encoding="utf-8",
    )
    second_hash = PolicyLoader().load(policy_path, tmp_path).reference.sha256

    assert first_hash != second_hash


def test_rejects_gitleaks_config_outside_policy_directory(tmp_path: Path) -> None:
    outside_path = tmp_path.parent / "outside-gitleaks.toml"
    outside_path.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
    data = v2_policy_data()
    checks = data["checks"]
    assert isinstance(checks, dict)
    security = checks["security"]
    assert isinstance(security, dict)
    secrets = security["secrets"]
    assert isinstance(secrets, dict)
    secrets["scanners"] = [
        {
            "engine": "gitleaks",
            "enabled": True,
            "config": "../outside-gitleaks.toml",
        }
    ]
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(PolicyError, match="escapes the policy directory"):
        PolicyLoader().load(policy_path, tmp_path)


def test_rejects_duplicate_secret_scanner_engines(tmp_path: Path) -> None:
    data = v2_policy_data()
    checks = data["checks"]
    assert isinstance(checks, dict)
    security = checks["security"]
    assert isinstance(security, dict)
    secrets = security["secrets"]
    assert isinstance(secrets, dict)
    secrets["scanners"] = [
        {"engine": "builtin", "enabled": True},
        {"engine": "builtin", "enabled": True},
    ]
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(PolicyError, match="duplicate engines"):
        PolicyLoader().load(policy_path, tmp_path)


def test_rejects_secret_scanning_without_enabled_scanner(tmp_path: Path) -> None:
    data = v2_policy_data()
    checks = data["checks"]
    assert isinstance(checks, dict)
    security = checks["security"]
    assert isinstance(security, dict)
    secrets = security["secrets"]
    assert isinstance(secrets, dict)
    secrets["scanners"] = [{"engine": "builtin", "enabled": False}]
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(PolicyError, match="at least one enabled scanner"):
        PolicyLoader().load(policy_path, tmp_path)
