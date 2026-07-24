import json
from pathlib import Path

import pytest

from skilltrustops.policies.loader import PolicyError, PolicyLoader


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


def test_uses_builtin_profile_when_repository_has_no_policy(tmp_path: Path) -> None:
    loaded = PolicyLoader().load(None, tmp_path)

    assert loaded.policy.profile == "recommended-v1"
    assert loaded.policy.checks.lint.enabled is True
    assert loaded.reference.source == "builtin:recommended-v1"
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
        "  privacy:\n"
        "    enabled: true\n",
        encoding="utf-8",
    )

    with pytest.raises(PolicyError, match="privacy"):
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
