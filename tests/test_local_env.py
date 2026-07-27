import os
from pathlib import Path

from pytest import MonkeyPatch

from skilltrustops.services.local_env import load_discovered_env, load_local_env


def test_load_local_env_preserves_existing_values(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "EXISTING_VALUE=file\nNEW_LOCAL_VALUE=loaded\n", encoding="utf-8"
    )
    monkeypatch.setenv("EXISTING_VALUE", "process")
    monkeypatch.delenv("NEW_LOCAL_VALUE", raising=False)

    load_local_env(env_file)

    assert os.environ["EXISTING_VALUE"] == "process"
    assert os.environ["NEW_LOCAL_VALUE"] == "loaded"


def test_load_discovered_env_searches_parent_directories(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    nested = tmp_path / "examples" / "skill"
    nested.mkdir(parents=True)
    (tmp_path / ".env").write_text("DISCOVERED_VALUE=yes\n", encoding="utf-8")
    monkeypatch.delenv("DISCOVERED_VALUE", raising=False)

    discovered = load_discovered_env(nested)

    assert discovered == tmp_path / ".env"
    assert os.environ["DISCOVERED_VALUE"] == "yes"
