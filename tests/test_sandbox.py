from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from skilltrustops.sandbox.providers import DockerSandboxProvider


def _package(tmp_path: Path) -> Path:
    (tmp_path / "SKILL.md").write_text("# Safe fixture\n", encoding="utf-8")
    return tmp_path


def test_docker_provider_applies_all_isolation_controls(
    tmp_path: Path, monkeypatch: Any
) -> None:
    calls: list[tuple[str, ...]] = []

    def runner(command: tuple[str, ...], **_: Any) -> subprocess.CompletedProcess[str]:
        calls.append(tuple(command))
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/docker")
    report = DockerSandboxProvider(runner=runner).run(_package(tmp_path))

    assert report.status == "passed"
    assert report.certifying is False
    run = calls[1]
    assert run[run.index("--network") :][:2] == ("--network", "none")
    assert "--read-only" in run
    assert run[run.index("--cap-drop") :][:2] == ("--cap-drop", "ALL")
    assert "no-new-privileges:true" in run
    assert run[run.index("--user") :][:2] == ("--user", "65532:65532")
    assert all(check.passed for check in report.checks[:4])


def test_gvisor_requires_runsc_and_digest_pinned_image(
    tmp_path: Path, monkeypatch: Any
) -> None:
    calls: list[tuple[str, ...]] = []

    def runner(command: tuple[str, ...], **_: Any) -> subprocess.CompletedProcess[str]:
        calls.append(tuple(command))
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/docker")
    image = "alpine@sha256:" + "a" * 64
    report = DockerSandboxProvider(
        runtime="runsc", image=image, runner=runner
    ).run(_package(tmp_path))

    assert report.provider == "gvisor"
    assert report.certifying is True
    assert calls[1][calls[1].index("--runtime") :][:2] == ("--runtime", "runsc")


def test_timeout_forcibly_cleans_up_container(
    tmp_path: Path, monkeypatch: Any
) -> None:
    calls: list[tuple[str, ...]] = []

    def runner(command: tuple[str, ...], **_: Any) -> subprocess.CompletedProcess[str]:
        calls.append(tuple(command))
        if len(calls) == 2:
            raise subprocess.TimeoutExpired(command, 90)
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/docker")
    report = DockerSandboxProvider(runner=runner).run(_package(tmp_path))

    assert report.status == "failed"
    assert report.exit_code == 124
    assert calls[2][:3] == ("docker", "rm", "-f")


def test_unavailable_daemon_is_fail_closed(tmp_path: Path, monkeypatch: Any) -> None:
    def runner(command: tuple[str, ...], **_: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 1, "", "daemon unavailable")

    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/docker")
    report = DockerSandboxProvider(runner=runner).run(_package(tmp_path))

    assert report.status == "unavailable"
    assert report.certifying is False
    assert report.checks[0].passed is False
