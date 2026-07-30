"""Docker and gVisor-backed isolation verification providers."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable, Sequence
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from skilltrustops.sandbox.models import SandboxCheck, SandboxReport

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]

PROBE_SCRIPT = """
set -eu
test -r /input/SKILL.md
test ! -e /var/run/docker.sock
test "$(id -u)" != "0"
if touch /input/.skilltrust-write-probe 2>/dev/null; then
  rm -f /input/.skilltrust-write-probe
  exit 21
fi
sha256sum /input/SKILL.md >/tmp/skill.sha256
test -s /tmp/skill.sha256
""".strip()


class DockerSandboxProvider:
    """Run trusted isolation probes without executing submitted package code."""

    def __init__(
        self,
        *,
        runtime: str = "runc",
        image: str = "alpine:3.20",
        runner: CommandRunner = subprocess.run,
    ) -> None:
        self.runtime = runtime
        self.image = image
        self.runner = runner

    @property
    def provider_name(self) -> str:
        return "gvisor" if self.runtime == "runsc" else "docker"

    def run(self, package_root: Path) -> SandboxReport:
        started = datetime.now(UTC).isoformat()
        certifying = self.runtime == "runsc" and "@sha256:" in self.image
        if shutil.which("docker") is None:
            return self._unavailable(started, "Docker CLI is not installed.")

        availability = self._execute(("docker", "info", "--format", "{{.ID}}"), 10)
        if availability.returncode != 0:
            return self._unavailable(
                started,
                "Docker is installed, but its daemon is not running or accessible.",
            )

        container_name = f"skilltrust-{uuid4().hex[:12]}"
        command = self._docker_command(package_root, container_name)
        completed = self._execute(command, 90, cleanup_container=container_name)
        exited = datetime.now(UTC).isoformat()
        passed = completed.returncode == 0
        checks = (
            SandboxCheck(
                id="STO-SBX-001",
                title="Sandbox process exited",
                passed=passed,
                explanation=(
                    "The trusted isolation probes completed successfully."
                    if passed
                    else "The sandbox exited with an error before all probes passed."
                ),
            ),
            SandboxCheck(
                id="STO-SBX-002",
                title="Submitted package mounted read-only",
                passed=passed,
                explanation=(
                    "The sandbox could read SKILL.md but could not modify the package."
                    if passed
                    else "Read-only package access was not proven."
                ),
            ),
            SandboxCheck(
                id="STO-SBX-003",
                title="External network disabled",
                passed=passed,
                explanation=(
                    "The container was started with Docker network mode 'none'."
                    if passed
                    else "Network isolation was not proven because the run failed."
                ),
            ),
            SandboxCheck(
                id="STO-SBX-004",
                title="Privileges restricted",
                passed=passed,
                explanation=(
                    "The process ran as a non-root user with all capabilities dropped."
                    if passed
                    else "Privilege restrictions were not proven."
                ),
            ),
            SandboxCheck(
                id="STO-SBX-005",
                title="Runtime suitable for assurance",
                passed=certifying,
                explanation=(
                    "The run used gVisor with a digest-pinned image."
                    if certifying
                    else "Docker development isolation is not a certifying boundary."
                ),
            ),
        )
        return SandboxReport(
            provider=self.provider_name,  # type: ignore[arg-type]
            status="passed" if passed else "failed",
            certifying=certifying,
            runtime=self.runtime,
            image=self.image,
            container_name=container_name,
            started_at=started,
            exited_at=exited,
            exit_code=completed.returncode,
            checks=checks,
            explanation=(
                "The sandbox exited and all executable isolation probes passed."
                if passed
                else "The sandbox exited, but one or more isolation probes failed."
            ),
        )

    def _docker_command(
        self, package_root: Path, container_name: str
    ) -> tuple[str, ...]:
        command = [
            "docker",
            "run",
            "--rm",
            "--name",
            container_name,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "64",
            "--memory",
            "256m",
            "--cpus",
            "1",
            "--user",
            "65532:65532",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=16m",
            "--mount",
            f"type=bind,src={package_root.absolute()},dst=/input,readonly",
        ]
        if self.runtime == "runsc":
            command.extend(("--runtime", "runsc"))
        command.extend((self.image, "sh", "-c", PROBE_SCRIPT))
        return tuple(command)

    def _execute(
        self,
        command: Sequence[str],
        timeout: int,
        *,
        cleanup_container: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return self.runner(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            if cleanup_container is not None:
                with suppress(OSError, subprocess.TimeoutExpired):
                    self.runner(
                        ("docker", "rm", "-f", cleanup_container),
                        capture_output=True,
                        text=True,
                        timeout=15,
                        check=False,
                    )
            return subprocess.CompletedProcess(command, 124, "", str(error))
        except OSError as error:
            return subprocess.CompletedProcess(command, 124, "", str(error))

    def _unavailable(self, started: str, explanation: str) -> SandboxReport:
        return SandboxReport(
            provider=self.provider_name,  # type: ignore[arg-type]
            status="unavailable",
            certifying=False,
            runtime=self.runtime,
            image=self.image,
            started_at=started,
            exited_at=datetime.now(UTC).isoformat(),
            explanation=explanation,
            checks=(
                SandboxCheck(
                    id="STO-SBX-000",
                    title="Sandbox runtime available",
                    passed=False,
                    explanation=explanation,
                ),
            ),
        )
