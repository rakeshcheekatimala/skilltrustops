"""Strict sandbox lifecycle and evidence contracts."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class SandboxCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    title: str
    passed: bool
    explanation: str


class SandboxReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: Literal["none", "docker", "gvisor"]
    status: Literal["not_requested", "passed", "failed", "unavailable"]
    certifying: bool
    runtime: str
    image: str | None = None
    timeout_seconds: int | None = None
    pids_limit: int | None = None
    memory: str | None = None
    cpus: float | None = None
    user_id: int | None = None
    group_id: int | None = None
    tmpfs_size_mb: int | None = None
    container_name: str | None = None
    started_at: str | None = None
    exited_at: str | None = None
    exit_code: int | None = None
    checks: tuple[SandboxCheck, ...] = ()
    explanation: str


def no_sandbox_report() -> SandboxReport:
    return SandboxReport(
        provider="none",
        status="not_requested",
        certifying=False,
        runtime="none",
        explanation=(
            "No code sandbox was requested. Behavioral tests still use in-memory "
            "fake tools and never execute submitted package code."
        ),
    )
