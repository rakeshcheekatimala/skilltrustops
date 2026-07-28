"""Sandbox provider boundary."""

from pathlib import Path
from typing import Protocol

from skilltrustops.sandbox.models import SandboxReport


class SandboxProvider(Protocol):
    def run(self, package_root: Path) -> SandboxReport:
        """Run isolation probes and return only after the sandbox exits."""
        ...
