"""Minimal local dotenv loading without exposing values."""

from __future__ import annotations

import os
from pathlib import Path


def load_local_env(path: Path) -> None:
    """Load simple KEY=VALUE entries while preserving process environment values."""
    if not path.is_file() or path.is_symlink():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        normalized_key = key.strip()
        if normalized_key and normalized_key.replace("_", "").isalnum():
            os.environ.setdefault(normalized_key, value.strip().strip("'\""))


def load_discovered_env(start: Path) -> Path | None:
    """Load the nearest .env from the current directory or one of its parents."""
    current = start.resolve()
    if current.is_file():
        current = current.parent
    for directory in (current, *current.parents):
        candidate = directory / ".env"
        if candidate.is_file() and not candidate.is_symlink():
            load_local_env(candidate)
            return candidate
    return None
