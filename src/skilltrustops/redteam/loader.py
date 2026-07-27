"""Safe loading for a single SKILL.md and declarative Phase 1 manifest."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError

from skilltrustops.redteam.models import PackageManifest

MAX_SKILL_BYTES = 512 * 1024
MAX_MANIFEST_BYTES = 512 * 1024


class RedTeamPackageError(ValueError):
    """Raised when an untrusted package cannot be safely loaded."""


@dataclass(frozen=True, slots=True)
class LoadedRedTeamPackage:
    root: Path
    skill_content: str
    manifest: PackageManifest
    skill_sha256: str
    manifest_sha256: str
    package_sha256: str


class RedTeamPackageLoader:
    def load(self, manifest_path: Path) -> LoadedRedTeamPackage:
        manifest_path = self._resolve_manifest_path(manifest_path.absolute())
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise RedTeamPackageError("Manifest must be a regular, non-symlink file")
        if manifest_path.suffix.lower() not in {".yaml", ".yml", ".json"}:
            raise RedTeamPackageError("Manifest must use YAML or JSON")
        raw_manifest = self._read(manifest_path, MAX_MANIFEST_BYTES, "manifest")
        try:
            data = (
                json.loads(raw_manifest)
                if manifest_path.suffix.lower() == ".json"
                else yaml.safe_load(raw_manifest)
            )
            manifest = PackageManifest.model_validate(data)
        except (json.JSONDecodeError, yaml.YAMLError, ValidationError) as error:
            raise RedTeamPackageError(f"Manifest validation failed: {error}") from error

        skill_path = manifest_path.parent / manifest.skill
        if skill_path.is_symlink() or not skill_path.is_file():
            raise RedTeamPackageError("Package must contain a regular SKILL.md file")
        if skill_path.parent != manifest_path.parent:
            raise RedTeamPackageError("SKILL.md must be next to the manifest")
        skill_content = self._read(skill_path, MAX_SKILL_BYTES, "SKILL.md")
        skill_digest = hashlib.sha256(skill_content.encode()).hexdigest()
        if (
            manifest.generation
            and manifest.generation.source_skill_sha256 != skill_digest
        ):
            raise RedTeamPackageError(
                "Generated manifest is stale because SKILL.md changed; regenerate it"
            )
        manifest_digest = hashlib.sha256(raw_manifest.encode()).hexdigest()
        package_digest = hashlib.sha256(
            f"{skill_digest}:{manifest_digest}".encode()
        ).hexdigest()
        return LoadedRedTeamPackage(
            root=manifest_path.parent,
            skill_content=skill_content,
            manifest=manifest,
            skill_sha256=skill_digest,
            manifest_sha256=manifest_digest,
            package_sha256=package_digest,
        )

    @staticmethod
    def _resolve_manifest_path(submitted_path: Path) -> Path:
        if submitted_path.name != "SKILL.md":
            return submitted_path
        if submitted_path.is_symlink() or not submitted_path.is_file():
            raise RedTeamPackageError("SKILL.md must be a regular, non-symlink file")
        candidates = [
            submitted_path.parent / "skilltrust-package.yaml",
            submitted_path.parent / "skilltrust-package.yml",
            submitted_path.parent / "skilltrust-package.json",
        ]
        manifests = [
            path for path in candidates if path.is_file() and not path.is_symlink()
        ]
        if not manifests:
            raise RedTeamPackageError(
                "No adjacent skilltrust-package.yaml, .yml, or .json was found "
                "for SKILL.md"
            )
        if len(manifests) > 1:
            raise RedTeamPackageError(
                "Multiple adjacent package manifests found; submit the intended "
                "manifest path"
            )
        return manifests[0]

    @staticmethod
    def _read(path: Path, maximum: int, label: str) -> str:
        try:
            size = path.stat().st_size
            if size > maximum:
                raise RedTeamPackageError(
                    f"{label} is {size} bytes; maximum is {maximum}"
                )
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            raise RedTeamPackageError(f"{label} must be UTF-8") from error
        except OSError as error:
            raise RedTeamPackageError(f"Could not read {label}: {error}") from error
