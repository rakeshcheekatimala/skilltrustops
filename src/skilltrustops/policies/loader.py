"""Safe YAML/JSON policy loading and repository-root discovery."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError

from skilltrustops.domain.reports import PolicyReference
from skilltrustops.policies.models import SkillTrustPolicy
from skilltrustops.policies.profiles import recommended_v1

POLICY_FILENAMES = (
    "skilltrustops.yaml",
    "skilltrustops.yml",
    "skilltrustops.json",
)
MAX_POLICY_BYTES = 256 * 1024


class PolicyError(ValueError):
    """Raised when a policy cannot be selected, loaded, or validated."""


@dataclass(frozen=True, slots=True)
class LoadedPolicy:
    """An effective policy and the provenance recorded in reports."""

    policy: SkillTrustPolicy
    reference: PolicyReference


class PolicyLoader:
    """Resolve one trusted repository policy or the built-in profile."""

    def load(
        self,
        policy_path: Path | None,
        search_start: Path,
    ) -> LoadedPolicy:
        """Load an explicit policy, discover a repository policy, or use defaults."""
        selected_path = policy_path or self._discover(search_start)
        if selected_path is None:
            policy = recommended_v1()
            return LoadedPolicy(
                policy=policy,
                reference=self._reference(policy, "builtin:recommended-v1"),
            )

        policy = self._load_file(selected_path)
        return LoadedPolicy(
            policy=policy,
            reference=self._reference(policy, str(selected_path.absolute())),
        )

    def _discover(self, search_start: Path) -> Path | None:
        root = self._repository_root(search_start)
        candidates = [
            root / name
            for name in POLICY_FILENAMES
            if (root / name).exists() or (root / name).is_symlink()
        ]
        if len(candidates) > 1:
            rendered = ", ".join(path.name for path in candidates)
            raise PolicyError(
                f"Multiple repository policies found: {rendered}. "
                "Keep one policy file or pass --policy explicitly."
            )
        return candidates[0] if candidates else None

    @staticmethod
    def _repository_root(search_start: Path) -> Path:
        start = search_start.absolute()
        if start.is_file():
            start = start.parent

        for candidate in (start, *start.parents):
            if (candidate / ".git").exists():
                return candidate
        return start

    def _load_file(self, path: Path) -> SkillTrustPolicy:
        if path.is_symlink():
            raise PolicyError(f"Policy must not be a symbolic link: {path}")
        if not path.exists():
            raise PolicyError(f"Policy file does not exist: {path}")
        if not path.is_file():
            raise PolicyError(f"Policy path is not a regular file: {path}")
        if path.suffix.lower() not in {".yaml", ".yml", ".json"}:
            raise PolicyError("Policy must use a .yaml, .yml, or .json extension.")

        try:
            size = path.stat().st_size
            if size > MAX_POLICY_BYTES:
                raise PolicyError(
                    f"Policy is {size} bytes; maximum is {MAX_POLICY_BYTES} bytes."
                )
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            raise PolicyError(
                f"Policy is not valid UTF-8 at byte {error.start}: {path}"
            ) from error
        except OSError as error:
            raise PolicyError(f"Policy could not be read: {error}") from error

        data = self._parse(content, path)
        try:
            return SkillTrustPolicy.model_validate(data)
        except ValidationError as error:
            raise PolicyError(f"Policy validation failed:\n{error}") from error

    @staticmethod
    def _parse(content: str, path: Path) -> object:
        try:
            if path.suffix.lower() == ".json":
                return json.loads(content)
            return yaml.safe_load(content)
        except (json.JSONDecodeError, yaml.YAMLError) as error:
            raise PolicyError(f"Policy syntax is invalid: {error}") from error

    @staticmethod
    def _reference(policy: SkillTrustPolicy, source: str) -> PolicyReference:
        canonical = json.dumps(
            policy.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return PolicyReference(
            profile=policy.profile,
            source=source,
            sha256=hashlib.sha256(canonical).hexdigest(),
        )
