"""Safe generation of built-in policy profiles."""

import json
from enum import StrEnum
from pathlib import Path

import yaml

from skilltrustops.policies.models import ProfileName
from skilltrustops.policies.profiles import recommended_v1, recommended_v2


class PolicyFileFormat(StrEnum):
    """Supported policy serialization formats."""

    YAML = "yaml"
    JSON = "json"


class PolicyWriteError(ValueError):
    """Raised when a policy cannot be generated safely."""


class PolicyWriter:
    """Write a built-in profile without overwriting an existing policy."""

    def write(
        self,
        path: Path,
        output_format: PolicyFileFormat,
        profile: ProfileName = ProfileName.RECOMMENDED_V2,
    ) -> Path:
        """Generate a built-in profile at an explicit destination."""
        expected_suffixes = (
            {".yaml", ".yml"} if output_format is PolicyFileFormat.YAML else {".json"}
        )
        if path.suffix.lower() not in expected_suffixes:
            expected = (
                ".yaml or .yml" if output_format is PolicyFileFormat.YAML else ".json"
            )
            raise PolicyWriteError(
                f"{output_format.value} policy output must use {expected}."
            )

        policy = (
            recommended_v1()
            if profile is ProfileName.RECOMMENDED_V1
            else recommended_v2()
        )
        policy_data = policy.model_dump(mode="json", exclude_none=True)
        if output_format is PolicyFileFormat.JSON:
            rendered = json.dumps(policy_data, indent=2) + "\n"
        else:
            rendered = yaml.safe_dump(policy_data, sort_keys=False)

        try:
            with path.open("x", encoding="utf-8") as policy_file:
                policy_file.write(rendered)
        except FileExistsError as error:
            raise PolicyWriteError(
                f"Policy already exists and was not overwritten: {path}"
            ) from error
        except OSError as error:
            raise PolicyWriteError(f"Policy could not be written: {error}") from error

        return path
