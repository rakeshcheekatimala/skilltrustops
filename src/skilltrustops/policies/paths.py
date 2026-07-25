"""Resolution of trusted files referenced by repository policy."""

from pathlib import Path

MAX_REFERENCED_POLICY_FILE_BYTES = 1024 * 1024


class TrustedPolicyPathError(ValueError):
    """A policy-referenced file is unsafe or unavailable."""


def resolve_trusted_policy_file(base_dir: Path, configured_path: Path) -> Path:
    """Resolve a regular file without allowing absolute paths or symlink escapes."""
    if configured_path.is_absolute():
        raise TrustedPolicyPathError(
            f"Policy-referenced path must be relative: {configured_path}"
        )

    base = base_dir.resolve(strict=True)
    candidate = base
    for component in configured_path.parts:
        candidate /= component
        if candidate.is_symlink():
            raise TrustedPolicyPathError(
                f"Policy-referenced path must not contain symlinks: {configured_path}"
            )

    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise TrustedPolicyPathError(
            f"Policy-referenced file does not exist: {configured_path}"
        ) from error

    if not resolved.is_relative_to(base):
        raise TrustedPolicyPathError(
            f"Policy-referenced path escapes the policy directory: {configured_path}"
        )
    if not resolved.is_file():
        raise TrustedPolicyPathError(
            f"Policy-referenced path is not a regular file: {configured_path}"
        )
    if resolved.stat().st_size > MAX_REFERENCED_POLICY_FILE_BYTES:
        raise TrustedPolicyPathError(
            "Policy-referenced file exceeds the 1 MiB safety limit: "
            f"{configured_path}"
        )
    return resolved
