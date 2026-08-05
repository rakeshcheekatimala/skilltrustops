"""Public Python API for deterministic SkillTrustOps scans."""

from pathlib import Path

from skilltrustops.domain.reports import BatchScanReport
from skilltrustops.policies.loader import PolicyLoader
from skilltrustops.services.batch import BatchScanService


def scan(
    target: str | Path,
    *,
    policy_path: str | Path | None = None,
) -> BatchScanReport:
    """Scan one SKILL.md or every skill below a folder with one policy."""
    selected_target = Path(target)
    selected_policy = Path(policy_path) if policy_path is not None else None
    loaded = PolicyLoader().load(selected_policy, selected_target)
    return BatchScanService().run(selected_target, loaded)
