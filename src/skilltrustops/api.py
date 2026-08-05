"""Public Python API for deterministic SkillTrustOps scans."""

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from skilltrustops import __version__
from skilltrustops.domain.reports import BatchScanReport
from skilltrustops.policies.loader import PolicyLoader
from skilltrustops.services.batch import BatchScanService

logger = logging.getLogger("skilltrustops")


def scan(
    target: str | Path,
    *,
    policy_path: str | Path | None = None,
    include_timing: bool = False,
    security: bool = True,
    privacy: bool = True,
) -> BatchScanReport:
    """Scan one SKILL.md or every skill below a folder with one policy."""
    selected_target = Path(target)
    selected_policy = Path(policy_path) if policy_path is not None else None
    with _scan_span(selected_target, selected_policy) as span:
        loaded = PolicyLoader().load(selected_policy, selected_target)
        report = BatchScanService().run(
            selected_target,
            loaded,
            include_timing=include_timing,
            run_security=security,
            run_privacy=privacy,
        )
        attributes = {
            "skilltrustops.ruleset_version": report.ruleset_version,
            "skilltrustops.skills.discovered": report.summary.discovered,
            "skilltrustops.skills.passed": report.summary.passed,
            "skilltrustops.skills.failed": report.summary.failed,
            "skilltrustops.skills.errors": report.summary.errors,
        }
        if span is not None:
            for key, value in attributes.items():
                span.set_attribute(key, value)
        logger.info("scan.complete", extra={"skilltrustops": attributes})
        return report


@contextmanager
def _scan_span(target: Path, policy_path: Path | None) -> Iterator[Any | None]:
    """Create an OpenTelemetry span when the optional API is installed."""
    try:
        from opentelemetry import trace  # type: ignore[import-not-found]
    except ImportError:
        yield None
        return

    tracer = trace.get_tracer("skilltrustops", __version__)
    with tracer.start_as_current_span("skilltrustops.scan") as span:
        span.set_attribute("skilltrustops.target", str(target))
        span.set_attribute(
            "skilltrustops.policy_source",
            str(policy_path) if policy_path is not None else "discovered",
        )
        yield span
