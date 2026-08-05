"""Run repeatable batch scans and record container limits plus raw skill results."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import platform
import resource
import statistics
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

from skilltrustops import __version__, scan


def read_cgroup(name: str) -> str | None:
    path = Path("/sys/fs/cgroup") / name
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    index = round((len(ordered) - 1) * quantile)
    return round(ordered[index], 3)


def corpus_identity(corpus: Path) -> dict[str, object]:
    entries = []
    for path in sorted(corpus.rglob("SKILL.md")):
        if path.is_symlink() or not path.is_file():
            continue
        content = path.read_bytes()
        relative = path.relative_to(corpus).as_posix()
        parts = Path(relative).parts
        entries.append(
            {
                "path": relative,
                "repository": "/".join(parts[:2]) if len(parts) >= 2 else "unknown",
                "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return {
        "skills": len(entries),
        "entries_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--corpus", type=Path, default=Path("/corpus"))
    parser.add_argument("--policy", type=Path, default=Path("/policy.yaml"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")

    reports: list[dict[str, object]] = []
    wall_times: list[float] = []
    skill_times: list[float] = []
    for run_number in range(1, args.runs + 1):
        started = perf_counter()
        report = scan(args.corpus, policy_path=args.policy)
        measured_ms = round((perf_counter() - started) * 1000, 3)
        wall_times.append(measured_ms)
        skill_times.extend(skill.duration_ms for skill in report.skills)
        reports.append(
            {
                "run": run_number,
                "wall_duration_ms": measured_ms,
                "report": report.model_dump(mode="json"),
            }
        )

    median_wall = statistics.median(wall_times)
    skills = reports[-1]["report"]["summary"]["discovered"]  # type: ignore[index]
    evidence = {
        "schema_version": "1.0",
        "created_at": datetime.now(UTC).isoformat(),
        "profile": args.profile,
        "tool_version": __version__,
        "corpus": corpus_identity(args.corpus),
        "runtime": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "visible_cpu_count": os.cpu_count(),
            "cgroup_cpu_max": read_cgroup("cpu.max"),
            "cgroup_memory_max": read_cgroup("memory.max"),
            "cgroup_memory_peak": read_cgroup("memory.peak"),
            "process_max_rss_kb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        },
        "summary": {
            "runs": args.runs,
            "skills": skills,
            "wall_duration_ms": wall_times,
            "median_wall_duration_ms": round(median_wall, 3),
            "median_throughput_skills_per_second": round(
                skills / (median_wall / 1000), 3  # type: ignore[operator]
            ),
            "skill_latency_ms": {
                "p50": percentile(skill_times, 0.50),
                "p95": percentile(skill_times, 0.95),
                "p99": percentile(skill_times, 0.99),
                "max": round(max(skill_times), 3),
            },
        },
        "runs": reports,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(evidence, indent=2) + "\n"
    if args.output.suffix == ".gz":
        with gzip.open(args.output, "wt", encoding="utf-8", compresslevel=9) as file:
            file.write(rendered)
    else:
        args.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
