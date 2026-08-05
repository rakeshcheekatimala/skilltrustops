"""Create a compact Markdown table from raw Docker benchmark evidence."""

from __future__ import annotations

import gzip
import hashlib
import json
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: summarize_docker_results.py RESULTS_DIR")
    root = Path(sys.argv[1])
    rows = []
    checksums = []
    corpus_fingerprints = set()
    result_paths = sorted(root.glob("*.json")) + sorted(root.glob("*.json.gz"))
    for path in result_paths:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as file:
                data = json.load(file)
        else:
            data = json.loads(path.read_text(encoding="utf-8"))
        runtime = data["runtime"]
        summary = data["summary"]
        corpus_fingerprints.add(data["corpus"]["entries_sha256"])
        checksums.append(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"
        )
        rows.append(
            (
                data["profile"],
                runtime["cgroup_cpu_max"],
                runtime["cgroup_memory_max"],
                summary["skills"],
                summary["median_wall_duration_ms"],
                summary["median_throughput_skills_per_second"],
                summary["skill_latency_ms"]["p95"],
                runtime["cgroup_memory_peak"],
            )
        )
    lines = [
        "# Docker benchmark summary",
        "",
        "| Profile | cgroup CPU | Memory bytes | Skills | Median ms | Skills/s | "
        "p95 skill ms | Peak memory bytes |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    lines.extend("| " + " | ".join(map(str, row)) + " |" for row in rows)
    if len(corpus_fingerprints) != 1:
        raise SystemExit("Docker profiles did not use one identical corpus")
    (root / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (root / "ARTIFACTS.sha256").write_text(
        "\n".join(sorted(checksums)) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
