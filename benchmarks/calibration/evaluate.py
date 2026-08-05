"""Evaluate deterministic rules against the authored calibration fixtures."""

from __future__ import annotations

import json
import math
import os
import tempfile
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from skilltrustops import scan

ROOT = Path(__file__).parent
DATASET = ROOT / "cases.jsonl"
OUTPUT = ROOT / "results.json"


def _materialize(case: dict[str, Any], root: Path) -> Path:
    package = root / case["skill_name"]
    package.mkdir()
    skill = (
        "---\n"
        f"name: {case['skill_name']}\n"
        "description: Deterministic calibration fixture for SkillTrustOps.\n"
        "---\n\n"
        f"{case['skill_body']}\n"
    )
    (package / "SKILL.md").write_text(skill, encoding="utf-8")
    for relative, content in case["files"].items():
        path = package / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if content == "__ARCHIVE_TRAVERSAL__":
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("../escape.txt", "synthetic")
        elif content == "__SAFE_ARCHIVE__":
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("fixtures/example.txt", "synthetic")
        elif content == "__SYMLINK__":
            os.symlink("../SKILL.md", path)
        else:
            path.write_text(str(content), encoding="utf-8")
    return package / "SKILL.md"


def _scores(tp: int, fp: int, fn: int, tn: int) -> dict[str, float | int]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "false_positive_rate": round(fpr, 6),
    }


def _wilson(successes: int, total: int) -> list[float]:
    if not total:
        return [0.0, 0.0]
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return [round(max(0.0, center - margin), 6), round(min(1.0, center + margin), 6)]


def main() -> None:
    cases = [
        json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines()
    ]
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    details: list[dict[str, object]] = []
    for case in cases:
        with tempfile.TemporaryDirectory(prefix="sto-cal-") as directory:
            target = _materialize(case, Path(directory))
            report = scan(target)
            rules = {
                finding.rule_id
                for skill in report.skills
                for check in skill.checks
                for finding in check.findings
            }
        expected = set(case["expected_rules"])
        predicted = bool(rules & ({FAMILY_RULES[case["family"]]}))
        positive = case["ground_truth"] == "positive"
        bucket = (
            "tp"
            if positive and predicted
            else "fn"
            if positive
            else "fp"
            if predicted
            else "tn"
        )
        counts[case["family"]][bucket] += 1
        details.append(
            {
                "case_id": case["case_id"],
                "family": case["family"],
                "expected_rules": sorted(expected),
                "observed_rules": sorted(rules),
                "outcome": bucket,
            }
        )
    family_metrics = {}
    aggregate = defaultdict(int)
    for family, values in sorted(counts.items()):
        metric = _scores(values["tp"], values["fp"], values["fn"], values["tn"])
        metric["recall_95pct_wilson"] = _wilson(
            values["tp"], values["tp"] + values["fn"]
        )
        metric["specificity_95pct_wilson"] = _wilson(
            values["tn"], values["tn"] + values["fp"]
        )
        family_metrics[family] = metric
        for key in ("tp", "fp", "fn", "tn"):
            aggregate[key] += values[key]
    result = {
        "schema_version": "1.0",
        "dataset_cases": len(cases),
        "label_status": "construction-derived; independent review required",
        "claim_boundary": (
            "Regression metrics only; not independently validated real-world accuracy."
        ),
        "aggregate": _scores(
            aggregate["tp"], aggregate["fp"], aggregate["fn"], aggregate["tn"]
        ),
        "by_family": family_metrics,
        "cases": details,
    }
    OUTPUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


FAMILY_RULES = {
    family: rule
    for family, rule, *_ in (
        ("prompt_injection", "STO-PKG-200"),
        ("obfuscation", "STO-PKG-201"),
        ("persistence", "STO-PKG-202"),
        ("exfiltration", "STO-PKG-203"),
        ("permission_abuse", "STO-PKG-204"),
        ("lifecycle_hook", "STO-PKG-205"),
        ("archive_escape", "STO-PKG-207"),
        ("dependency_risk", "STO-PKG-208"),
        ("symlink_escape", "STO-PKG-206"),
        ("cross_file_risk", "STO-PKG-210"),
    )
}


if __name__ == "__main__":
    main()
