"""Content-addressed evidence bundle and Inspect-compatible JSONL event export."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from skilltrustops.redteam.attacks import ATTACK_PACK_ID, ATTACK_PACK_VERSION
from skilltrustops.redteam.friendly import render_friendly_markdown
from skilltrustops.redteam.models import EvidenceReference, RedTeamReport


@dataclass(frozen=True, slots=True)
class EvidenceWriter:
    root: Path

    def write(self, report: RedTeamReport) -> EvidenceReference:
        directory = (self.root / report.run_id).absolute()
        directory.mkdir(parents=True, exist_ok=False)
        report_path = directory / "report.json"
        inspect_path = directory / "inspect-events.jsonl"
        manifest_path = directory / "evidence-manifest.json"
        friendly_path = directory / "friendly-report.md"

        report_payload = report.model_dump(mode="json", exclude={"evidence"})
        report_path.write_text(
            json.dumps(report_payload, indent=2, sort_keys=True), encoding="utf-8"
        )
        with inspect_path.open("w", encoding="utf-8") as stream:
            for attempt in report.attempts:
                stream.write(
                    json.dumps(
                        {
                            "schema_version": "skilltrust-inspect-events-1",
                            "task_id": attempt.case.id,
                            "model": report.model.model_dump(mode="json"),
                            "input": [
                                turn.model_dump(mode="json")
                                for turn in attempt.case.turns
                            ],
                            "output": attempt.output,
                            "events": [
                                event.model_dump(mode="json") for event in attempt.trace
                            ],
                            "scores": {
                                assertion.rule_id: int(assertion.passed)
                                for assertion in attempt.assertions
                            },
                            "outcome": attempt.outcome,
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
        friendly_path.write_text(render_friendly_markdown(report), encoding="utf-8")
        artifacts = {
            report_path.name: _digest(report_path),
            inspect_path.name: _digest(inspect_path),
            friendly_path.name: _digest(friendly_path),
        }
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "run_id": report.run_id,
                    "package_sha256": report.package_sha256,
                    "skill_sha256": report.skill_sha256,
                    "manifest_sha256": report.manifest_sha256,
                    "model": report.model.model_dump(mode="json"),
                    "attack_pack": {
                        "id": ATTACK_PACK_ID,
                        "version": ATTACK_PACK_VERSION,
                    },
                    "artifacts": artifacts,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return EvidenceReference(
            directory=str(directory),
            manifest=str(manifest_path),
            report=str(report_path),
            inspect_log=str(inspect_path),
            friendly_report=str(friendly_path),
        )


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
