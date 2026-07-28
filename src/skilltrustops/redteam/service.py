"""Application service for the Phase 1 reference behavioral assessment."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from skilltrustops import __version__
from skilltrustops.redteam.assertions import evaluate
from skilltrustops.redteam.attacks import cases_for
from skilltrustops.redteam.evidence import EvidenceWriter
from skilltrustops.redteam.friendly import build_friendly_report
from skilltrustops.redteam.loader import LoadedRedTeamPackage, RedTeamPackageLoader
from skilltrustops.redteam.models import (
    AssessmentDecision,
    AttackAttempt,
    AttemptOutcome,
    RedTeamReport,
    RedTeamSummary,
    TraceEvent,
)
from skilltrustops.redteam.simulator import GeneratedToolRuntime, SimulationState
from skilltrustops.redteam.targets import ModelTarget
from skilltrustops.sandbox.contracts import SandboxProvider
from skilltrustops.sandbox.models import no_sandbox_report


class RedTeamService:
    """Run attacks without executing any code from the submitted package."""

    def __init__(self, evidence_root: Path):
        self.evidence_root = evidence_root

    def run(
        self,
        manifest_path: Path,
        target: ModelTarget,
        sandbox_provider: SandboxProvider | None = None,
    ) -> RedTeamReport:
        package = RedTeamPackageLoader().load(manifest_path)
        sandbox = (
            sandbox_provider.run(package.root)
            if sandbox_provider is not None
            else no_sandbox_report()
        )
        planned_cases = cases_for(package.manifest)
        attempts = (
            tuple(
                self._run_case(package, target, case)
                for case in planned_cases
            )
            if sandbox.status not in {"failed", "unavailable"}
            else ()
        )
        succeeded = sum(
            attempt.outcome is AttemptOutcome.ATTACK_SUCCEEDED for attempt in attempts
        )
        inconclusive = sum(
            attempt.outcome in {AttemptOutcome.INCONCLUSIVE, AttemptOutcome.ERROR}
            for attempt in attempts
        )
        if succeeded:
            decision = AssessmentDecision.BLOCKED
            reasons = (f"{succeeded} adversarial case(s) produced a security failure",)
        elif sandbox.status in {"failed", "unavailable"}:
            decision = AssessmentDecision.INCONCLUSIVE
            reasons = (sandbox.explanation,)
        elif sandbox.status == "passed" and not sandbox.certifying:
            decision = AssessmentDecision.INCONCLUSIVE
            reasons = (
                "Docker development isolation passed, but it is not a certifying "
                "sandbox boundary",
            )
        elif inconclusive:
            decision = AssessmentDecision.INCONCLUSIVE
            reasons = (f"{inconclusive} case(s) could not be evaluated conclusively",)
        elif (
            package.manifest.generation and package.manifest.generation.requires_review
        ):
            decision = AssessmentDecision.INCONCLUSIVE
            reasons = (
                "Generated manifest is a draft and requires review before assurance",
            )
        else:
            decision = AssessmentDecision.ASSURED
            reasons = (
                "All applicable Phase 1 cases were resisted in the reference harness",
            )
        report = RedTeamReport(
            run_id=f"rt_{uuid4().hex[:12]}",
            started_at=datetime.now(UTC).isoformat(),
            package_name=package.manifest.name,
            package_version=package.manifest.version,
            package_sha256=package.package_sha256,
            skill_sha256=package.skill_sha256,
            manifest_sha256=package.manifest_sha256,
            model=target.choice,
            harness_version=__version__,
            decision=decision,
            decision_reasons=reasons,
            summary=RedTeamSummary(
                planned=len(planned_cases),
                executed=len(attempts),
                resisted=sum(
                    attempt.outcome is AttemptOutcome.RESISTED for attempt in attempts
                ),
                attack_succeeded=succeeded,
                inconclusive=inconclusive,
            ),
            attempts=attempts,
            sandbox=sandbox,
            model_execution_deterministic=target.deterministic,
        )
        report = report.model_copy(
            update={"friendly_report": build_friendly_report(report)}
        )
        reference = EvidenceWriter(self.evidence_root).write(report)
        return report.model_copy(update={"evidence": reference})

    def _run_case(
        self,
        package: LoadedRedTeamPackage,
        target: ModelTarget,
        case: object,
    ) -> AttackAttempt:
        # Imported type is deliberately local to keep the public service surface small.
        from skilltrustops.redteam.models import AttackCase, ModelResponse

        if not isinstance(case, AttackCase):
            raise TypeError("Unexpected attack case")
        fixture = package.manifest.synthetic_fixture
        state = SimulationState(
            current_user_id=fixture.current_user_id,
            records={
                record.resource_id: dict(record.fields) for record in fixture.records
            },
            owners={record.resource_id: record.owner_id for record in fixture.records},
            canaries=dict(fixture.canaries),
        )
        runtime = GeneratedToolRuntime(package.manifest.tools, state)
        last_response = ModelResponse(content="")
        try:
            for index, turn in enumerate(case.turns):
                state.events.append(
                    TraceEvent(
                        sequence=len(state.events) + 1,
                        type="document" if turn.channel == "document" else "message",
                        detail={"content": turn.content, "trust": turn.trust},
                    )
                )
                last_response = target.respond(
                    skill_content=package.skill_content,
                    manifest=package.manifest,
                    case=case,
                    turn_index=index,
                )
                state.events.append(
                    TraceEvent(
                        sequence=len(state.events) + 1,
                        type="model_output",
                        detail={"content": last_response.content},
                    )
                )
                for call in last_response.tool_calls:
                    runtime.execute(call)
        except (
            Exception
        ) as error:  # target failures become evidence, not process crashes
            error_assertions = evaluate(
                case, last_response, tuple(state.events), state.canaries
            )
            state.events.append(
                TraceEvent(
                    sequence=len(state.events) + 1,
                    type="assertion",
                    detail={"error": str(error)},
                )
            )
            return AttackAttempt(
                case=case,
                outcome=AttemptOutcome.ERROR,
                assertions=error_assertions,
                trace=tuple(state.events),
                output=last_response.content,
            )

        assertions = evaluate(case, last_response, tuple(state.events), state.canaries)
        for assertion in assertions:
            state.events.append(
                TraceEvent(
                    sequence=len(state.events) + 1,
                    type="assertion",
                    detail=assertion.model_dump(mode="json"),
                )
            )
        outcome = (
            AttemptOutcome.RESISTED
            if all(assertion.passed for assertion in assertions)
            else AttemptOutcome.ATTACK_SUCCEEDED
        )
        return AttackAttempt(
            case=case,
            outcome=outcome,
            assertions=assertions,
            trace=tuple(state.events),
            output=last_response.content,
        )
