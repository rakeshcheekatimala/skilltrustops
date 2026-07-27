"""Loopback-only FastAPI adapter over the shared SkillTrustOps services."""

import os
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter
from typing import Literal
from uuid import uuid4

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from backend.models import (
    CheckResult,
    Decision,
    EngineInfo,
    ManifestGenerationRequest,
    ModelConfigurationStatus,
    RedTeamRunRequest,
    ScanContentRequest,
    ScanRequest,
    SkillInfo,
    Summary,
    TrustDecisionReport,
)
from skilltrustops import __version__
from skilltrustops.factories import (
    build_lint_engine,
    build_privacy_engine,
    build_security_engine,
)
from skilltrustops.policies.loader import PolicyError, PolicyLoader
from skilltrustops.redteam.generator import (
    ManifestGenerationResult,
    RedTeamManifestGenerator,
)
from skilltrustops.redteam.loader import RedTeamPackageError
from skilltrustops.redteam.models import RedTeamReport
from skilltrustops.redteam.service import RedTeamService
from skilltrustops.redteam.targets import OpenAIModelTarget, ReferenceModelTarget
from skilltrustops.services.lint import LintService
from skilltrustops.services.local_env import load_local_env
from skilltrustops.services.static_scan import StaticScanService

ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env"


load_local_env(ENV_FILE)

app = FastAPI(title="SkillTrustOps Studio API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "local", "version": __version__}


@app.get("/api/redteam/config", response_model=ModelConfigurationStatus)
def redteam_config() -> ModelConfigurationStatus:
    return ModelConfigurationStatus(
        openai_configured=bool(os.getenv("OPENAI_API_KEY")),
        openai_default_model=os.getenv("SKILLTRUST_OPENAI_MODEL", "gpt-5.6-terra"),
        reference_models=["resistant-demo", "vulnerable-demo"],
        env_file=str(ENV_FILE),
    )


@app.post("/api/redteam/runs", response_model=RedTeamReport)
def run_redteam(request: RedTeamRunRequest) -> RedTeamReport:
    manifest_path = Path(request.manifest_path)
    if not manifest_path.is_absolute():
        manifest_path = ROOT / manifest_path
    try:
        target = (
            OpenAIModelTarget(request.model)
            if request.provider == "openai"
            else ReferenceModelTarget(request.model)
        )
        return RedTeamService(ROOT / ".skilltrustops" / "redteam-runs").run(
            manifest_path, target
        )
    except (RedTeamPackageError, ValueError) as error:
        raise HTTPException(400, str(error)) from error


@app.post(
    "/api/redteam/manifests/generate",
    response_model=ManifestGenerationResult,
)
def generate_redteam_manifest(
    request: ManifestGenerationRequest,
) -> ManifestGenerationResult:
    skill_path = Path(request.skill_path)
    if not skill_path.is_absolute():
        skill_path = ROOT / skill_path
    skill_path = skill_path.resolve()
    if not skill_path.is_relative_to(ROOT):
        raise HTTPException(400, "Manifest generation is limited to this repository")
    try:
        return RedTeamManifestGenerator().write(
            skill_path,
            force=request.force,
            strategy=request.strategy,
            model=request.model,
        )
    except RedTeamPackageError as error:
        raise HTTPException(400, str(error)) from error


@app.get("/api/redteam/demo/{profile}", response_model=RedTeamReport)
def redteam_demo(
    profile: Literal["resistant-demo", "vulnerable-demo"],
) -> RedTeamReport:
    return run_redteam(
        RedTeamRunRequest(
            manifest_path="examples/redteam-support/skilltrust-package.yaml",
            provider="reference",
            model=profile,
        )
    )


@app.post("/api/scans", response_model=TrustDecisionReport)
def scan(request: ScanRequest) -> TrustDecisionReport:
    started = perf_counter()
    started_at = datetime.now(UTC)
    skill_path = Path(request.skill_path).expanduser().resolve()
    if not skill_path.is_file() or skill_path.name != "SKILL.md":
        raise HTTPException(400, "Select a readable SKILL.md file.")

    policy_path = (
        Path(request.policy_path).expanduser() if request.policy_path else None
    )
    try:
        loaded = PolicyLoader().load(policy_path, skill_path.parent)
    except PolicyError as error:
        raise HTTPException(400, f"Invalid policy: {error}") from error

    policy = loaded.policy
    reports = []
    lint_started = perf_counter()
    lint_report = LintService(build_lint_engine(policy.checks.lint)).run(
        skill_path, loaded.reference
    )
    reports.append(
        ("specification", lint_report, (perf_counter() - lint_started) * 1000)
    )

    if policy.checks.security and policy.checks.security.enabled:
        report = StaticScanService(
            build_security_engine(policy.checks.security, loaded.base_dir), "security"
        ).run(skill_path, loaded.reference)
        reports.append(("security", report, report.duration_ms))
    if policy.checks.privacy and policy.checks.privacy.enabled:
        report = StaticScanService(
            build_privacy_engine(policy.checks.privacy), "privacy"
        ).run(skill_path, loaded.reference)
        reports.append(("privacy", report, report.duration_ms))

    findings = [finding for _, report, _ in reports for finding in report.findings]
    counts = {
        key: 0 for key in ("critical", "high", "medium", "low", "error", "warning")
    }
    for finding in findings:
        if finding.severity.value in counts:
            counts[finding.severity.value] += 1
    blockers = counts["critical"] + counts["high"]
    verdict = (
        "blocked" if blockers else ("needs_remediation" if findings else "admissible")
    )
    quoted_skill = f'"{skill_path}"'
    quoted_policy = (
        f' --policy "{loaded.reference.source}"' if loaded.reference.source else ""
    )

    return TrustDecisionReport(
        run_id=f"run_{uuid4().hex[:12]}",
        skill=SkillInfo(
            path=str(skill_path),
            name=skill_path.parent.name,
            sha256=sha256(skill_path.read_bytes()).hexdigest(),
        ),
        policy=loaded.reference.model_dump(),
        engine=EngineInfo(version=__version__),
        decision=Decision(verdict=verdict, blocking_findings=blockers),
        summary=Summary(
            **counts, passed=sum(1 for _, report, _ in reports if report.passed)
        ),
        checks=[
            CheckResult(
                name=name,
                passed=report.passed,
                finding_count=len(report.findings),
                duration_ms=round(duration, 3),
            )
            for name, report, duration in reports
        ],
        findings=findings,
        started_at=started_at.isoformat(),
        duration_ms=round((perf_counter() - started) * 1000, 3),
        equivalent_cli=(
            f"skilltrustops security {quoted_skill}{quoted_policy} --format json"
        ),
    )


@app.get("/api/demo", response_model=TrustDecisionReport)
def demo() -> TrustDecisionReport:
    return scan(
        ScanRequest(
            skill_path=str(ROOT / "examples/invalid-skill/SKILL.md"),
            policy_path=str(ROOT / "skilltrustops.yaml"),
        )
    )


@app.post("/api/scans/content", response_model=TrustDecisionReport)
def scan_content(request: ScanContentRequest) -> TrustDecisionReport:
    """Inspect browser-selected content without retaining it after the request."""
    if request.filename != "SKILL.md":
        raise HTTPException(400, "The selected file must be named SKILL.md.")
    if not request.content.strip():
        raise HTTPException(400, "The selected SKILL.md is empty.")
    display_name = "selected-skill"
    lines = request.content.splitlines()
    if lines and lines[0].strip() == "---":
        closing = next(
            (index for index, line in enumerate(lines[1:], 1) if line.strip() == "---"),
            None,
        )
        if closing is not None:
            try:
                metadata = yaml.safe_load("\n".join(lines[1:closing]))
                if isinstance(metadata, dict) and isinstance(metadata.get("name"), str):
                    display_name = metadata["name"]
            except yaml.YAMLError:
                pass
    with TemporaryDirectory(prefix="skilltrustops-") as directory:
        skill_dir = Path(directory) / display_name
        skill_dir.mkdir()
        skill_path = skill_dir / "SKILL.md"
        skill_path.write_text(request.content, encoding="utf-8")
        report = scan(
            ScanRequest(skill_path=str(skill_path), policy_path=request.policy_path)
        )
    return report.model_copy(
        update={
            "skill": report.skill.model_copy(
                update={"path": request.filename, "name": display_name}
            ),
            "equivalent_cli": (
                f'skilltrustops security "./{request.filename}" '
                '--policy "./skilltrustops.yaml" --format json'
            ),
        }
    )
