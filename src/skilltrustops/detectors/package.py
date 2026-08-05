"""Bounded, non-executing inspection of complete skill packages."""

from __future__ import annotations

import json
import os
import re
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

from skilltrustops.detectors.pii import BuiltinPiiDetector
from skilltrustops.domain.findings import Finding, Severity
from skilltrustops.domain.skills import SkillFile
from skilltrustops.policies.models import PiiEntity

MAX_PACKAGE_FILES = 2_000
MAX_PACKAGE_BYTES = 32 * 1024 * 1024
MAX_TEXT_FILE_BYTES = 1024 * 1024
MAX_ARCHIVE_MEMBERS = 5_000
MAX_ARCHIVE_EXPANDED_BYTES = 128 * 1024 * 1024

TEXT_NAMES = {
    "dockerfile",
    "makefile",
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "pipfile",
    "gemfile",
    "cargo.toml",
    "go.mod",
}
TEXT_SUFFIXES = {
    ".md",
    ".txt",
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".ps1",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".xml",
    ".html",
    ".sql",
}
ARCHIVE_SUFFIXES = {".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz"}

RULES: tuple[tuple[str, Severity, str, re.Pattern[str], str, tuple[str, ...]], ...] = (
    (
        "STO-PKG-200",
        Severity.HIGH,
        "Prompt-injection or authority-override instruction detected.",
        re.compile(
            r"(?i)\b(?:ignore|disregard|override)\b.{0,80}\b(?:previous|prior|system|developer|policy|instructions?)\b|\b(?:system|developer)\s+message\s*:",
            re.DOTALL,
        ),
        "Remove authority-override language or isolate it as an explicitly labeled security-test fixture.",
        ("ignore", "disregard", "override", "system message", "developer message"),
    ),
    (
        "STO-PKG-201",
        Severity.HIGH,
        "Encoded or dynamically reconstructed payload detected.",
        re.compile(
            r"(?i)\b(?:base64\s+(?:-d|--decode)|atob\s*\(|b64decode\s*\(|fromCharCode\s*\(|eval\s*\(.{0,80}(?:decode|base64))",
            re.DOTALL,
        ),
        "Use transparent, reviewable source and remove runtime decoding or dynamic execution.",
        ("base64", "atob", "b64decode", "fromcharcode", "eval"),
    ),
    (
        "STO-PKG-202",
        Severity.CRITICAL,
        "Persistence mechanism detected.",
        re.compile(
            r"(?i)(?:\bcrontab\b|/etc/cron|\.bashrc|\.zshrc|authorized_keys|launchagents|systemd/system|\.git/hooks|startup folder)"
        ),
        "Do not modify startup, scheduler, authentication, or repository-hook state from a skill.",
        (
            "crontab",
            "/etc/cron",
            ".bashrc",
            ".zshrc",
            "authorized_keys",
            "launchagents",
            "systemd/system",
            ".git/hooks",
            "startup folder",
        ),
    ),
    (
        "STO-PKG-203",
        Severity.CRITICAL,
        "Potential secret or data-exfiltration flow detected.",
        re.compile(
            r"(?is)(?:curl\b.{0,180}(?:-d|--data|--upload-file)|requests\.(?:post|put)\s*\(|fetch\s*\(.{0,160}method\s*:\s*['\"]POST|process\.env|os\.environ).{0,240}(?:https?://|webhook|upload|post)"
        ),
        "Remove outbound transmission or constrain it to approved destinations with explicit data classification and consent.",
        ("curl", "requests.", "fetch(", "process.env", "os.environ"),
    ),
    (
        "STO-PKG-204",
        Severity.HIGH,
        "Excessive permission or privilege change detected.",
        re.compile(
            r"(?i)(?:\bsudo\b|chmod\s+(?:-R\s+)?777\b|chown\s+-R\b|--privileged\b|docker\.sock|allow[-_ ]?all|permissions?\s*[:=]\s*['\"]?\*)"
        ),
        "Use least privilege and enumerate the exact permissions and resources required.",
        (
            "sudo",
            "chmod",
            "chown",
            "--privileged",
            "docker.sock",
            "allow-all",
            "allow_all",
            "permission",
        ),
    ),
    (
        "STO-PKG-205",
        Severity.HIGH,
        "Package lifecycle execution hook detected.",
        re.compile(
            r"(?i)(?:\bpreinstall\b|\bpostinstall\b|\bprepare\b|setup_requires\s*=|cmdclass\s*=|build-system|build-backend)"
        ),
        "Review lifecycle hooks and build backends as executable supply-chain code; pin and verify their provenance.",
        (
            "preinstall",
            "postinstall",
            "prepare",
            "setup_requires",
            "cmdclass",
            "build-system",
            "build-backend",
        ),
    ),
)


class PackageSecurityScanner:
    """Inspect package files, links, archives, manifests, and cross-file references."""

    def scan(self, skill_path: Path) -> tuple[Finding, ...]:
        root = skill_path.absolute().parent
        findings: list[Finding] = []
        files: list[Path] = []
        total_bytes = 0
        for current, directories, names in os.walk(root, followlinks=False):
            current_path = Path(current)
            kept: list[str] = []
            for name in sorted(directories):
                path = current_path / name
                if path.is_symlink():
                    findings.append(self._link_finding(path, root))
                else:
                    kept.append(name)
            directories[:] = kept
            for name in sorted(names):
                path = current_path / name
                if path.is_symlink():
                    findings.append(self._link_finding(path, root))
                    continue
                try:
                    mode = path.stat(follow_symlinks=False).st_mode
                    size = path.stat(follow_symlinks=False).st_size
                except OSError as error:
                    findings.append(
                        self._finding(
                            "STO-PKG-009",
                            Severity.ERROR,
                            "Package entry could not be inspected.",
                            f"Metadata read failed for {self._relative(path, root)}: {error}",
                            "Make the entry readable and retry.",
                            self._relative(path, root),
                        )
                    )
                    continue
                if not stat.S_ISREG(mode):
                    findings.append(
                        self._finding(
                            "STO-PKG-206",
                            Severity.HIGH,
                            "Non-regular package entry detected.",
                            f"Special filesystem entry: {self._relative(path, root)}.",
                            "Remove device, socket, FIFO, or other special entries from the package.",
                            self._relative(path, root),
                        )
                    )
                    continue
                files.append(path)
                total_bytes += size
                if len(files) > MAX_PACKAGE_FILES or total_bytes > MAX_PACKAGE_BYTES:
                    return tuple(
                        [
                            *findings,
                            self._finding(
                                "STO-PKG-007",
                                Severity.ERROR,
                                "Package exceeds bounded scan limits.",
                                f"Limit is {MAX_PACKAGE_FILES} files and {MAX_PACKAGE_BYTES} bytes.",
                                "Reduce the package or scan separately versioned components.",
                                ".",
                            ),
                        ]
                    )

        texts: dict[str, str] = {}
        for path in files:
            relative = self._relative(path, root)
            if path.suffix.lower() in ARCHIVE_SUFFIXES:
                findings.extend(self._scan_archive(path, relative))
            if (
                not self._is_text_candidate(path)
                or path.stat().st_size > MAX_TEXT_FILE_BYTES
            ):
                continue
            try:
                content = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            texts[relative] = content
            lowered = content.lower()
            for rule_id, severity, message, pattern, remediation, triggers in RULES:
                if not any(trigger in lowered for trigger in triggers):
                    continue
                for match in pattern.finditer(content):
                    line = content.count("\n", 0, match.start()) + 1
                    findings.append(
                        self._finding(
                            rule_id,
                            severity,
                            message,
                            f"Pattern detected at {relative}:{line}; matched content redacted.",
                            remediation,
                            f"{relative}:{line}",
                        )
                    )
            findings.extend(self._manifest_findings(path, relative, content))

        findings.extend(self._cross_file_findings(texts, root))
        return tuple(self._deduplicate(findings))

    @staticmethod
    def _is_text_candidate(path: Path) -> bool:
        return path.name.lower() in TEXT_NAMES or path.suffix.lower() in TEXT_SUFFIXES

    def _manifest_findings(
        self, path: Path, relative: str, content: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        if path.name == "package.json":
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                return findings
            scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
            if isinstance(scripts, dict):
                for hook in ("preinstall", "postinstall", "prepare"):
                    if hook in scripts:
                        findings.append(
                            self._finding(
                                "STO-PKG-205",
                                Severity.HIGH,
                                "Package lifecycle execution hook detected.",
                                f"package.json declares {hook}; command redacted.",
                                "Remove the hook or require explicit review of its exact pinned implementation.",
                                relative,
                            )
                        )
        if path.name in {"requirements.txt", "Pipfile"}:
            for index, line in enumerate(content.splitlines(), 1):
                value = line.strip()
                if (
                    value
                    and not value.startswith(("#", "-"))
                    and not re.search(
                        r"(?:==|===|@\s*(?:https|git\+).+@[0-9a-f]{7,})", value
                    )
                ):
                    findings.append(
                        self._finding(
                            "STO-PKG-208",
                            Severity.MEDIUM,
                            "Unpinned dependency detected.",
                            f"Dependency without an immutable version at {relative}:{index}; value redacted.",
                            "Pin dependencies to reviewed versions and record hashes where supported.",
                            f"{relative}:{index}",
                        )
                    )
        return findings

    def _cross_file_findings(self, texts: dict[str, str], root: Path) -> list[Finding]:
        skill = texts.get("SKILL.md", "")
        findings: list[Finding] = []
        risky_paths = {
            path
            for path, content in texts.items()
            if path != "SKILL.md" and self._contains_risky_pattern(content)
        }
        for match in re.finditer(
            r"(?i)(?:^|[\s`(])((?:scripts|references|assets)/[A-Za-z0-9_./-]+)", skill
        ):
            reference = match.group(1).rstrip(".,)`")
            candidate = root / reference
            if not candidate.exists():
                line = skill.count("\n", 0, match.start(1)) + 1
                findings.append(
                    self._finding(
                        "STO-PKG-209",
                        Severity.MEDIUM,
                        "Referenced package file is missing.",
                        f"Missing reference at SKILL.md:{line}: {reference}.",
                        "Add the referenced file or remove the stale instruction.",
                        f"SKILL.md:{line}",
                    )
                )
            elif reference in risky_paths:
                findings.append(
                    self._finding(
                        "STO-PKG-210",
                        Severity.HIGH,
                        "Skill delegates to a risky package file.",
                        f"SKILL.md references {reference}, which contains a high-risk behavior pattern.",
                        "Review the referenced file and remove or constrain the risky behavior.",
                        reference,
                    )
                )
        return findings

    @staticmethod
    def _contains_risky_pattern(content: str) -> bool:
        lowered = content.lower()
        return any(
            any(trigger in lowered for trigger in triggers) and pattern.search(content)
            for _, _, _, pattern, _, triggers in RULES[1:]
        )

    def _scan_archive(self, path: Path, relative: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as archive:
                    members = [
                        (
                            item.filename,
                            item.file_size,
                            (item.external_attr >> 16) & 0o170000 == stat.S_IFLNK,
                        )
                        for item in archive.infolist()
                    ]
            elif tarfile.is_tarfile(path):
                with tarfile.open(path, "r:*") as archive:
                    members = [
                        (item.name, item.size, item.issym() or item.islnk())
                        for item in archive.getmembers()
                    ]
            else:
                return findings
        except (OSError, tarfile.TarError, zipfile.BadZipFile):
            return findings
        expanded = sum(size for _, size, _ in members)
        if len(members) > MAX_ARCHIVE_MEMBERS or expanded > MAX_ARCHIVE_EXPANDED_BYTES:
            findings.append(
                self._finding(
                    "STO-PKG-207",
                    Severity.CRITICAL,
                    "Archive exceeds safe expansion limits.",
                    f"Archive {relative} has {len(members)} entries and {expanded} expanded bytes.",
                    "Reduce and review the archive before scanning or extraction.",
                    relative,
                )
            )
        for name, _, is_link in members:
            member = PurePosixPath(name.replace("\\", "/"))
            if is_link or member.is_absolute() or ".." in member.parts:
                findings.append(
                    self._finding(
                        "STO-PKG-207",
                        Severity.CRITICAL,
                        "Unsafe archive member detected.",
                        f"Archive {relative} contains a link or path-traversal entry; name redacted.",
                        "Rebuild the archive with regular relative paths only.",
                        relative,
                    )
                )
                break
        return findings

    def _link_finding(self, path: Path, root: Path) -> Finding:
        return self._finding(
            "STO-PKG-206",
            Severity.HIGH,
            "Symbolic link detected in skill package.",
            f"Link path: {self._relative(path, root)}; target not followed.",
            "Replace links with reviewed regular files or exclude them from the package.",
            self._relative(path, root),
        )

    @staticmethod
    def _relative(path: Path, root: Path) -> str:
        return path.relative_to(root).as_posix()

    @staticmethod
    def _finding(
        rule_id: str,
        severity: Severity,
        message: str,
        evidence: str,
        remediation: str,
        location: str,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            severity=severity,
            message=message,
            evidence=evidence,
            remediation=remediation,
            location=location,
        )

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, str | None, str]] = set()
        result: list[Finding] = []
        for finding in findings:
            key = (finding.rule_id, finding.location, finding.message)
            if key not in seen:
                seen.add(key)
                result.append(finding)
        return result


class PackageSecurityDetector:
    """Content-engine adapter that expands one SKILL.md to its package root."""

    def scan(self, skill_file: SkillFile) -> tuple[Finding, ...]:
        return PackageSecurityScanner().scan(skill_file.path)


class PackagePrivacyDetector:
    """Apply configured PII rules to every bounded text file in the package."""

    def __init__(self, entities: tuple[PiiEntity, ...]) -> None:
        self._detector = BuiltinPiiDetector(entities)

    def scan(self, skill_file: SkillFile) -> tuple[Finding, ...]:
        root = skill_file.path.absolute().parent
        findings: list[Finding] = []
        files = 0
        total_bytes = 0
        for current, directories, names in os.walk(root, followlinks=False):
            current_path = Path(current)
            directories[:] = [
                name
                for name in sorted(directories)
                if not (current_path / name).is_symlink()
            ]
            for name in sorted(names):
                path = current_path / name
                if path == skill_file.path.absolute() or path.is_symlink():
                    continue
                try:
                    size = path.stat(follow_symlinks=False).st_size
                except OSError:
                    continue
                files += 1
                total_bytes += size
                if files > MAX_PACKAGE_FILES or total_bytes > MAX_PACKAGE_BYTES:
                    return tuple(findings)
                if (
                    not path.is_file()
                    or size > MAX_TEXT_FILE_BYTES
                    or not PackageSecurityScanner._is_text_candidate(path)
                ):
                    continue
                try:
                    content = path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                relative = path.relative_to(root).as_posix()
                for finding in self._detector.scan(
                    SkillFile(path=path, content=content)
                ):
                    location = finding.location
                    if location and ":" in location:
                        _, _, line = location.rpartition(":")
                        location = f"{relative}:{line}"
                    else:
                        location = relative
                    findings.append(finding.model_copy(update={"location": location}))
        return tuple(findings)
