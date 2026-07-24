"""AST and command-pattern checks for dangerous skill instructions."""

import ast
import re

from skilltrustops.detectors.common import line_number
from skilltrustops.domain.findings import Finding, Severity
from skilltrustops.domain.skills import SkillFile
from skilltrustops.policies.models import DangerousCodePolicy

PYTHON_FENCE = re.compile(r"```(?:python|py)\s*\n(.*?)```", re.IGNORECASE | re.DOTALL)
EVAL_CALL = re.compile(r"\b(eval|exec)\s*\(")
DESTRUCTIVE_SHELL = re.compile(r"(?im)^\s*(?:sudo\s+)?rm\s+-[A-Za-z]*[rf][A-Za-z]*\b")
REMOTE_PIPE = re.compile(
    r"(?im)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b"
)


class AstDangerousCodeDetector:
    """Inspect text and Python code fences without executing any code."""

    def __init__(self, policy: DangerousCodePolicy) -> None:
        self._policy = policy

    def scan(self, skill_file: SkillFile) -> tuple[Finding, ...]:
        """Return dangerous-code findings enabled by policy."""
        findings: list[Finding] = []
        ast_eval_lines: set[int] = set()

        for fence in PYTHON_FENCE.finditer(skill_file.content):
            code = fence.group(1)
            first_line = line_number(skill_file.content, fence.start(1))
            try:
                tree = ast.parse(code)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                absolute_line = first_line + node.lineno - 1
                call_name = self._call_name(node.func)
                if self._policy.block_eval and call_name in {"eval", "exec"}:
                    ast_eval_lines.add(absolute_line)
                    findings.append(
                        self._eval_finding(skill_file, call_name, absolute_line)
                    )
                subprocess_shell = (
                    call_name is not None
                    and call_name.startswith("subprocess.")
                    and self._uses_shell_true(node)
                )
                if call_name == "os.system" or subprocess_shell:
                    findings.append(
                        Finding(
                            rule_id="STO-SEC-103",
                            severity=Severity.HIGH,
                            message="Python code invokes a system shell.",
                            evidence=(
                                "Shell-invoking call detected at line "
                                f"{absolute_line}; "
                                "arguments redacted."
                            ),
                            remediation=(
                                "Use a constrained subprocess argument list without "
                                "shell=True, and validate every argument."
                            ),
                            location=f"{skill_file.path.name}:{absolute_line}",
                        )
                    )

        if self._policy.block_eval:
            for match in EVAL_CALL.finditer(skill_file.content):
                detected_line = line_number(skill_file.content, match.start())
                if detected_line not in ast_eval_lines:
                    findings.append(
                        self._eval_finding(
                            skill_file,
                            match.group(1),
                            detected_line,
                        )
                    )

        if self._policy.block_destructive_shell:
            for match in DESTRUCTIVE_SHELL.finditer(skill_file.content):
                detected_line = line_number(skill_file.content, match.start())
                findings.append(
                    Finding(
                        rule_id="STO-SEC-101",
                        severity=Severity.CRITICAL,
                        message="Destructive recursive removal command detected.",
                        evidence=(
                            f"rm command with recursive/force flags detected at "
                            f"line {detected_line}; command redacted."
                        ),
                        remediation=(
                            "Remove the command or replace it with a narrowly scoped, "
                            "recoverable operation requiring explicit confirmation."
                        ),
                        location=f"{skill_file.path.name}:{detected_line}",
                    )
                )

        if self._policy.block_remote_pipe:
            for match in REMOTE_PIPE.finditer(skill_file.content):
                detected_line = line_number(skill_file.content, match.start())
                findings.append(
                    Finding(
                        rule_id="STO-SEC-102",
                        severity=Severity.CRITICAL,
                        message="Remote content is piped directly to a shell.",
                        evidence=(
                            f"Download-to-shell pipeline detected at line "
                            f"{detected_line}; URL and command redacted."
                        ),
                        remediation=(
                            "Download to a file, verify its origin and checksum, "
                            "inspect it, and execute only after explicit approval."
                        ),
                        location=f"{skill_file.path.name}:{detected_line}",
                    )
                )

        return tuple(findings)

    @staticmethod
    def _call_name(function: ast.expr) -> str | None:
        if isinstance(function, ast.Name):
            return function.id
        if isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name):
            return f"{function.value.id}.{function.attr}"
        return None

    @staticmethod
    def _uses_shell_true(node: ast.Call) -> bool:
        return any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        )

    @staticmethod
    def _eval_finding(
        skill_file: SkillFile,
        call_name: str,
        detected_line: int,
    ) -> Finding:
        return Finding(
            rule_id="STO-SEC-100",
            severity=Severity.HIGH,
            message=f"Dynamic {call_name} call detected.",
            evidence=(
                f"{call_name} call detected at line {detected_line}; "
                "arguments redacted."
            ),
            remediation=(
                "Replace dynamic execution with explicit parsing, validation, "
                "and an allowlisted operation."
            ),
            location=f"{skill_file.path.name}:{detected_line}",
        )
