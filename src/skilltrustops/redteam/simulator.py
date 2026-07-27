"""In-memory world and generated tool implementations with no side effects."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from skilltrustops.redteam.models import ToolCall, ToolDefinition, TraceEvent


@dataclass(slots=True)
class SimulationState:
    current_user_id: str
    records: dict[str, dict[str, Any]]
    owners: dict[str, str]
    canaries: dict[str, str]
    confirmations: set[str] = field(default_factory=set)
    events: list[TraceEvent] = field(default_factory=list)


class GeneratedToolRuntime:
    """Validate and simulate declared tools without executing submitted code."""

    def __init__(self, tools: tuple[ToolDefinition, ...], state: SimulationState):
        self.tools = {tool.name: tool for tool in tools}
        self.state = state

    def execute(self, call: ToolCall) -> dict[str, Any]:
        tool = self.tools.get(call.name)
        self._event(
            "tool_call_attempted", {"tool": call.name, "arguments": call.arguments}
        )
        if tool is None:
            return self._blocked(call.name, "undeclared_tool")
        properties = tool.input_schema.get("properties", {})
        required = tool.input_schema.get("required", [])
        if any(name not in call.arguments for name in required):
            return self._blocked(call.name, "missing_required_argument")
        if any(name not in properties for name in call.arguments):
            return self._blocked(call.name, "unknown_argument")

        authorization = tool.security.authorization
        resource_id = None
        if authorization.scope == "current_user":
            argument = authorization.resource_id_argument or ""
            resource_id = str(call.arguments.get(argument, ""))
            if self.state.owners.get(resource_id) != self.state.current_user_id:
                return self._blocked(call.name, "unauthorized_resource")
        if (
            tool.security.confirmation.required
            and call.name not in self.state.confirmations
        ):
            return self._blocked(call.name, "missing_confirmation")

        result = self.state.records.get(resource_id or "", {"status": "simulated"})
        self._event(
            "tool_call_simulated",
            {"tool": call.name, "executed": False, "result": result},
        )
        return {"status": "simulated", "executed": False, "result": result}

    def _blocked(self, tool: str, reason: str) -> dict[str, Any]:
        self._event(
            "tool_call_blocked",
            {"tool": tool, "executed": False, "reason": reason},
        )
        return {"status": "blocked", "executed": False, "reason": reason}

    def _event(self, event_type: str, detail: dict[str, Any]) -> None:
        self.state.events.append(
            TraceEvent(
                sequence=len(self.state.events) + 1,
                type=event_type,  # type: ignore[arg-type]
                detail=detail,
            )
        )
