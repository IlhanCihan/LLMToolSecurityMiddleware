from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .models import ToolCall, ToolCategory, ToolDecision
from .secrets import SecretDetector

TOOL_CATEGORIES: dict[str, ToolCategory] = {
    "search_web": ToolCategory.SEARCH,
    "fetch_url": ToolCategory.FETCH,
    "read_file": ToolCategory.FILE_READ,
    "write_file": ToolCategory.FILE_WRITE,
    "draft_email": ToolCategory.EMAIL,
    "send_email": ToolCategory.EMAIL,
    "query_database": ToolCategory.DATABASE,
    "execute_code_sandbox": ToolCategory.CODE_EXEC,
}


class SecurityLogger:
    def __init__(
        self,
        path: str,
        secret_detector: SecretDetector | None = None,
    ) -> None:
        self._path = path
        self._secrets = secret_detector or SecretDetector()

    def log(
        self,
        call: ToolCall,
        decision: ToolDecision,
        *,
        latency_ms: float = 0.0,
    ) -> dict[str, Any]:
        redacted_args = self._secrets.redact_payload(call.args)
        record: dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "session_id": call.session_id or call.context_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_goal": call.user_goal,
            "tool_name": call.tool_name,
            "tool_category": _tool_category(call.tool_name).value,
            "decision": decision.action.value,
            "allowed": decision.allowed,
            "matched_policy_rules": decision.matched_policies,
            "risk_signals": _redact_signals(decision.signals, self._secrets),
            "taint_provenance_summary": decision.taint_summary,
            "redacted_arguments": redacted_args,
            "latency_ms": round(latency_ms, 2),
            "explanation": decision.explanation or "; ".join(decision.reasons),
            "requires_approval": decision.requires_approval,
            "quarantined": decision.quarantined,
        }
        with open(self._path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=True) + "\n")
        return record


def _tool_category(tool_name: str) -> ToolCategory:
    return TOOL_CATEGORIES.get(tool_name, ToolCategory.UNKNOWN)


def _redact_signals(signals: dict[str, Any], detector: SecretDetector) -> dict[str, Any]:
    redacted = dict(signals)
    evidence = redacted.get("injection_evidence")
    if isinstance(evidence, list):
        redacted["injection_evidence"] = [detector.redact_text(str(item)) for item in evidence]
    risk = redacted.get("risk")
    if isinstance(risk, dict):
        risk_copy = dict(risk)
        if "secret_matches" in risk_copy:
            risk_copy["secret_matches"] = ["[REDACTED]"]
        redacted["risk"] = risk_copy
    return redacted
