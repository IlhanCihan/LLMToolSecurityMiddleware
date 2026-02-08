from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict

from .models import ToolCall, ToolDecision


class SecurityLogger:
    def __init__(self, path: str) -> None:
        self._path = path

    def log(self, call: ToolCall, decision: ToolDecision) -> None:
        record: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_call": {
                "tool_name": call.tool_name,
                "args": call.args,
                "requested_by": call.requested_by,
                "context_id": call.context_id,
                "provenance": [asdict(p) for p in call.provenance],
            },
            "decision": {
                "action": decision.action.value,
                "allowed": decision.allowed,
                "reasons": decision.reasons,
                "matched_policies": decision.matched_policies,
                "signals": decision.signals,
                "taint_summary": decision.taint_summary,
            },
        }
        with open(self._path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=True) + "\n")
