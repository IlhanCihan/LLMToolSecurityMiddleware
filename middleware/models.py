from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class TrustLevel(str, Enum):
    SYSTEM = "system"
    DEVELOPER = "developer"
    USER = "user"
    RETRIEVED = "retrieved"
    TOOL_OUTPUT = "tool_output"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class DataProvenance:
    source_id: str
    trust: TrustLevel
    description: str = ""


@dataclass
class ToolCall:
    tool_name: str
    args: Dict[str, Any]
    requested_by: str
    context_id: str
    provenance: List[DataProvenance] = field(default_factory=list)


class DecisionAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    SANDBOX = "sandbox"


@dataclass
class ToolDecision:
    action: DecisionAction
    allowed: bool
    reasons: List[str]
    matched_policies: List[str]
    signals: Dict[str, Any]
    taint_summary: Dict[str, Any]
    sanitized_args: Optional[Dict[str, Any]] = None

