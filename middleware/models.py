from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SourceType(str, Enum):
    USER = "user"
    SYSTEM = "system"
    RETRIEVED_DOCUMENT = "retrieved_document"
    WEBPAGE = "webpage"
    EMAIL = "email"
    TOOL_OUTPUT = "tool_output"
    MCP_TOOL = "mcp_tool"
    DATABASE = "database"


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class ConfidentialityLevel(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"


class IntegrityLevel(str, Enum):
    TRUSTED = "trusted"
    USER_CONTROLLED = "user_controlled"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class TransformType(str, Enum):
    RETRIEVED = "retrieved"
    SUMMARIZED = "summarized"
    REDACTED = "redacted"
    VALIDATED = "validated"


class DecisionAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    SANDBOX = "sandbox"
    REDACT = "redact"
    REQUIRE_APPROVAL = "require_approval"
    QUARANTINE = "quarantine"
    ALLOW_WITH_TRANSFORM = "allow_with_transform"


class ToolCategory(str, Enum):
    SEARCH = "search"
    FETCH = "fetch"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    EMAIL = "email"
    DATABASE = "database"
    CODE_EXEC = "code_exec"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class DataProvenance:
    source_id: str
    source_type: SourceType = SourceType.USER
    trust: TrustLevel = TrustLevel.UNKNOWN
    confidentiality: ConfidentialityLevel = ConfidentialityLevel.PUBLIC
    integrity: IntegrityLevel = IntegrityLevel.UNKNOWN
    transforms: tuple[TransformType, ...] = ()
    description: str = ""


@dataclass
class ToolCall:
    tool_name: str
    args: dict[str, Any]
    requested_by: str
    context_id: str
    session_id: str = ""
    user_goal: str = ""
    provenance: list[DataProvenance] = field(default_factory=list)


@dataclass
class ToolDecision:
    action: DecisionAction
    allowed: bool
    reasons: list[str]
    matched_policies: list[str]
    signals: dict[str, Any]
    taint_summary: dict[str, Any]
    sanitized_args: dict[str, Any] | None = None
    explanation: str = ""
    requires_approval: bool = False
    quarantined: bool = False


@dataclass
class ToolResponse:
    tool_name: str
    content: Any
    provenance: list[DataProvenance] = field(default_factory=list)
    session_id: str = ""
    context_id: str = ""


@dataclass
class FirewallDecision:
    action: DecisionAction
    content: Any
    allowed: bool
    reasons: list[str]
    matched_policies: list[str]
    signals: dict[str, Any]
    provenance: list[DataProvenance]
    quarantined: bool = False
    explanation: str = ""
