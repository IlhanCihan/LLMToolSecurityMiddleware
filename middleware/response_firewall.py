from __future__ import annotations

import re
from typing import Any

from .detectors import PromptInjectionHeuristics
from .models import (
    DecisionAction,
    FirewallDecision,
    SourceType,
    ToolResponse,
)
from .secrets import SecretDetector
from .taint import default_untrusted_provenance

AUTHORITY_ESCALATION_PATTERNS = [
    r"grant\s+(?:admin|root|sudo)\s+access",
    r"enable\s+developer\s+mode",
    r"you\s+may\s+now\s+call",
    r"ignore\s+all\s+restrictions",
    r"new\s+tool\s+permissions?",
]


class ResponseFirewall:
    def __init__(
        self,
        injection_detector: PromptInjectionHeuristics | None = None,
        secret_detector: SecretDetector | None = None,
        injection_quarantine_threshold: float = 0.5,
    ) -> None:
        self._injection = injection_detector or PromptInjectionHeuristics()
        self._secrets = secret_detector or SecretDetector()
        self._injection_threshold = injection_quarantine_threshold
        self._authority_patterns = [
            re.compile(pat, re.IGNORECASE) for pat in AUTHORITY_ESCALATION_PATTERNS
        ]

    def inspect(self, response: ToolResponse) -> FirewallDecision:
        text = _content_to_text(response.content)
        injection = self._injection.scan_text(text)
        secret_scan = self._secrets.scan_text(text)
        authority_hits = [
            pattern.pattern for pattern in self._authority_patterns if pattern.search(text)
        ]

        provenance = list(response.provenance)
        if not provenance:
            provenance = [
                default_untrusted_provenance(
                    source_id=f"tool:{response.tool_name}",
                    source_type=SourceType.TOOL_OUTPUT,
                )
            ]

        signals: dict[str, Any] = {
            "risk": {
                "injection_score": injection.score,
                "injection_matches": injection.matches,
                "secret_detected": secret_scan.detected,
                "secret_types": secret_scan.types,
                "authority_escalation": len(authority_hits) > 0,
                "authority_matches": authority_hits,
            }
        }

        reasons: list[str] = []
        if injection.score >= self._injection_threshold:
            reasons.append(f"Tool output injection score {injection.score:.2f} exceeds threshold")
            return FirewallDecision(
                action=DecisionAction.QUARANTINE,
                content=_quarantine_content(text),
                allowed=False,
                reasons=reasons,
                matched_policies=["response_firewall:injection"],
                signals=signals,
                provenance=provenance,
                quarantined=True,
                explanation="Suspicious tool output quarantined due to injection patterns",
            )

        if authority_hits:
            reasons.append("Tool output attempts to grant new authority")
            return FirewallDecision(
                action=DecisionAction.QUARANTINE,
                content=_quarantine_content(text),
                allowed=False,
                reasons=reasons,
                matched_policies=["response_firewall:authority"],
                signals=signals,
                provenance=provenance,
                quarantined=True,
                explanation="Tool output blocked: authority escalation attempt",
            )

        sanitized = text
        action = DecisionAction.ALLOW
        if secret_scan.detected:
            sanitized = self._secrets.redact_text(text)
            action = DecisionAction.REDACT
            reasons.append(f"Secrets redacted from tool output: {', '.join(secret_scan.types)}")

        return FirewallDecision(
            action=action,
            content=sanitized,
            allowed=True,
            reasons=reasons or ["Tool output passed response firewall"],
            matched_policies=["response_firewall:pass"],
            signals=signals,
            provenance=provenance,
            explanation="; ".join(reasons) if reasons else "Output allowed",
        )


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        return " ".join(str(v) for v in content.values())
    if isinstance(content, list):
        return " ".join(str(item) for item in content)
    return str(content)


def _quarantine_content(text: str) -> str:
    return "[QUARANTINED: suspicious tool output withheld from agent context]"
