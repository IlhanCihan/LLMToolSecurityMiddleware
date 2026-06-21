from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .detectors import ExternalIntentClassifier, PromptInjectionHeuristics
from .logger import TOOL_CATEGORIES, SecurityLogger
from .mock_tools import MOCK_TOOLS, SANDBOX_TOOLS
from .models import DecisionAction, ToolCall, ToolDecision, ToolResponse
from .policy import PolicyEngine
from .response_firewall import ResponseFirewall
from .secrets import SecretDetector, SecretScanResult
from .taint import collect_provenance, has_untrusted_external, summarize_provenance, untrusted_ratio


class DefenseMode(str, Enum):
    NO_DEFENSE = "no_defense"
    REGEX_DETECTOR_ONLY = "regex_detector_only"
    ALLOWLIST_ONLY = "allowlist_only"
    POLICY_WITHOUT_TAINT = "policy_without_taint"
    FULL_MIDDLEWARE = "full_middleware"


@dataclass
class MiddlewareContext:
    context_id: str
    session_id: str = ""
    user_goal: str = ""
    system_prompt: str = ""
    developer_instructions: str = ""
    user_message: str = ""
    retrieved_text: str = ""
    tool_output: str = ""
    provenance: dict[str, str] = field(default_factory=dict)


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Callable[..., Any]] = {}
        self._sandbox_tools: dict[str, Callable[..., Any]] = {}

    def register(
        self,
        name: str,
        func: Callable[..., Any],
        sandbox: Callable[..., Any] | None = None,
    ) -> None:
        self._tools[name] = func
        if sandbox:
            self._sandbox_tools[name] = sandbox

    def get(self, name: str) -> Callable[..., Any]:
        if name not in self._tools:
            raise KeyError(f"Unknown tool: {name}")
        return self._tools[name]

    def get_sandbox(self, name: str) -> Callable[..., Any] | None:
        return self._sandbox_tools.get(name)

    @classmethod
    def with_mock_tools(cls) -> ToolRegistry:
        registry = cls()
        for name, func in MOCK_TOOLS.items():
            registry.register(name, func, sandbox=SANDBOX_TOOLS.get(name))
        return registry


class SecurityMiddleware:
    def __init__(
        self,
        policy: PolicyEngine | None = None,
        logger: SecurityLogger | None = None,
        detectors: PromptInjectionHeuristics | None = None,
        intent_classifier: ExternalIntentClassifier | None = None,
        secret_detector: SecretDetector | None = None,
        response_firewall: ResponseFirewall | None = None,
        mode: DefenseMode = DefenseMode.FULL_MIDDLEWARE,
    ) -> None:
        self._policy = policy
        self._logger = logger
        self._detectors = detectors or PromptInjectionHeuristics()
        self._intent = intent_classifier or ExternalIntentClassifier()
        self._secrets = secret_detector or SecretDetector()
        self._firewall = response_firewall or ResponseFirewall(secret_detector=self._secrets)
        self._mode = mode

    def evaluate_tool_call(
        self,
        call: ToolCall,
        context: MiddlewareContext,
    ) -> ToolDecision:
        start = time.perf_counter()
        if self._mode == DefenseMode.NO_DEFENSE:
            decision = ToolDecision(
                action=DecisionAction.ALLOW,
                allowed=True,
                reasons=["No defense mode enabled"],
                matched_policies=[],
                signals={},
                taint_summary={},
                explanation="Allowed without inspection (no_defense baseline)",
            )
            self._write_log(call, decision, start)
            return decision

        signals = self._build_signals(call, context)
        combined_prov = collect_provenance(call.args) + list(call.provenance)
        taint_summary = summarize_provenance(combined_prov)

        if self._mode == DefenseMode.REGEX_DETECTOR_ONLY:
            score = signals.get("risk", {}).get("injection_score", 0.0)
            if score >= 0.6:
                decision = ToolDecision(
                    action=DecisionAction.DENY,
                    allowed=False,
                    reasons=[f"Injection score {score:.2f} exceeds threshold"],
                    matched_policies=["regex_detector_only"],
                    signals=signals,
                    taint_summary=taint_summary,
                    explanation="Denied by regex detector baseline",
                )
            else:
                decision = ToolDecision(
                    action=DecisionAction.ALLOW,
                    allowed=True,
                    reasons=["Passed regex detector"],
                    matched_policies=["regex_detector_only"],
                    signals=signals,
                    taint_summary=taint_summary,
                    explanation="Allowed by regex detector baseline",
                )
            self._write_log(call, decision, start)
            return decision

        if self._mode == DefenseMode.ALLOWLIST_ONLY:
            assert self._policy is not None
            if self._policy.is_tool_allowed(call.tool_name):
                decision = ToolDecision(
                    action=DecisionAction.ALLOW,
                    allowed=True,
                    reasons=["Tool on allowlist"],
                    matched_policies=["allowlist_only"],
                    signals=signals,
                    taint_summary=taint_summary,
                    explanation="Allowed by tool allowlist baseline",
                )
            else:
                decision = ToolDecision(
                    action=DecisionAction.DENY,
                    allowed=False,
                    reasons=[f"Tool {call.tool_name} not on allowlist"],
                    matched_policies=["allowlist_only"],
                    signals=signals,
                    taint_summary=taint_summary,
                    explanation="Denied: tool not on allowlist",
                )
            self._write_log(call, decision, start)
            return decision

        assert self._policy is not None
        valid, arg_reasons = self._policy.validate_args(call.tool_name, call.args)
        if not valid:
            decision = ToolDecision(
                action=DecisionAction.DENY,
                allowed=False,
                reasons=arg_reasons,
                matched_policies=["capability_constraints"],
                signals=signals,
                taint_summary=taint_summary,
                explanation="; ".join(arg_reasons),
            )
            self._write_log(call, decision, start)
            return decision

        skip_taint = self._mode == DefenseMode.POLICY_WITHOUT_TAINT
        decision = self._policy.evaluate(call, signals, skip_taint=skip_taint)

        if decision.action == DecisionAction.REDACT:
            decision.sanitized_args = self._secrets.redact_payload(call.args)
        if decision.action == DecisionAction.ALLOW_WITH_TRANSFORM:
            decision.sanitized_args = self._transform_args(call.args)

        self._write_log(call, decision, start)
        return decision

    def enforce(
        self,
        registry: ToolRegistry,
        call: ToolCall,
        context: MiddlewareContext,
    ) -> tuple[ToolDecision, Any]:
        decision = self.evaluate_tool_call(call, context)
        if not decision.allowed:
            return decision, None

        args = decision.sanitized_args or call.args
        if decision.action == DecisionAction.SANDBOX:
            sandbox = registry.get_sandbox(call.tool_name)
            if sandbox:
                return decision, sandbox(**args)

        tool = registry.get(call.tool_name)
        return decision, tool(**args)

    def inspect_tool_response(self, response: ToolResponse) -> Any:
        firewall_decision = self._firewall.inspect(response)
        if firewall_decision.quarantined or not firewall_decision.allowed:
            return firewall_decision.content
        return firewall_decision.content

    def _build_signals(
        self,
        call: ToolCall,
        context: MiddlewareContext,
    ) -> dict[str, Any]:
        injection_signal = self._detectors.scan_payload(call.args)
        context_text = " ".join([context.retrieved_text, context.tool_output]).strip()
        context_signal = (
            self._detectors.scan_text(context_text) if context_text else injection_signal
        )
        combined_score = max(injection_signal.score, context_signal.score)
        combined_matches = injection_signal.matches + context_signal.matches
        combined_evidence = injection_signal.evidence + context_signal.evidence

        combined_text = " ".join(
            [context.user_message, context.retrieved_text, context.tool_output]
        )
        intent, intent_score = self._intent.classify(combined_text)
        combined_prov = collect_provenance(call.args) + list(call.provenance)
        taint_summary = summarize_provenance(combined_prov)
        secret_scan = self._scan_secrets_for_policy(call.tool_name, call.args)
        category = TOOL_CATEGORIES.get(call.tool_name)
        capabilities: list[str] = []
        if self._policy:
            capabilities = self._policy.available_capabilities(call.tool_name)

        return {
            "injection_score": combined_score,
            "injection_matches": combined_matches,
            "injection_evidence": combined_evidence,
            "intent": intent,
            "intent_score": intent_score,
            "untrusted_ratio": untrusted_ratio(taint_summary),
            "capabilities": capabilities,
            "risk": {
                "injection_score": injection_signal.score,
                "context_injection_score": context_signal.score,
                "combined_injection_score": combined_score,
                "secret_detected": secret_scan.detected,
                "secret_types": secret_scan.types,
                "intent": intent,
                "intent_score": intent_score,
            },
            "tool": {
                "name": call.tool_name,
                "category": category.value if category else "unknown",
            },
            "taint": {
                **taint_summary,
                "untrusted_ratio": untrusted_ratio(taint_summary),
                "has_untrusted": has_untrusted_external(taint_summary),
            },
        }

    def _scan_secrets_for_policy(self, tool_name: str, args: dict[str, Any]) -> SecretScanResult:
        filtered = dict(args)
        if tool_name in {"send_email", "draft_email"}:
            filtered.pop("to", None)
        return self._secrets.scan_payload(filtered)

    def _transform_args(self, args: dict[str, Any]) -> dict[str, Any]:
        transformed = self._secrets.redact_payload(args)
        return transformed

    def _write_log(
        self,
        call: ToolCall,
        decision: ToolDecision,
        start: float,
    ) -> None:
        if self._logger:
            latency_ms = (time.perf_counter() - start) * 1000
            self._logger.log(call, decision, latency_ms=latency_ms)
