from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .detectors import ExternalIntentClassifier, PromptInjectionHeuristics
from .logger import SecurityLogger
from .models import DecisionAction, ToolCall, ToolDecision
from .policy import PolicyEngine
from .taint import collect_provenance, summarize_provenance


@dataclass
class MiddlewareContext:
    context_id: str
    system_prompt: str = ""
    developer_instructions: str = ""
    user_message: str = ""
    retrieved_text: str = ""
    tool_output: str = ""
    provenance: Dict[str, str] = field(default_factory=dict)


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: Dict[str, Callable[..., Any]] = {}
        self._sandbox_tools: Dict[str, Callable[..., Any]] = {}

    def register(self, name: str, func: Callable[..., Any], sandbox: Optional[Callable[..., Any]] = None) -> None:
        self._tools[name] = func
        if sandbox:
            self._sandbox_tools[name] = sandbox

    def get(self, name: str) -> Callable[..., Any]:
        if name not in self._tools:
            raise KeyError(f"Unknown tool: {name}")
        return self._tools[name]

    def get_sandbox(self, name: str) -> Optional[Callable[..., Any]]:
        return self._sandbox_tools.get(name)


class SecurityMiddleware:
    def __init__(
        self,
        policy: PolicyEngine,
        logger: Optional[SecurityLogger] = None,
        detectors: Optional[PromptInjectionHeuristics] = None,
        intent_classifier: Optional[ExternalIntentClassifier] = None,
    ) -> None:
        self._policy = policy
        self._logger = logger
        self._detectors = detectors or PromptInjectionHeuristics()
        self._intent = intent_classifier or ExternalIntentClassifier()

    def evaluate_tool_call(self, call: ToolCall, context: MiddlewareContext) -> ToolDecision:
        injection_signal = self._detectors.scan_payload(call.args)
        untrusted_text = " ".join([context.retrieved_text, context.tool_output]).strip()
        if untrusted_text:
            text_signal = self._detectors.scan_text(untrusted_text)
            injection_signal.score = max(injection_signal.score, text_signal.score)
            injection_signal.matches.extend(text_signal.matches)
            injection_signal.evidence.extend(text_signal.evidence)
        combined_text = " ".join(
            [
                context.user_message,
                context.retrieved_text,
                context.tool_output,
            ]
        )
        intent, intent_score = self._intent.classify(combined_text)
        combined_prov = collect_provenance(call.args) + list(call.provenance)
        taint_summary = summarize_provenance(combined_prov)
        untrusted_ratio = _untrusted_ratio(taint_summary)

        signals: Dict[str, Any] = {
            "injection_score": injection_signal.score,
            "injection_matches": injection_signal.matches,
            "injection_evidence": injection_signal.evidence,
            "intent": intent,
            "intent_score": intent_score,
            "untrusted_ratio": untrusted_ratio,
            "capabilities": self._policy.available_capabilities(call.tool_name),
        }

        valid, arg_reasons = self._policy.validate_args(call.tool_name, call.args)
        if not valid:
            decision = ToolDecision(
                action=DecisionAction.DENY,
                allowed=False,
                reasons=arg_reasons,
                matched_policies=["arg_constraints"],
                signals=signals,
                taint_summary=taint_summary,
            )
            self._write_log(call, decision)
            return decision

        decision = self._policy.evaluate(call, signals)
        self._write_log(call, decision)
        return decision

    def enforce(self, registry: ToolRegistry, call: ToolCall, context: MiddlewareContext) -> Tuple[ToolDecision, Any]:
        decision = self.evaluate_tool_call(call, context)
        if decision.action == DecisionAction.DENY:
            return decision, None
        tool = registry.get(call.tool_name)
        if decision.action == DecisionAction.SANDBOX:
            sandbox = registry.get_sandbox(call.tool_name)
            if sandbox:
                return decision, sandbox(**call.args)
        return decision, tool(**call.args)

    def _write_log(self, call: ToolCall, decision: ToolDecision) -> None:
        if self._logger:
            self._logger.log(call, decision)


def _untrusted_ratio(taint_summary: Dict[str, int]) -> float:
    untrusted = taint_summary.get("retrieved", 0) + taint_summary.get("tool_output", 0)
    total = sum(taint_summary.values())
    if total == 0:
        return 0.0
    return untrusted / total
