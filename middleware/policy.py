from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .models import DecisionAction, ToolCall, ToolDecision
from .taint import collect_provenance, summarize_provenance


@dataclass
class PolicyRule:
    rule_id: str
    effect: DecisionAction
    tool: Optional[str] = None
    max_injection_score: Optional[float] = None
    max_untrusted_ratio: Optional[float] = None
    require_intent: Optional[str] = None
    require_capability: Optional[str] = None

    def matches(self, call: ToolCall, signals: Dict[str, Any]) -> bool:
        if self.tool and self.tool != call.tool_name:
            return False
        if self.max_injection_score is not None:
            if signals.get("injection_score", 0.0) > self.max_injection_score:
                return False
        if self.max_untrusted_ratio is not None:
            if signals.get("untrusted_ratio", 0.0) > self.max_untrusted_ratio:
                return False
        if self.require_intent and signals.get("intent") != self.require_intent:
            return False
        if self.require_capability:
            if self.require_capability not in signals.get("capabilities", []):
                return False
        return True


@dataclass
class Capability:
    name: str
    tools: List[str]
    arg_constraints: Dict[str, Dict[str, Any]]


class PolicyEngine:
    def __init__(self, policy: Dict[str, Any]) -> None:
        self._policy = policy
        self._rules = [self._parse_rule(rule) for rule in policy.get("rules", [])]
        self._capabilities = [self._parse_capability(cap) for cap in policy.get("capabilities", [])]
        self._default_action = DecisionAction(policy.get("default_action", "deny"))

    @classmethod
    def from_file(cls, path: str) -> "PolicyEngine":
        import json

        with open(path, "r", encoding="utf-8") as handle:
            policy = json.load(handle)
        return cls(policy)

    def evaluate(self, call: ToolCall, signals: Dict[str, Any]) -> ToolDecision:
        combined_prov = collect_provenance(call.args) + list(call.provenance)
        taint_summary = summarize_provenance(combined_prov)
        matched: List[str] = []
        reasons: List[str] = []

        for rule in self._rules:
            if rule.matches(call, signals):
                matched.append(rule.rule_id)
                reasons.append(f"Matched rule {rule.rule_id} -> {rule.effect.value}")
                if rule.effect == DecisionAction.DENY:
                    return ToolDecision(
                        action=DecisionAction.DENY,
                        allowed=False,
                        reasons=reasons,
                        matched_policies=matched,
                        signals=signals,
                        taint_summary=taint_summary,
                    )
                if rule.effect == DecisionAction.SANDBOX:
                    return ToolDecision(
                        action=DecisionAction.SANDBOX,
                        allowed=True,
                        reasons=reasons,
                        matched_policies=matched,
                        signals=signals,
                        taint_summary=taint_summary,
                    )

        allow_rule = self._first_allow_rule(call, signals)
        if allow_rule:
            matched.append(allow_rule.rule_id)
            reasons.append(f"Matched rule {allow_rule.rule_id} -> allow")
            return ToolDecision(
                action=DecisionAction.ALLOW,
                allowed=True,
                reasons=reasons,
                matched_policies=matched,
                signals=signals,
                taint_summary=taint_summary,
            )

        return ToolDecision(
            action=self._default_action,
            allowed=self._default_action != DecisionAction.DENY,
            reasons=["No allow rule matched; using default action"],
            matched_policies=matched,
            signals=signals,
            taint_summary=taint_summary,
        )

    def available_capabilities(self, tool_name: str) -> List[str]:
        caps = []
        for cap in self._capabilities:
            if tool_name in cap.tools:
                caps.append(cap.name)
        return caps

    def validate_args(self, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, List[str]]:
        reasons: List[str] = []
        for cap in self._capabilities:
            if tool_name not in cap.tools:
                continue
            for arg_name, constraint in cap.arg_constraints.items():
                if arg_name not in args:
                    if constraint.get("required", False):
                        reasons.append(f"Missing required arg {arg_name} for {cap.name}")
                    continue
                if "type" in constraint:
                    if not _validate_type(args[arg_name], constraint["type"]):
                        reasons.append(f"Arg {arg_name} fails type constraint {constraint['type']}")
                if "max_len" in constraint and isinstance(args[arg_name], str):
                    if len(args[arg_name]) > constraint["max_len"]:
                        reasons.append(f"Arg {arg_name} exceeds max_len {constraint['max_len']}")
        return len(reasons) == 0, reasons

    def _first_allow_rule(self, call: ToolCall, signals: Dict[str, Any]) -> Optional[PolicyRule]:
        for rule in self._rules:
            if rule.effect != DecisionAction.ALLOW:
                continue
            if rule.matches(call, signals):
                return rule
        return None

    @staticmethod
    def _parse_rule(raw: Dict[str, Any]) -> PolicyRule:
        return PolicyRule(
            rule_id=raw["id"],
            effect=DecisionAction(raw["effect"]),
            tool=raw.get("tool"),
            max_injection_score=raw.get("max_injection_score"),
            max_untrusted_ratio=raw.get("max_untrusted_ratio"),
            require_intent=raw.get("require_intent"),
            require_capability=raw.get("require_capability"),
        )

    @staticmethod
    def _parse_capability(raw: Dict[str, Any]) -> Capability:
        return Capability(
            name=raw["name"],
            tools=raw.get("tools", []),
            arg_constraints=raw.get("arg_constraints", {}),
        )


def _validate_type(value: Any, expected: str) -> bool:
    types = {
        "str": str,
        "int": int,
        "float": float,
        "bool": bool,
        "dict": dict,
        "list": list,
    }
    if expected not in types:
        return True
    return isinstance(value, types[expected])
