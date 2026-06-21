from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .models import DecisionAction, ToolCall, ToolDecision
from .secrets import SecretDetector
from .taint import collect_provenance, summarize_provenance, untrusted_ratio

OPERATORS = frozenset({"eq", "neq", "gt", "gte", "lt", "lte", "in", "not_in", "contains", "regex"})


@dataclass
class PolicyRule:
    rule_id: str
    effect: DecisionAction
    when: dict[str, dict[str, Any]] = field(default_factory=dict)
    priority: int = 100

    def matches(self, context: dict[str, Any]) -> bool:
        if not self.when:
            return True
        return all(_evaluate_condition(path, spec, context) for path, spec in self.when.items())


@dataclass
class Capability:
    name: str
    tools: list[str]
    read_only: bool = False
    write: bool = False
    allowed_path_prefixes: list[str] = field(default_factory=list)
    blocked_path_patterns: list[str] = field(default_factory=list)
    max_argument_length: dict[str, int] = field(default_factory=dict)
    required_fields: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)
    blocked_external_destinations: list[str] = field(default_factory=list)
    no_secrets_in_arguments: bool = False
    arg_constraints: dict[str, dict[str, Any]] = field(default_factory=dict)


class PolicyEngine:
    def __init__(
        self, policy: dict[str, Any], secret_detector: SecretDetector | None = None
    ) -> None:
        self._policy = policy
        self._secret_detector = secret_detector or SecretDetector()
        self._rules = sorted(
            [self._parse_rule(rule) for rule in policy.get("rules", [])],
            key=lambda rule: rule.priority,
        )
        self._capabilities = [self._parse_capability(cap) for cap in policy.get("capabilities", [])]
        self._default_action = DecisionAction(policy.get("default_action", "deny"))
        self._tool_allowlist = policy.get("tool_allowlist", [])

    @classmethod
    def from_file(cls, path: str) -> PolicyEngine:
        import json

        with open(path, encoding="utf-8") as handle:
            policy = json.load(handle)
        return cls(policy)

    def evaluate(
        self,
        call: ToolCall,
        signals: dict[str, Any],
        *,
        skip_taint: bool = False,
    ) -> ToolDecision:
        combined_prov = collect_provenance(call.args) + list(call.provenance)
        taint_summary = summarize_provenance(combined_prov)
        if skip_taint:
            taint_summary = {"total": 0, "trust": {}, "source_types": {}}

        context = _build_context(call, signals, taint_summary)
        matched: list[str] = []
        reasons: list[str] = []

        for rule in self._rules:
            if not rule.matches(context):
                continue
            matched.append(rule.rule_id)
            reasons.append(f"Matched rule {rule.rule_id} -> {rule.effect.value}")
            decision = _decision_from_effect(
                rule.effect,
                reasons,
                matched,
                signals,
                taint_summary,
            )
            if decision is not None:
                decision.explanation = "; ".join(reasons)
                return decision

        default_allowed = self._default_action not in {
            DecisionAction.DENY,
            DecisionAction.QUARANTINE,
        }
        return ToolDecision(
            action=self._default_action,
            allowed=default_allowed,
            reasons=["No matching rule; applying default-deny policy"],
            matched_policies=matched,
            signals=signals,
            taint_summary=taint_summary,
            explanation="Default deny: no explicit allow rule matched",
            requires_approval=self._default_action == DecisionAction.REQUIRE_APPROVAL,
            quarantined=self._default_action == DecisionAction.QUARANTINE,
        )

    def available_capabilities(self, tool_name: str) -> list[str]:
        return [cap.name for cap in self._capabilities if tool_name in cap.tools]

    def is_tool_allowed(self, tool_name: str) -> bool:
        if not self._tool_allowlist:
            return True
        return tool_name in self._tool_allowlist

    def validate_args(
        self,
        tool_name: str,
        args: dict[str, Any],
    ) -> tuple[bool, list[str]]:
        reasons: list[str] = []
        applicable = [cap for cap in self._capabilities if tool_name in cap.tools]
        if not applicable:
            return True, reasons

        for cap in applicable:
            reasons.extend(self._validate_capability(cap, tool_name, args))
        return len(reasons) == 0, reasons

    def _validate_capability(
        self,
        cap: Capability,
        tool_name: str,
        args: dict[str, Any],
    ) -> list[str]:
        reasons: list[str] = []
        for field_name in cap.required_fields:
            if field_name not in args or args[field_name] in ("", None):
                reasons.append(f"Missing required field {field_name} for {cap.name}")

        for arg_name, max_len in cap.max_argument_length.items():
            value = args.get(arg_name)
            if isinstance(value, str) and len(value) > max_len:
                reasons.append(f"Arg {arg_name} exceeds max length {max_len} for {cap.name}")

        for arg_name, constraint in cap.arg_constraints.items():
            if arg_name not in args:
                if constraint.get("required", False):
                    reasons.append(f"Missing required arg {arg_name} for {cap.name}")
                continue
            value = args[arg_name]
            if "type" in constraint and not _validate_type(value, constraint["type"]):
                reasons.append(f"Arg {arg_name} fails type constraint {constraint['type']}")
            max_len = constraint.get("max_len")
            if max_len is not None and isinstance(value, str) and len(value) > max_len:
                reasons.append(f"Arg {arg_name} exceeds max_len {max_len}")

        path_value = args.get("path")
        if isinstance(path_value, str):
            reasons.extend(self._validate_path(cap, path_value))

        url_value = args.get("url") or args.get("to") or args.get("recipient")
        if isinstance(url_value, str):
            reasons.extend(self._validate_destination(cap, url_value, cap.write))

        if cap.no_secrets_in_arguments:
            scan = self._secret_detector.scan_payload(args)
            if scan.detected:
                reasons.append(
                    f"Secrets detected in arguments for {cap.name}: {', '.join(scan.types)}"
                )

        if cap.read_only and cap.write:
            reasons.append(f"Capability {cap.name} cannot be both read_only and write")

        return reasons

    def _validate_path(self, cap: Capability, path: str) -> list[str]:
        reasons: list[str] = []
        if cap.allowed_path_prefixes:
            if not any(path.startswith(prefix) for prefix in cap.allowed_path_prefixes):
                reasons.append(f"Path {path} not under allowed prefixes for {cap.name}")
        for pattern in cap.blocked_path_patterns:
            if re.search(pattern, path):
                reasons.append(f"Path {path} matches blocked pattern for {cap.name}")
        return reasons

    def _validate_destination(
        self,
        cap: Capability,
        destination: str,
        is_write: bool = False,
    ) -> list[str]:
        reasons: list[str] = []
        for blocked in cap.blocked_external_destinations:
            if blocked in destination:
                reasons.append(
                    f"Destination {destination} matches blocked destination for {cap.name}"
                )
        if cap.allowed_domains and not is_write:
            if not any(domain in destination for domain in cap.allowed_domains):
                reasons.append(f"Destination {destination} not in allowed domains for {cap.name}")
        return reasons

    @staticmethod
    def _parse_rule(raw: dict[str, Any]) -> PolicyRule:
        return PolicyRule(
            rule_id=raw["id"],
            effect=DecisionAction(raw["effect"]),
            when=raw.get("when", {}),
            priority=raw.get("priority", 100),
        )

    @staticmethod
    def _parse_capability(raw: dict[str, Any]) -> Capability:
        return Capability(
            name=raw["name"],
            tools=raw.get("tools", []),
            read_only=raw.get("read_only", False),
            write=raw.get("write", False),
            allowed_path_prefixes=raw.get("allowed_path_prefixes", []),
            blocked_path_patterns=raw.get("blocked_path_patterns", []),
            max_argument_length=raw.get("max_argument_length", {}),
            required_fields=raw.get("required_fields", []),
            allowed_domains=raw.get("allowed_domains", []),
            blocked_external_destinations=raw.get("blocked_external_destinations", []),
            no_secrets_in_arguments=raw.get("no_secrets_in_arguments", False),
            arg_constraints=raw.get("arg_constraints", {}),
        )


def _build_context(
    call: ToolCall,
    signals: dict[str, Any],
    taint_summary: dict[str, Any],
) -> dict[str, Any]:
    return {
        "tool": {
            "name": call.tool_name,
            "category": signals.get("tool", {}).get("category", "unknown"),
        },
        "risk": signals.get("risk", {}),
        "taint": {
            **taint_summary,
            "untrusted_ratio": untrusted_ratio(taint_summary),
            "has_untrusted": untrusted_ratio(taint_summary) > 0,
        },
        "capabilities": signals.get("capabilities", []),
        "intent": signals.get("intent", "unknown"),
        "intent_score": signals.get("intent_score", 0.0),
    }


def _decision_from_effect(
    effect: DecisionAction,
    reasons: list[str],
    matched: list[str],
    signals: dict[str, Any],
    taint_summary: dict[str, Any],
) -> ToolDecision | None:
    blocking = {
        DecisionAction.DENY,
        DecisionAction.QUARANTINE,
    }
    approval = {DecisionAction.REQUIRE_APPROVAL}
    allowing = {
        DecisionAction.ALLOW,
        DecisionAction.SANDBOX,
        DecisionAction.REDACT,
        DecisionAction.ALLOW_WITH_TRANSFORM,
    }

    if effect in blocking:
        return ToolDecision(
            action=effect,
            allowed=False,
            reasons=reasons,
            matched_policies=matched,
            signals=signals,
            taint_summary=taint_summary,
            quarantined=effect == DecisionAction.QUARANTINE,
        )
    if effect in approval:
        return ToolDecision(
            action=effect,
            allowed=False,
            reasons=reasons,
            matched_policies=matched,
            signals=signals,
            taint_summary=taint_summary,
            requires_approval=True,
        )
    if effect in allowing:
        return ToolDecision(
            action=effect,
            allowed=True,
            reasons=reasons,
            matched_policies=matched,
            signals=signals,
            taint_summary=taint_summary,
        )
    return None


def _evaluate_condition(path: str, spec: dict[str, Any], context: dict[str, Any]) -> bool:
    actual = _resolve_path(context, path)
    for operator, expected in spec.items():
        if operator not in OPERATORS:
            continue
        if not _apply_operator(operator, actual, expected):
            return False
    return True


def _resolve_path(context: dict[str, Any], path: str) -> Any:
    current: Any = context
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _apply_operator(operator: str, actual: Any, expected: Any) -> bool:
    if operator == "eq":
        return actual == expected
    if operator == "neq":
        return actual != expected
    if operator == "gt":
        return _compare(actual, expected, lambda a, b: a > b)
    if operator == "gte":
        return _compare(actual, expected, lambda a, b: a >= b)
    if operator == "lt":
        return _compare(actual, expected, lambda a, b: a < b)
    if operator == "lte":
        return _compare(actual, expected, lambda a, b: a <= b)
    if operator == "in":
        if isinstance(expected, list):
            return actual in expected
        return False
    if operator == "not_in":
        if isinstance(expected, list):
            return actual not in expected
        return True
    if operator == "contains":
        if isinstance(actual, str) and isinstance(expected, str):
            return expected in actual
        if isinstance(actual, list):
            return expected in actual
        return False
    if operator == "regex":
        if not isinstance(actual, str) or not isinstance(expected, str):
            return False
        return re.search(expected, actual) is not None
    return False


def _compare(actual: Any, expected: Any, op: Any) -> bool:
    if actual is None or expected is None:
        return False
    try:
        return bool(op(actual, expected))
    except TypeError:
        return False


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
