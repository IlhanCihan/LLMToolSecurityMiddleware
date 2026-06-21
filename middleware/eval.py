from __future__ import annotations

import argparse
import csv
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .middleware import DefenseMode, MiddlewareContext, SecurityMiddleware, ToolRegistry
from .models import (
    ConfidentialityLevel,
    DataProvenance,
    IntegrityLevel,
    SourceType,
    ToolCall,
    ToolResponse,
    TransformType,
    TrustLevel,
)
from .policy import PolicyEngine
from .response_firewall import ResponseFirewall


@dataclass
class Scenario:
    name: str
    description: str
    user_goal: str
    user_message: str
    retrieved_text: str
    tool_output: str
    tool_call: ToolCall
    expect_allowed: bool
    expect_action: str | None = None
    is_attack: bool = False
    inspect_response: bool = False
    response_content: str = ""


class Evaluator:
    def __init__(
        self,
        middleware: SecurityMiddleware,
        registry: ToolRegistry,
        *,
        response_firewall: ResponseFirewall | None = None,
    ) -> None:
        self._middleware = middleware
        self._registry = registry
        self._firewall = response_firewall or ResponseFirewall()

    def run(self, scenarios: list[Scenario]) -> dict[str, Any]:
        details: list[dict[str, Any]] = []
        latencies: list[float] = []

        for scenario in scenarios:
            start = time.perf_counter()
            context = MiddlewareContext(
                context_id=scenario.tool_call.context_id,
                session_id=scenario.tool_call.session_id,
                user_goal=scenario.user_goal or scenario.user_message,
                user_message=scenario.user_message,
                retrieved_text=scenario.retrieved_text,
                tool_output=scenario.tool_output,
            )
            decision, output = self._middleware.enforce(
                self._registry,
                scenario.tool_call,
                context,
            )
            elapsed_ms = (time.perf_counter() - start) * 1000
            latencies.append(elapsed_ms)

            response_quarantined = False
            if scenario.inspect_response and scenario.response_content:
                fw = self._firewall.inspect(
                    ToolResponse(
                        tool_name=scenario.tool_call.tool_name,
                        content=scenario.response_content,
                        session_id=scenario.tool_call.session_id,
                        context_id=scenario.tool_call.context_id,
                    )
                )
                response_quarantined = fw.quarantined

            success = decision.allowed == scenario.expect_allowed
            if scenario.expect_action:
                success = success and decision.action.value == scenario.expect_action

            details.append(
                {
                    "name": scenario.name,
                    "description": scenario.description,
                    "allowed": decision.allowed,
                    "action": decision.action.value,
                    "expected_allowed": scenario.expect_allowed,
                    "expected_action": scenario.expect_action,
                    "success": success,
                    "is_attack": scenario.is_attack,
                    "matched_policies": decision.matched_policies,
                    "signals": decision.signals,
                    "response_quarantined": response_quarantined,
                    "latency_ms": round(elapsed_ms, 2),
                    "output": str(output) if output is not None else None,
                }
            )

        return {
            "metrics": self._compute_metrics(details, latencies),
            "details": details,
        }

    @staticmethod
    def _compute_metrics(details: list[dict[str, Any]], latencies: list[float]) -> dict[str, Any]:
        attacks = [d for d in details if d["is_attack"]]
        benign = [d for d in details if not d["is_attack"]]

        attack_success = sum(1 for d in attacks if d["allowed"]) / len(attacks) if attacks else 0.0
        benign_success = sum(1 for d in benign if d["allowed"]) / len(benign) if benign else 0.0
        false_allows = sum(1 for d in attacks if d["allowed"] and d["expected_allowed"] is False)
        false_blocks = sum(1 for d in benign if not d["allowed"] and d["expected_allowed"] is True)
        total = len(details) or 1

        return {
            "attack_success_rate": round(attack_success, 4),
            "benign_task_success_rate": round(benign_success, 4),
            "false_allow_rate": round(false_allows / total, 4),
            "false_block_rate": round(false_blocks / total, 4),
            "approval_rate": round(
                sum(1 for d in details if d["action"] == "require_approval") / total,
                4,
            ),
            "sandbox_rate": round(
                sum(1 for d in details if d["action"] == "sandbox") / total,
                4,
            ),
            "latency_overhead_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0.0,
            "accuracy": round(sum(1 for d in details if d["success"]) / total, 4),
            "total_scenarios": len(details),
        }


def load_scenarios_from_dir(directory: Path) -> list[Scenario]:
    scenarios: list[Scenario] = []
    for path in sorted(directory.glob("*.json")):
        scenarios.append(load_scenario_file(path))
    return scenarios


def load_scenario_file(path: Path) -> Scenario:
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)

    provenance = [
        DataProvenance(
            source_id=item.get("source_id", "unknown"),
            source_type=SourceType(item.get("source_type", "user")),
            trust=TrustLevel(item.get("trust", "unknown")),
            confidentiality=ConfidentialityLevel(item.get("confidentiality", "public")),
            integrity=IntegrityLevel(item.get("integrity", "unknown")),
            transforms=tuple(TransformType(t) for t in item.get("transforms", [])),
            description=item.get("description", ""),
        )
        for item in raw.get("provenance", [])
    ]

    tool_call_raw = raw["tool_call"]
    tool_call = ToolCall(
        tool_name=tool_call_raw["tool_name"],
        args=tool_call_raw.get("args", {}),
        requested_by=tool_call_raw.get("requested_by", "agent"),
        context_id=tool_call_raw.get("context_id", raw["name"]),
        session_id=raw.get("session_id", raw["name"]),
        user_goal=raw.get("user_goal", raw.get("user_message", "")),
        provenance=provenance,
    )

    return Scenario(
        name=raw["name"],
        description=raw.get("description", ""),
        user_goal=raw.get("user_goal", ""),
        user_message=raw.get("user_message", ""),
        retrieved_text=raw.get("retrieved_text", ""),
        tool_output=raw.get("tool_output", ""),
        tool_call=tool_call,
        expect_allowed=raw.get("expect_allowed", False),
        expect_action=raw.get("expect_action"),
        is_attack=raw.get("is_attack", False),
        inspect_response=raw.get("inspect_response", False),
        response_content=raw.get("response_content", ""),
    )


def build_middleware(mode: DefenseMode, policy_path: Path) -> SecurityMiddleware:
    if mode == DefenseMode.NO_DEFENSE:
        return SecurityMiddleware(mode=mode)
    policy = PolicyEngine.from_file(str(policy_path))
    return SecurityMiddleware(policy=policy, mode=mode)


def write_results(results: dict[str, Any], output_dir: Path, mode: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"eval_{mode}.json"
    csv_path = output_dir / f"eval_{mode}.csv"

    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)

    with open(csv_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "name",
                "allowed",
                "action",
                "expected_allowed",
                "success",
                "is_attack",
                "latency_ms",
            ],
        )
        writer.writeheader()
        for row in results["details"]:
            writer.writerow(
                {
                    "name": row["name"],
                    "allowed": row["allowed"],
                    "action": row["action"],
                    "expected_allowed": row["expected_allowed"],
                    "success": row["success"],
                    "is_attack": row["is_attack"],
                    "latency_ms": row["latency_ms"],
                }
            )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run middleware evaluation scenarios")
    parser.add_argument(
        "--mode",
        choices=[m.value for m in DefenseMode],
        default=DefenseMode.FULL_MIDDLEWARE.value,
    )
    parser.add_argument(
        "--scenarios",
        type=Path,
        default=Path("examples/scenarios"),
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path("policies/default_policy.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results"),
    )
    args = parser.parse_args()

    mode = DefenseMode(args.mode)
    scenarios = load_scenarios_from_dir(args.scenarios)
    middleware = build_middleware(mode, args.policy)
    registry = ToolRegistry.with_mock_tools()
    evaluator = Evaluator(middleware, registry)
    results = evaluator.run(scenarios)
    results["mode"] = mode.value
    write_results(results, args.output, mode.value)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
