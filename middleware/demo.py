from __future__ import annotations

import json
from pathlib import Path

from .eval import Evaluator, load_scenarios_from_dir
from .logger import SecurityLogger
from .middleware import DefenseMode, MiddlewareContext, SecurityMiddleware, ToolRegistry
from .models import ToolCall, ToolResponse
from .policy import PolicyEngine


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    policy_path = root / "policies" / "default_policy.json"
    scenarios_dir = root / "examples" / "scenarios"
    log_path = root / "security_audit.jsonl"

    policy = PolicyEngine.from_file(str(policy_path))
    logger = SecurityLogger(str(log_path))
    registry = ToolRegistry.with_mock_tools()
    middleware = SecurityMiddleware(
        policy=policy,
        logger=logger,
        mode=DefenseMode.FULL_MIDDLEWARE,
    )

    scenarios = load_scenarios_from_dir(scenarios_dir)
    if not scenarios:
        _run_inline_demo(middleware, registry)
        return

    print("=== LLM Tool Security Middleware Demo ===\n")
    for scenario in scenarios[:3]:
        context = MiddlewareContext(
            context_id=scenario.tool_call.context_id,
            session_id=scenario.tool_call.session_id,
            user_goal=scenario.user_goal,
            user_message=scenario.user_message,
            retrieved_text=scenario.retrieved_text,
            tool_output=scenario.tool_output,
        )
        decision, output = middleware.enforce(registry, scenario.tool_call, context)
        print(f"Scenario: {scenario.name}")
        print(f"  Decision: {decision.action.value} (allowed={decision.allowed})")
        print(f"  Explanation: {decision.explanation}")
        if output:
            print(f"  Output: {output}")
        if scenario.inspect_response and scenario.response_content:
            sanitized = middleware.inspect_tool_response(
                ToolResponse(
                    tool_name=scenario.tool_call.tool_name,
                    content=scenario.response_content,
                    context_id=scenario.tool_call.context_id,
                )
            )
            print(f"  Firewall output: {sanitized}")
        print()

    evaluator = Evaluator(middleware, registry)
    report = evaluator.run(scenarios)
    print("Evaluation summary:")
    print(json.dumps(report["metrics"], indent=2))


def _run_inline_demo(middleware: SecurityMiddleware, registry: ToolRegistry) -> None:
    call = ToolCall(
        tool_name="search_web",
        args={"query": "public security report 2024"},
        requested_by="agent",
        context_id="demo",
        user_goal="Find public security reports",
    )
    context = MiddlewareContext(
        context_id="demo",
        user_goal="Find public security reports",
        user_message="Find recent public security reports.",
    )
    decision, output = middleware.enforce(registry, call, context)
    print(json.dumps({"decision": decision.action.value, "output": output}, indent=2))


if __name__ == "__main__":
    main()
