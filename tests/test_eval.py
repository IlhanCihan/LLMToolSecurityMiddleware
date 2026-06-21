from __future__ import annotations

from pathlib import Path

import pytest

from middleware.eval import Evaluator, load_scenarios_from_dir
from middleware.middleware import DefenseMode, SecurityMiddleware, ToolRegistry
from middleware.policy import PolicyEngine

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def scenarios():
    return load_scenarios_from_dir(ROOT / "examples" / "scenarios")


@pytest.fixture
def full_middleware() -> SecurityMiddleware:
    policy = PolicyEngine.from_file(str(ROOT / "policies" / "default_policy.json"))
    return SecurityMiddleware(policy=policy, mode=DefenseMode.FULL_MIDDLEWARE)


def test_load_all_scenarios(scenarios) -> None:
    assert len(scenarios) >= 7
    names = {scenario.name for scenario in scenarios}
    assert "safe-search" in names
    assert "benign-security-article" in names


def test_full_middleware_evaluation(scenarios, full_middleware) -> None:
    registry = ToolRegistry.with_mock_tools()
    evaluator = Evaluator(full_middleware, registry)
    results = evaluator.run(scenarios)
    metrics = results["metrics"]
    assert metrics["total_scenarios"] == len(scenarios)
    assert metrics["benign_task_success_rate"] >= 0.5
    assert all("latency_ms" in detail for detail in results["details"])


@pytest.mark.parametrize("mode", list(DefenseMode))
def test_baseline_modes_run(mode: DefenseMode, scenarios) -> None:
    policy_path = ROOT / "policies" / "default_policy.json"
    if mode == DefenseMode.NO_DEFENSE:
        middleware = SecurityMiddleware(mode=mode)
    else:
        policy = PolicyEngine.from_file(str(policy_path))
        middleware = SecurityMiddleware(policy=policy, mode=mode)
    registry = ToolRegistry.with_mock_tools()
    evaluator = Evaluator(middleware, registry)
    results = evaluator.run(scenarios[:2])
    assert "attack_success_rate" in results["metrics"]
