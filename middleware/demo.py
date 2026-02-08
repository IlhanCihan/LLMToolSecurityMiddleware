from __future__ import annotations

import json
from pathlib import Path

from .eval import Evaluator, build_scenarios
from .logger import SecurityLogger
from .middleware import SecurityMiddleware, ToolRegistry
from .policy import PolicyEngine


def tool_search(query: str) -> str:
    return f"search results for: {query}"


def tool_file_write(path: str, content: str) -> str:
    return f"wrote {len(content)} bytes to {path}"


def sandbox_file_write(path: str, content: str) -> str:
    redacted = content[:20] + "...[redacted]"
    return f"sandboxed write to {path}: {redacted}"


def main() -> None:
    policy_path = Path(__file__).resolve().parents[1] / "policies" / "default_policy.json"
    policy = PolicyEngine.from_file(str(policy_path))
    logger = SecurityLogger(str(Path("security_audit.jsonl")))

    registry = ToolRegistry()
    registry.register("search", tool_search)
    registry.register("file_write", tool_file_write, sandbox=sandbox_file_write)

    middleware = SecurityMiddleware(policy=policy, logger=logger)

    evaluator = Evaluator(middleware, registry)
    report = evaluator.run(build_scenarios())
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
