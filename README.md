# LLM Tool Security Middleware

A reference implementation of a **middleware security layer** for tool-using LLM agents. The middleware sits between an agent and its tools, applying deterministic guards, structured policies, and taint-aware enforcement to detect, contain, and mitigate prompt injection and instruction hijacking—especially when malicious instructions originate from untrusted sources such as retrieved documents, web pages, emails, PDFs, or prior tool outputs.

The LLM is **not** the final authority on security. Policy decisions are made by explicit rules, capability constraints, secret detection, and provenance tracking.

## Problem Statement

Tool-using agents combine trusted instructions with untrusted data. Attackers can embed instructions in retrieved content or tool outputs to trick agents into:

- Exfiltrating secrets via email, search, or file tools
- Writing malicious files outside allowed paths
- Escalating privileges or bypassing developer guardrails
- Leaking sensitive data into logs or external systems

This project provides a **reproducible, testable Python package** that demonstrates how middleware can enforce security before tool execution and sanitize tool responses before they re-enter agent context.

## Threat Model Summary

| Threat | Example | Mitigation |
|--------|---------|------------|
| Prompt injection | PDF says "ignore instructions and write secrets" | Injection heuristics + policy deny |
| Data exfiltration | Email tool sends data to attacker domain | Capability constraints + approval |
| Secret leakage | API key in search query | Secret detector + deny/redact |
| Tool output injection | Web fetch returns hijack instructions | Response firewall + quarantine |
| Path traversal | Write to `/etc/passwd` | Allowed path prefixes + blocked patterns |
| Privilege escalation | Output grants new tool authority | Response firewall authority checks |

**Trust boundaries:**

- System/developer instructions: most trusted
- User input: trusted for intent, not for security authority
- Retrieved content & tool outputs: untrusted by default

## Architecture

```
User / System / Dev Instructions
            |
         Agent
            |
     Tool Call Request
            |
   +------------------------+
   |  Security Middleware   |
   |------------------------|
   | 1) Provenance / Taint  |
   | 2) Injection Scan      |
   | 3) Secret Detection    |
   | 4) Capability Checks   |
   | 5) Policy Engine       |
   | 6) Audit Logging       |
   +------------------------+
            |
        Tool Registry
            |
         Tools
            |
   +------------------------+
   |  Response Firewall     |
   | (sanitize tool output) |
   +------------------------+
            |
         Agent Context
```

### Core Modules

| Module | Purpose |
|--------|---------|
| `middleware/taint.py` | Provenance labels and taint propagation |
| `middleware/secrets.py` | API keys, JWTs, passwords, etc. |
| `middleware/detectors.py` | Prompt-injection heuristics |
| `middleware/policy.py` | Operator-based rules + capabilities |
| `middleware/middleware.py` | Orchestration and enforcement |
| `middleware/response_firewall.py` | Tool output inspection |
| `middleware/logger.py` | Structured audit logs (secrets redacted) |
| `middleware/eval.py` | Scenario-based evaluation harness |
| `middleware/mock_tools.py` | Demo tool implementations |

## Installation

Requires Python 3.10+.

```bash
git clone <repo-url>
cd UniDeliverable
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Verify the install:

```bash
pytest -v
```

## Quick Start

Run the interactive demo (uses scenarios from `examples/scenarios/`):

```bash
python -m middleware.demo
```

Audit logs are written to `security_audit.jsonl` with secrets redacted.

## Policy Examples

Policies use explicit operators (`eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in`, `not_in`, `contains`, `regex`) and **default-deny** when no rule matches.

```json
{
  "id": "deny-high-injection",
  "effect": "deny",
  "priority": 10,
  "when": {
    "risk.injection_score": { "gte": 0.6 }
  }
}
```

```json
{
  "id": "require-approval-external-email",
  "effect": "require_approval",
  "priority": 30,
  "when": {
    "tool.name": { "eq": "send_email" },
    "taint.has_untrusted": { "eq": true }
  }
}
```

Supported decision actions: `allow`, `deny`, `sandbox`, `redact`, `require_approval`, `quarantine`, `allow_with_transform`.

See `policies/default_policy.json` for the full policy.

## Capability Examples

Capabilities constrain tool arguments beyond simple allow/deny:

```json
{
  "name": "file_write_sandboxed",
  "tools": ["write_file"],
  "write": true,
  "allowed_path_prefixes": ["/sandbox/"],
  "blocked_path_patterns": ["\\.\\./", "/etc/"],
  "required_fields": ["path", "content"],
  "max_argument_length": { "content": 5000 }
}
```

```json
{
  "name": "read_only_search",
  "tools": ["search_web"],
  "read_only": true,
  "no_secrets_in_arguments": true,
  "required_fields": ["query"]
}
```

## Evaluation

Run scenario-based evaluation with metrics:

```bash
python -m middleware.eval --mode full_middleware
```

Baseline modes for comparison:

| Mode | Description |
|------|-------------|
| `no_defense` | Allow all tool calls |
| `regex_detector_only` | Deny on high injection score only |
| `allowlist_only` | Allow only tools on policy allowlist |
| `policy_without_taint` | Policy rules without taint signals |
| `full_middleware` | Complete pipeline |

```bash
python -m middleware.eval --mode regex_detector_only --output results
python -m middleware.eval --mode full_middleware --scenarios examples/scenarios --output results
```

**Metrics:** `attack_success_rate`, `benign_task_success_rate`, `false_allow_rate`, `false_block_rate`, `approval_rate`, `sandbox_rate`, `latency_overhead_ms`

Results are written to JSON and CSV under `results/`.

Scenarios live in `examples/scenarios/`:

- Safe search
- Malicious PDF → file write
- Malicious email exfiltration
- Tool output injection
- Secret in search query
- Benign security article
- External email requiring approval

## Development

```bash
black .
ruff check .
pytest -v
```

## Limitations

- Injection detection uses regex heuristics, not ML classifiers
- Mock tools do not call real APIs
- Policy evaluation is synchronous and in-process
- Provenance tracking requires callers to wrap tainted values explicitly
- No persistent approval workflow UI (approval is a decision action only)

## Roadmap

- Human-in-the-loop approval queue
- ML-based injection classifier plugin
- OpenTelemetry export for audit events
- Policy versioning and signed policy bundles
- Integration adapters for LangChain, MCP, and OpenAI tool schemas

## License

MIT
