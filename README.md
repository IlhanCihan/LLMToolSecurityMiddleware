# LLM Tool Security Middleware

This repository provides a reference architecture and prototype implementation
for a middleware security layer that sits between a tool-using LLM agent and
its tools. The middleware detects, contains, and mitigates prompt injection
and instruction hijacking, especially when malicious instructions originate
from untrusted sources such as retrieved documents, web pages, emails, PDFs,
logs, or tool outputs.

The design intentionally avoids making the LLM the final authority on
security. Instead, deterministic guards, structured policies, and taint-aware
enforcement decide whether tool calls are allowed, denied, or sandboxed.

## Architecture Overview

```
User / System / Dev Instructions
            |
         Agent
            |
     Tool Call Request
            |
   +-------------------+
   | Security Middleware|
   |-------------------|
   | 1) Taint Tracking  |
   | 2) Injection Scan  |
   | 3) Policy Engine   |
   | 4) Audit Logging   |
   +-------------------+
            |
        Tool Registry
            |
         Tools
```

### Trust Boundaries

- **System & developer instructions**: most trusted.
- **User input**: trusted but not authoritative for security.
- **Retrieved content**: untrusted; treated as data only.
- **Tool outputs**: untrusted unless explicitly upgraded by policy.

### Threat Model (examples)

- Exfiltration: extracting secrets or internal data via tools.
- Privilege escalation: calling tools beyond assigned capability.
- Destructive actions: file deletion, remote API writes, data corruption.
- Policy bypass: overriding or ignoring system/developer instructions.

## Components

1. **Taint Tracking** (`middleware/taint.py`)
   - Tracks provenance of data and propagates trust labels into tool args.

2. **Detectors** (`middleware/detectors.py`)
   - Deterministic prompt-injection heuristics (not LLM-based).
   - Signals feed the policy engine but do not decide alone.

3. **Policy Engine** (`middleware/policy.py`)
   - Capability-based permissions.
   - Structured rules for allow/deny/sandbox.
   - Default-deny with explicit allow paths.

4. **Middleware** (`middleware/middleware.py`)
   - Orchestrates signals, policy evaluation, and tool execution.

5. **Audit Logger** (`middleware/logger.py`)
   - JSONL logs with decision rationale and policy triggers.

6. **Evaluation Harness** (`middleware/eval.py`)
   - Synthetic RAG + tool tasks with adversarial injections.
   - Metrics for attack success rate and usability.

## Quick Start

```
python -m middleware.demo
```

This runs a demo scenario and prints a decision log. See
`middleware/demo.py` for the setup and `policies/default_policy.json`
for the policy.

## Extending the System

- Add new detectors in `middleware/detectors.py`
- Extend policy schema in `middleware/policy.py`
- Implement new tools in `middleware/demo.py` or integrate real tools
- Add evaluation scenarios in `middleware/eval.py`

## Notes on Design Choices

- **LLM is not the final authority**: policy decisions are deterministic.
- **Partial execution**: sandbox path can return redacted or simulated output.
- **Explainability**: every decision records the matched rules and signals.

