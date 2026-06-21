from __future__ import annotations

from typing import Any


def search_web(query: str) -> str:
    return f"[mock] search results for: {query}"


def fetch_url(url: str) -> str:
    return f"[mock] fetched content from {url}"


def read_file(path: str) -> str:
    return f"[mock] contents of {path}"


def write_file(path: str, content: str) -> str:
    return f"[mock] wrote {len(content)} bytes to {path}"


def sandbox_write_file(path: str, content: str) -> str:
    redacted = content[:40] + "...[sandbox-redacted]"
    return f"[mock sandbox] wrote to {path}: {redacted}"


def draft_email(to: str, subject: str, body: str) -> str:
    return f"[mock] drafted email to {to}: {subject}"


def send_email(to: str, subject: str, body: str) -> str:
    return f"[mock] sent email to {to}: {subject}"


def query_database(sql: str) -> str:
    return f"[mock] query result for: {sql[:80]}"


def execute_code_sandbox(code: str) -> str:
    return f"[mock sandbox] executed {len(code)} chars of code"


MOCK_TOOLS: dict[str, Any] = {
    "search_web": search_web,
    "fetch_url": fetch_url,
    "read_file": read_file,
    "write_file": write_file,
    "draft_email": draft_email,
    "send_email": send_email,
    "query_database": query_database,
    "execute_code_sandbox": execute_code_sandbox,
}

SANDBOX_TOOLS: dict[str, Any] = {
    "write_file": sandbox_write_file,
    "execute_code_sandbox": execute_code_sandbox,
}
