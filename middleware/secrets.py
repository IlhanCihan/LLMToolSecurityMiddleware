from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class SecretMatch:
    secret_type: str
    pattern_name: str
    redacted: str


@dataclass
class SecretScanResult:
    detected: bool
    types: list[str] = field(default_factory=list)
    matches: list[SecretMatch] = field(default_factory=list)


SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "api_key": re.compile(
        r"(?i)(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?"
    ),
    "jwt": re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(
        r"(?i)(?:aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{30,})['\"]?"
    ),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "password": re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
}


REDACTION_PLACEHOLDER = "[REDACTED:{type}]"


class SecretDetector:
    def __init__(self, patterns: dict[str, re.Pattern[str]] | None = None) -> None:
        self._patterns = patterns or SECRET_PATTERNS

    def scan_text(self, text: str) -> SecretScanResult:
        matches: list[SecretMatch] = []
        types: list[str] = []
        for secret_type, pattern in self._patterns.items():
            if secret_type == "credit_card" and not self._looks_like_card(text, pattern):
                continue
            for _match in pattern.finditer(text):
                types.append(secret_type)
                matches.append(
                    SecretMatch(
                        secret_type=secret_type,
                        pattern_name=pattern.pattern,
                        redacted=REDACTION_PLACEHOLDER.format(type=secret_type),
                    )
                )
        return SecretScanResult(
            detected=len(matches) > 0,
            types=sorted(set(types)),
            matches=matches,
        )

    def scan_payload(self, payload: dict[str, object]) -> SecretScanResult:
        flattened = " ".join(_flatten(payload))
        return self.scan_text(flattened)

    def redact_text(self, text: str) -> str:
        redacted = text
        for secret_type, pattern in self._patterns.items():
            redacted = pattern.sub(REDACTION_PLACEHOLDER.format(type=secret_type), redacted)
        return redacted

    def redact_payload(self, payload: dict[str, object]) -> dict[str, object]:
        return _redact_value(payload, self)

    @staticmethod
    def _looks_like_card(text: str, pattern: re.Pattern[str]) -> bool:
        for match in pattern.finditer(text):
            digits = re.sub(r"\D", "", match.group(0))
            if 13 <= len(digits) <= 19:
                return True
        return False


def _flatten(payload: dict[str, object]) -> list[str]:
    parts: list[str] = []
    for val in payload.values():
        if isinstance(val, str):
            parts.append(val)
        elif isinstance(val, dict):
            parts.extend(_flatten(val))
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    parts.append(item)
    return parts


def _redact_value(value: object, detector: SecretDetector) -> object:
    if isinstance(value, str):
        return detector.redact_text(value)
    if isinstance(value, dict):
        return {k: _redact_value(v, detector) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(item, detector) for item in value]
    return value
