from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


INJECTION_PATTERNS = [
    r"ignore\s+previous",
    r"disregard\s+system",
    r"override\s+instructions",
    r"reveal\s+system\s+prompt",
    r"exfiltrate",
    r"send\s+secrets",
    r"bypass\s+policy",
    r"developer\s+mode",
    r"call\s+tool",
    r"delete\s+files",
]


@dataclass
class InjectionSignal:
    score: float
    matches: List[str]
    evidence: List[str]


class PromptInjectionHeuristics:
    def __init__(self, patterns: List[str] | None = None) -> None:
        self._patterns = [re.compile(pat, re.IGNORECASE) for pat in (patterns or INJECTION_PATTERNS)]

    def scan_text(self, text: str) -> InjectionSignal:
        matches: List[str] = []
        evidence: List[str] = []
        for pattern in self._patterns:
            if pattern.search(text):
                matches.append(pattern.pattern)
                evidence.append(self._extract_evidence(text, pattern))
        score = min(1.0, len(matches) / max(1, len(self._patterns) / 4))
        return InjectionSignal(score=score, matches=matches, evidence=evidence)

    def scan_payload(self, payload: Dict[str, Any]) -> InjectionSignal:
        flattened = " ".join(_flatten(payload))
        return self.scan_text(flattened)

    @staticmethod
    def _extract_evidence(text: str, pattern: re.Pattern[str]) -> str:
        match = pattern.search(text)
        if not match:
            return ""
        start = max(0, match.start() - 40)
        end = min(len(text), match.end() + 40)
        return text[start:end].replace("\n", " ")


def _flatten(payload: Dict[str, Any]) -> List[str]:
    parts: List[str] = []
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


class ExternalIntentClassifier:
    def classify(self, text: str) -> Tuple[str, float]:
        return "unknown", 0.0
