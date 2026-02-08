from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List

from .models import DataProvenance, TrustLevel


@dataclass
class TaintedValue:
    value: Any
    provenance: List[DataProvenance] = field(default_factory=list)

    def merge(self, other: "TaintedValue") -> "TaintedValue":
        merged = list(self.provenance)
        merged.extend(other.provenance)
        return TaintedValue(value=other.value, provenance=_dedupe(merged))


def wrap(value: Any, provenance: Iterable[DataProvenance]) -> TaintedValue:
    return TaintedValue(value=value, provenance=list(provenance))


def taint_args(args: Dict[str, Any], provenance: Iterable[DataProvenance]) -> Dict[str, TaintedValue]:
    tainted: Dict[str, TaintedValue] = {}
    for key, val in args.items():
        tainted[key] = wrap(val, provenance)
    return tainted


def collect_provenance(value: Any) -> List[DataProvenance]:
    if isinstance(value, TaintedValue):
        return list(value.provenance)
    if isinstance(value, dict):
        prov: List[DataProvenance] = []
        for item in value.values():
            prov.extend(collect_provenance(item))
        return _dedupe(prov)
    if isinstance(value, list):
        prov: List[DataProvenance] = []
        for item in value:
            prov.extend(collect_provenance(item))
        return _dedupe(prov)
    return []


def summarize_provenance(prov: Iterable[DataProvenance]) -> Dict[str, int]:
    summary: Dict[str, int] = {level.value: 0 for level in TrustLevel}
    for item in prov:
        summary[item.trust.value] = summary.get(item.trust.value, 0) + 1
    return summary


def _dedupe(items: Iterable[DataProvenance]) -> List[DataProvenance]:
    seen = set()
    deduped: List[DataProvenance] = []
    for item in items:
        key = (item.source_id, item.trust.value, item.description)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped
