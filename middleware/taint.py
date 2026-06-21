from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .models import (
    ConfidentialityLevel,
    DataProvenance,
    IntegrityLevel,
    SourceType,
    TransformType,
    TrustLevel,
)


@dataclass
class TaintedValue:
    value: Any
    provenance: list[DataProvenance] = field(default_factory=list)

    def merge(self, other: TaintedValue) -> TaintedValue:
        merged = list(self.provenance)
        merged.extend(other.provenance)
        return TaintedValue(value=other.value, provenance=_dedupe(merged))


def wrap(value: Any, provenance: Iterable[DataProvenance]) -> TaintedValue:
    return TaintedValue(value=value, provenance=list(provenance))


def taint_args(
    args: dict[str, Any], provenance: Iterable[DataProvenance]
) -> dict[str, TaintedValue]:
    return {key: wrap(val, provenance) for key, val in args.items()}


def collect_provenance(value: Any) -> list[DataProvenance]:
    if isinstance(value, TaintedValue):
        return list(value.provenance)
    if isinstance(value, dict):
        prov: list[DataProvenance] = []
        for item in value.values():
            prov.extend(collect_provenance(item))
        return _dedupe(prov)
    if isinstance(value, list):
        prov = []
        for item in value:
            prov.extend(collect_provenance(item))
        return _dedupe(prov)
    return []


def summarize_provenance(prov: Iterable[DataProvenance]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "source_types": {},
        "trust": {},
        "confidentiality": {},
        "integrity": {},
        "transforms": {},
        "total": 0,
    }
    for item in prov:
        summary["total"] += 1
        _inc(summary["source_types"], item.source_type.value)
        _inc(summary["trust"], item.trust.value)
        _inc(summary["confidentiality"], item.confidentiality.value)
        _inc(summary["integrity"], item.integrity.value)
        for transform in item.transforms:
            _inc(summary["transforms"], transform.value)
    return summary


def untrusted_ratio(summary: dict[str, Any]) -> float:
    trust_counts = summary.get("trust", {})
    untrusted = trust_counts.get(TrustLevel.UNTRUSTED.value, 0)
    untrusted += trust_counts.get(TrustLevel.EXTERNAL.value, 0)
    total = summary.get("total", 0)
    if total == 0:
        return 0.0
    return untrusted / total


def has_untrusted_external(summary: dict[str, Any]) -> bool:
    trust_counts = summary.get("trust", {})
    return (
        trust_counts.get(TrustLevel.UNTRUSTED.value, 0) > 0
        or trust_counts.get(TrustLevel.EXTERNAL.value, 0) > 0
    )


def default_untrusted_provenance(source_id: str, source_type: SourceType) -> DataProvenance:
    return DataProvenance(
        source_id=source_id,
        source_type=source_type,
        trust=TrustLevel.UNTRUSTED,
        confidentiality=ConfidentialityLevel.INTERNAL,
        integrity=IntegrityLevel.EXTERNAL,
        transforms=(TransformType.RETRIEVED,),
    )


def _inc(bucket: dict[str, int], key: str) -> None:
    bucket[key] = bucket.get(key, 0) + 1


def _dedupe(items: Iterable[DataProvenance]) -> list[DataProvenance]:
    seen: set[tuple[Any, ...]] = set()
    deduped: list[DataProvenance] = []
    for item in items:
        key = (
            item.source_id,
            item.source_type.value,
            item.trust.value,
            item.confidentiality.value,
            item.integrity.value,
            item.transforms,
            item.description,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped
