"""Article IV - Evaluator-Trust Integrity.

    Attributed(E) = Provenance(E)   for every evidence trail E surfaced to the evaluator

A containment system can satisfy Authority Monotonicity perfectly and still
produce an evidentiary record that misleads whoever consumes it, via two
named failure modes:

  1. Re-entry attribution laundering: hash/ID collision or reuse across
     semantically distinct mirror instances corrupts which session an
     evaluator believes produced which evidence.
  2. Evaluation metric gaming: an agent learns to produce the behavioral
     proxy for genuine success (e.g. time-to-detect) without the underlying
     property, earning evaluator trust it has not earned.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class EvidenceRecord:
    """One piece of evidence surfaced to an evaluator."""

    evidence_id: str
    attributed_session: str
    """The session the evaluator is told produced this evidence."""
    provenance_session: str
    """The session that actually produced this evidence."""
    proxy_score: Optional[float] = None
    """The measured behavioral proxy for the property of interest, if any."""
    true_property: Optional[bool] = None
    """Whether the underlying property the proxy is meant to measure
    actually held, if known (e.g. via independent audit)."""


@dataclass(frozen=True)
class AttributionViolation:
    record: EvidenceRecord

    def __str__(self) -> str:
        return (
            f"evidence {self.record.evidence_id!r} attributed to session "
            f"{self.record.attributed_session!r} but actually produced by "
            f"{self.record.provenance_session!r} (attribution laundering)"
        )


@dataclass(frozen=True)
class MetricGamingViolation:
    record: EvidenceRecord
    threshold: float

    def __str__(self) -> str:
        return (
            f"evidence {self.record.evidence_id!r} scored {self.record.proxy_score} "
            f"(>= threshold {self.threshold}) but true_property is False "
            "(proxy diverges from the property it is meant to measure)"
        )


def check_attribution_integrity(
    records: list[EvidenceRecord],
) -> list[AttributionViolation]:
    """Article IV, failure mode 1: Attributed(E) = Provenance(E) for every E."""
    return [
        AttributionViolation(r)
        for r in records
        if r.attributed_session != r.provenance_session
    ]


def check_metric_gaming(
    records: list[EvidenceRecord],
    threshold: float = 0.5,
) -> list[MetricGamingViolation]:
    """Article IV, failure mode 2: a high proxy score with a false
    underlying property means the proxy has been gamed rather than earned.
    """
    violations: list[MetricGamingViolation] = []
    for r in records:
        if (
            r.proxy_score is not None
            and r.true_property is not None
            and r.proxy_score >= threshold
            and not r.true_property
        ):
            violations.append(MetricGamingViolation(r, threshold))
    return violations


def check_evaluator_trust_integrity(
    records: list[EvidenceRecord],
    threshold: float = 0.5,
) -> dict[str, list]:
    return {
        "attribution": check_attribution_integrity(records),
        "metric_gaming": check_metric_gaming(records, threshold),
    }
