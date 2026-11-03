"""An experimental PMU rule and durable incident state machine.

The rule was calibrated on two early Google rowhammer-test captures on this host.
It is not a general Rowhammer classifier or a calibrated probability.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field


def experimental_score(features: dict[str, float]) -> float:
    # A score reaches the 0.8 alert threshold only when all three measured
    # conditions hold. Generic cache misses alone caused frequent false alerts.
    # This score represents rule strength, not attack probability.
    miss = features["cache_misses_per_s"] / 42_000_000
    ratio = features["cache_miss_ratio"] / 0.58
    low_ipc = 0.8 / max(features["ipc"], 1e-9)
    return round(min(1.0, 0.8 * min(miss, ratio, low_ipc)), 5)


@dataclass
class Incident:
    id: str
    first_seen: str
    opened_at: str
    last_seen: str
    peak_score: float
    suspicious_windows: int
    valid_windows: int
    status: str = "active"
    process_candidates: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return vars(self).copy()


class IncidentPolicy:
    def __init__(self, threshold: float = 0.8):
        self.threshold = threshold
        self.votes: deque[tuple[str, bool, float]] = deque(maxlen=5)
        self.active: Incident | None = None
        self.quiet = 0

    def gap(self) -> None:
        self.votes.clear()
        self.quiet = 0

    def update(self, timestamp: str, score: float, incident_id: str) -> tuple[str | None, Incident | None]:
        suspicious = score >= self.threshold
        self.votes.append((timestamp, suspicious, score))
        if self.active is None:
            if len(self.votes) == 5 and sum(v for _, v, _ in self.votes) >= 3:
                first = next(t for t, v, _ in self.votes if v)
                self.active = Incident(incident_id, first, timestamp, timestamp,
                                       max(s for _, _, s in self.votes),
                                       sum(v for _, v, _ in self.votes), len(self.votes))
                return "INCIDENT_OPENED", self.active
            return None, None
        incident = self.active
        incident.valid_windows += 1
        incident.last_seen = timestamp
        incident.peak_score = max(incident.peak_score, score)
        if suspicious:
            incident.suspicious_windows += 1
            self.quiet = 0
        else:
            self.quiet += 1
        if self.quiet >= 5:
            incident.status = "closed"
            self.active = None
            self.votes.clear()
            self.quiet = 0
            return "INCIDENT_CLOSED", incident
        return None, incident
