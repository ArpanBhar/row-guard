"""Versioned feature extraction for 1-second rolling windows."""
from __future__ import annotations

import statistics
from collections import deque

FEATURES = (
    ("cycles_per_s", "Cycles / s", "/s"),
    ("instructions_per_s", "Instructions / s", "/s"),
    ("cache_references_per_s", "Cache references / s", "/s"),
    ("cache_misses_per_s", "Cache misses / s", "/s"),
    ("ipc", "Instructions per cycle", "ratio"),
    ("cache_miss_ratio", "Cache miss ratio", "ratio"),
    ("cache_miss_cv", "Cache miss variability", "ratio"),
    ("running_ratio", "PMU running ratio", "ratio"),
    ("risk_score", "Risk score", "score"),
)


class FeatureWindow:
    def __init__(self, samples: int = 10):
        self.samples = deque(maxlen=samples)
        self.length = samples

    def clear(self) -> None:
        self.samples.clear()

    def add(self, rates: dict[str, float], running_ratio: float) -> dict[str, float] | None:
        self.samples.append((rates, running_ratio))
        if len(self.samples) < self.length:
            return None
        result = {key: statistics.fmean(sample[0][key] for sample in self.samples) for key in rates}
        result["running_ratio"] = statistics.fmean(sample[1] for sample in self.samples)
        cycles = result["cycles_per_s"]
        refs = result["cache_references_per_s"]
        if cycles <= 0 or refs <= 0:
            return None
        result["ipc"] = result["instructions_per_s"] / cycles
        result["cache_miss_ratio"] = result["cache_misses_per_s"] / refs
        miss_rates = [sample[0]["cache_misses_per_s"] for sample in self.samples]
        mean = statistics.fmean(miss_rates)
        result["cache_miss_cv"] = statistics.pstdev(miss_rates) / mean if mean > 0 else 0.0
        return result
