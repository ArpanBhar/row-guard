"""Small, explicit logistic model artifact for offline-trained PMU features."""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

INPUTS = ("cache_misses_per_s", "cache_miss_ratio", "cache_miss_cv", "ipc")
DEFAULT_MODEL_PATH = Path(__file__).resolve().parent / "models" / "pmu-logistic.json"


class LinearModel:
    def __init__(self, path: Path):
        raw = path.read_bytes()
        data = json.loads(raw)
        if data.get("schema") != 1 or tuple(data.get("features", [])) != INPUTS:
            raise ValueError("model feature schema mismatch")
        for field in ("mean", "std", "weights"):
            if len(data.get(field, [])) != len(INPUTS):
                raise ValueError(f"invalid {field} length")
            if not all(isinstance(x, (int, float)) and math.isfinite(x) for x in data[field]):
                raise ValueError(f"non-finite {field}")
        if any(value <= 0 for value in data["std"]):
            raise ValueError("model standard deviation must be positive")
        if not 0 < data.get("threshold", 0) < 1:
            raise ValueError("model threshold must be in (0, 1)")
        if not math.isfinite(data.get("bias", float("nan"))):
            raise ValueError("model bias must be finite")
        self.data = data
        self.sha256 = hashlib.sha256(raw).hexdigest()
        self.threshold = float(data["threshold"])
        self.id = f"logistic:{self.sha256[:12]}"

    def score(self, features: dict[str, float]) -> float:
        standardized = [(features[name] - self.data["mean"][i]) / self.data["std"][i]
                        for i, name in enumerate(INPUTS)]
        value = self.data["bias"] + sum(w * x for w, x in zip(self.data["weights"], standardized))
        if not math.isfinite(value):
            raise ValueError("non-finite model input")
        return 1 / (1 + math.exp(-max(-60.0, min(60.0, value))))
