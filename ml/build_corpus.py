"""Build a run-grouped PMU training CSV from independently timed lab captures."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from rowguard.model import INPUTS

LABELS = {"baseline": 0, "benign_memory": 0, "settle": 0, "post": 0, "attack": 1}
TRIM_SECONDS = {"baseline": (1, 0), "benign_memory": (0, 0), "settle": (0, 0),
                "attack": (2, 1), "post": (2, 1)}


def instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def build(captures: list[Path], output: Path) -> dict:
    rows: list[dict] = []
    sources = []
    for directory in captures:
        manifest_path = directory / "manifest.json"
        database_path = directory / "telemetry.sqlite3"
        manifest = json.loads(manifest_path.read_text())
        phases = {name: (instant(span["start"]) + timedelta(seconds=TRIM_SECONDS[name][0]),
                         instant(span["end"]) - timedelta(seconds=TRIM_SECONDS[name][1]), label)
                  for name, span in manifest["phases"].items() if (label := LABELS.get(name)) is not None}
        if not phases or "attack" not in phases or not manifest.get("tool_result"):
            raise ValueError(f"capture lacks a completed attack phase: {directory}")
        with sqlite3.connect(f"file:{database_path}?mode=ro", uri=True) as database:
            samples = database.execute("SELECT timestamp, values_json, quality_json FROM samples ORDER BY timestamp")
            counts = {0: 0, 1: 0}
            for timestamp, values_json, quality_json in samples:
                t = instant(timestamp)
                label = next((label for start, end, label in phases.values() if start <= t <= end), None)
                if label is None or not json.loads(quality_json).get("valid", True):
                    continue
                values = json.loads(values_json)
                if any(name not in values or not math.isfinite(values[name]) for name in INPUTS):
                    continue
                rows.append({"run_id": manifest["run_id"], "label": label,
                             **{name: values[name] for name in INPUTS}})
                counts[label] += 1
        if min(counts.values()) < 20:
            raise ValueError(f"capture has too few labelled windows: {directory} {counts}")
        sources.append({"run_id": manifest["run_id"], "phase_counts": counts,
                        "tester_sha256": manifest["tester_sha256"],
                        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                        "telemetry_sha256": hashlib.sha256(database_path.read_bytes()).hexdigest()})
    if len({item["run_id"] for item in sources}) != len(sources):
        raise ValueError("duplicate run ID")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["run_id", "label", *INPUTS])
        writer.writeheader()
        writer.writerows(rows)
    report = {"runs": len(sources), "windows": len(rows), "labels": {str(label): sum(row["label"] == label for row in rows)
                                                                   for label in (0, 1)}, "sources": sources,
              "csv_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
              "label_policy": "manifest phases; benign memory start/stop transients included; attack first 2 s and last 1 s excluded; post first 2 s excluded"}
    output.with_suffix(".manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--captures", type=Path, nargs="+", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.captures, args.out), indent=2))


if __name__ == "__main__":
    main()
