"""Train a first logistic PMU model from labelled, run-grouped CSV windows.

Input columns: run_id,label,cache_misses_per_s,cache_miss_ratio,cache_miss_cv,ipc.
The input must come from measured, independently labelled collection sessions.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

import numpy as np

from rowguard.model import INPUTS


def load(path: Path):
    with path.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    if not rows:
        raise ValueError("training CSV is empty")
    groups = np.array([row["run_id"] for row in rows])
    labels = np.array([int(row["label"]) for row in rows], dtype=np.float64)
    if not set(labels).issubset({0.0, 1.0}):
        raise ValueError("labels must be 0 or 1")
    features = np.array([[float(row[name]) for name in INPUTS] for row in rows], dtype=np.float64)
    if not np.isfinite(features).all():
        raise ValueError("training features must be finite")
    return features, labels, groups


def split_by_run(groups, labels, seed=42):
    ids = np.unique(groups)
    if len(ids) < 10:
        raise ValueError("at least ten independent runs are required")
    for trial in range(1000):
        rng = np.random.default_rng(seed + trial)
        shuffled = rng.permutation(ids)
        n_train = max(2, int(len(ids) * 0.6))
        n_val = max(2, int(len(ids) * 0.2))
        if n_train + n_val >= len(ids):
            continue
        partitions = [shuffled[:n_train], shuffled[n_train:n_train + n_val], shuffled[n_train + n_val:]]
        masks = [np.isin(groups, part) for part in partitions]
        if all(len(np.unique(labels[mask])) == 2 for mask in masks):
            return masks
    raise ValueError("could not create three run-disjoint partitions with both labels")


def sigmoid(x):
    return 1 / (1 + np.exp(-np.clip(x, -60, 60)))


def metrics(labels, scores, threshold):
    predicted = scores >= threshold
    tp = int(np.sum(predicted & (labels == 1)))
    fp = int(np.sum(predicted & (labels == 0)))
    fn = int(np.sum(~predicted & (labels == 1)))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {"precision": precision, "recall": recall,
            "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
            "tp": tp, "fp": fp, "fn": fn, "windows": len(labels)}


def train(path: Path, out: Path, seed: int = 42):
    x, y, groups = load(path)
    train_mask, val_mask, test_mask = split_by_run(groups, y, seed)
    mean = x[train_mask].mean(axis=0)
    std = x[train_mask].std(axis=0)
    std = np.where(std > 0, std, 1.0)
    train_x = (x[train_mask] - mean) / std
    val_x = (x[val_mask] - mean) / std
    test_x = (x[test_mask] - mean) / std
    train_y = y[train_mask]
    weights = np.zeros(train_x.shape[1])
    bias = 0.0
    for iteration in range(3000):
        prediction = sigmoid(train_x @ weights + bias)
        error = prediction - train_y
        learning_rate = 0.08 / (1 + iteration / 1000)
        weights -= learning_rate * ((train_x.T @ error) / len(train_y) + 0.001 * weights)
        bias -= learning_rate * float(error.mean())
    val_scores = sigmoid(val_x @ weights + bias)
    candidates = np.linspace(0.1, 0.9, 81)
    threshold = float(max(candidates, key=lambda value: (metrics(y[val_mask], val_scores, value)["f1"], value)))
    test_scores = sigmoid(test_x @ weights + bias)
    report = {"schema": 1, "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
              "run_counts": {"train": int(len(set(groups[train_mask]))), "validation": int(len(set(groups[val_mask]))),
                             "test": int(len(set(groups[test_mask])))},
              "window_counts": {"train": int(train_mask.sum()), "validation": int(val_mask.sum()), "test": int(test_mask.sum())},
              "validation": metrics(y[val_mask], val_scores, threshold),
              "held_out_test": metrics(y[test_mask], test_scores, threshold),
              "caveat": "Window metrics only; hardware validation and incident-level evaluation are separate gates."}
    model = {"schema": 1, "algorithm": "logistic_regression_numpy_v1", "features": list(INPUTS),
             "mean": mean.tolist(), "std": std.tolist(), "weights": weights.tolist(), "bias": bias,
             "threshold": threshold, "source_sha256": report["source_sha256"], "seed": seed}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(model, sort_keys=True, separators=(",", ":")) + "\n")
    out.with_suffix(".report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    print(json.dumps(train(args.csv, args.out, args.seed), indent=2))


if __name__ == "__main__":
    main()
