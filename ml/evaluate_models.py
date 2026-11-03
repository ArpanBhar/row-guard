"""Compare fixed PMU classifiers with nested, run-disjoint validation.

Each outer test fold contains complete capture runs. Within the remaining runs,
a separate group split chooses the incident threshold. No overlapping window
from a test run participates in fitting or threshold selection for that fold.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import time
from pathlib import Path

import numpy as np
import sklearn
import xgboost
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.model_selection import GroupKFold, GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

from ml.train import incident_metrics, load, sigmoid, split_by_run
from rowguard.detector import experimental_score
from rowguard.model import DEFAULT_MODEL_PATH, INPUTS, LinearModel


class DeployedStyleLogistic:
    """The same fitting and score equations used by ml.train and LinearModel."""

    def fit(self, features: np.ndarray, labels: np.ndarray):
        self.mean = features.mean(axis=0)
        self.std = np.where(features.std(axis=0) > 0, features.std(axis=0), 1.0)
        x = (features - self.mean) / self.std
        self.weights = np.zeros(x.shape[1])
        self.bias = 0.0
        for iteration in range(3000):
            prediction = sigmoid(x @ self.weights + self.bias)
            error = prediction - labels
            learning_rate = 0.08 / (1 + iteration / 1000)
            self.weights -= learning_rate * ((x.T @ error) / len(labels) + 0.001 * self.weights)
            self.bias -= learning_rate * float(error.mean())
        return self

    def predict_proba(self, features: np.ndarray) -> np.ndarray:
        positive = sigmoid(((features - self.mean) / self.std) @ self.weights + self.bias)
        return np.column_stack((1 - positive, positive))


def model_factories():
    return {
        "deployed_style_logistic": DeployedStyleLogistic,
        "logistic_regression": lambda: make_pipeline(StandardScaler(), LogisticRegression(
            C=1.0, class_weight="balanced", max_iter=2000, random_state=42)),
        "random_forest": lambda: RandomForestClassifier(
            n_estimators=200, max_depth=6, min_samples_leaf=10,
            class_weight="balanced_subsample", n_jobs=1, random_state=42),
        "xgboost": lambda: xgboost.XGBClassifier(
            n_estimators=150, max_depth=3, learning_rate=0.05, min_child_weight=10,
            subsample=0.8, colsample_bytree=1.0, reg_lambda=3.0, tree_method="hist",
            eval_metric="logloss", n_jobs=1, random_state=42),
        "rbf_svm": lambda: make_pipeline(StandardScaler(), SVC(
            C=1.0, kernel="rbf", gamma="scale", class_weight="balanced")),
    }


def scores_for(model, features: np.ndarray) -> np.ndarray:
    if hasattr(model, "decision_function"):
        return np.asarray(model.decision_function(features), dtype=float)
    return np.asarray(model.predict_proba(features)[:, 1], dtype=float)


def window_metrics(labels: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    predicted = scores >= threshold
    positive = labels == 1
    tp = int(np.sum(predicted & positive))
    fp = int(np.sum(predicted & ~positive))
    fn = int(np.sum(~predicted & positive))
    tn = int(np.sum(~predicted & ~positive))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {"precision": precision, "recall": recall,
            "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
            "accuracy": (tp + tn) / len(labels), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "windows": len(labels)}


def choose_threshold(labels: np.ndarray, scores: np.ndarray, groups: np.ndarray) -> float:
    candidates = np.unique(np.quantile(scores, np.linspace(0, 1, 101)))
    candidates = np.r_[candidates, np.nextafter(scores.max(), np.inf)]
    def objective(value):
        incidents = incident_metrics(labels, scores, groups, value)
        windows = window_metrics(labels, scores, value)
        return (-incidents["benign_incident_openings"], incidents["attack_runs_detected"],
                windows["f1"], value)
    return float(max(candidates, key=objective))


def summarize(folds: list[dict]) -> dict:
    counts = {name: sum(fold["windows"][name] for fold in folds) for name in ("tp", "fp", "fn", "tn", "windows")}
    precision = counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] + counts["fp"] else 0.0
    recall = counts["tp"] / (counts["tp"] + counts["fn"]) if counts["tp"] + counts["fn"] else 0.0
    counts.update({"precision": precision, "recall": recall,
                   "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
                   "accuracy": (counts["tp"] + counts["tn"]) / counts["windows"],
                   "mean_fold_average_precision": float(np.mean([fold["average_precision"] for fold in folds]))})
    counts["incidents"] = {name: sum(fold["incidents"][name] for fold in folds)
                           for name in ("attack_runs", "attack_runs_detected", "attack_incident_openings",
                                        "benign_incident_openings")}
    counts["mean_predict_us_per_window"] = float(np.mean([fold["predict_us_per_window"] for fold in folds]))
    return counts


def external_metrics(labels: np.ndarray, scores: np.ndarray, groups: np.ndarray, threshold: float) -> dict:
    return {"windows": window_metrics(labels, scores, threshold),
            "average_precision": float(average_precision_score(labels, scores)),
            "incidents": incident_metrics(labels, scores, groups, threshold),
            "by_run": {str(run_id): {"windows": window_metrics(labels[groups == run_id],
                                                                 scores[groups == run_id], threshold),
                                      "incidents": incident_metrics(labels[groups == run_id],
                                                                    scores[groups == run_id],
                                                                    groups[groups == run_id], threshold)}
                       for run_id in dict.fromkeys(groups)}}


def evaluate_external(train_csv: Path, external_csv: Path) -> dict:
    features, labels, groups = load(train_csv)
    labels = labels.astype(int)
    external_x, external_y, external_groups = load(external_csv)
    external_y = external_y.astype(int)
    if set(groups) & set(external_groups):
        raise ValueError("external capture runs overlap training runs")
    train_mask, validation_mask, _ = split_by_run(groups, labels, seed=42)
    result = {}
    for name, factory in model_factories().items():
        model = factory().fit(features[train_mask], labels[train_mask])
        threshold = choose_threshold(labels[validation_mask], scores_for(model, features[validation_mask]),
                                     groups[validation_mask])
        scores = scores_for(model, external_x)
        result[name] = {"threshold": threshold,
                        **external_metrics(external_y, scores, external_groups, threshold)}
    rule_scores = np.array([experimental_score(dict(zip(INPUTS, row))) for row in external_x])
    result["fixed_pmu_rule"] = {"threshold": 0.8,
                                **external_metrics(external_y, rule_scores, external_groups, 0.8)}
    packaged = LinearModel(DEFAULT_MODEL_PATH)
    packaged_scores = np.array([packaged.score(dict(zip(INPUTS, row))) for row in external_x])
    result["packaged_logistic_artifact"] = {"threshold": packaged.threshold,
                                            "model_sha256": packaged.sha256,
                                            **external_metrics(external_y, packaged_scores,
                                                               external_groups, packaged.threshold)}
    return {"dataset_sha256": hashlib.sha256(external_csv.read_bytes()).hexdigest(),
            "runs": sorted(set(external_groups)), "windows": len(external_y),
            "fit_runs": sorted(set(groups[train_mask])), "threshold_runs": sorted(set(groups[validation_mask])),
            "note": "External runs were not used for fitting or threshold selection. Report whether they were observed during model development separately.",
            "models": result}


def evaluate(csv_path: Path, external_csv: Path | None = None) -> dict:
    features, labels, groups = load(csv_path)
    labels = labels.astype(int)
    if len(set(groups)) < 10:
        raise ValueError("at least ten independent capture runs are required")
    factories = model_factories()
    results = {name: [] for name in (*factories, "fixed_pmu_rule")}
    for fold_number, (outer_train, outer_test) in enumerate(GroupKFold(n_splits=5).split(features, labels, groups)):
        inner_train_pos, validation_pos = next(GroupShuffleSplit(
            n_splits=1, test_size=0.25, random_state=42 + fold_number).split(
                features[outer_train], labels[outer_train], groups[outer_train]))
        inner_train = outer_train[inner_train_pos]
        validation = outer_train[validation_pos]
        split = {"train_runs": sorted(set(groups[inner_train])),
                 "validation_runs": sorted(set(groups[validation])),
                 "test_runs": sorted(set(groups[outer_test]))}
        if (set(split["train_runs"]) & set(split["validation_runs"]) or
                set(split["train_runs"]) & set(split["test_runs"]) or
                set(split["validation_runs"]) & set(split["test_runs"])):
            raise AssertionError("capture run leaked across partitions")
        for name, factory in factories.items():
            model = factory()
            start = time.perf_counter()
            model.fit(features[inner_train], labels[inner_train])
            fit_seconds = time.perf_counter() - start
            validation_scores = scores_for(model, features[validation])
            threshold = choose_threshold(labels[validation], validation_scores, groups[validation])
            start = time.perf_counter()
            test_scores = scores_for(model, features[outer_test])
            predict_us = (time.perf_counter() - start) * 1e6 / len(outer_test)
            results[name].append({**split, "threshold": threshold, "fit_seconds": fit_seconds,
                                  "predict_us_per_window": predict_us,
                                  "average_precision": float(average_precision_score(labels[outer_test], test_scores)),
                                  "windows": window_metrics(labels[outer_test], test_scores, threshold),
                                  "incidents": incident_metrics(labels[outer_test], test_scores,
                                                                groups[outer_test], threshold)})
        start = time.perf_counter()
        baseline_scores = np.array([experimental_score(dict(zip(INPUTS, row))) for row in features[outer_test]])
        baseline_predict_us = (time.perf_counter() - start) * 1e6 / len(outer_test)
        results["fixed_pmu_rule"].append({**split, "threshold": 0.8, "fit_seconds": 0.0,
                                           "predict_us_per_window": baseline_predict_us,
                                           "average_precision": float(average_precision_score(labels[outer_test], baseline_scores)),
                                           "windows": window_metrics(labels[outer_test], baseline_scores, 0.8),
                                           "incidents": incident_metrics(labels[outer_test], baseline_scores,
                                                                         groups[outer_test], 0.8)})
    report = {"dataset_sha256": hashlib.sha256(csv_path.read_bytes()).hexdigest(),
            "dataset_runs": len(set(groups)), "dataset_windows": len(labels),
            "protocol": "5 outer folds by whole run; inner 6-run fit/2-run threshold selection; 2-run outer test",
            "versions": {"python": platform.python_version(), "numpy": np.__version__,
                         "scikit_learn": sklearn.__version__, "xgboost": xgboost.__version__},
            "model_configs": {"deployed_style_logistic": "ml.train equations: 3000 iterations, L2=0.001",
                              **{name: repr(factory()) for name, factory in factories.items()
                                 if name != "deployed_style_logistic"}},
            "models": {name: {"summary": summarize(folds), "folds": folds} for name, folds in results.items()}}
    if external_csv is not None:
        report["external"] = evaluate_external(csv_path, external_csv)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", type=Path, default=Path("ml/data/rowguard_pmu_training.csv"))
    parser.add_argument("--out", type=Path, default=Path("docs/MODEL_COMPARISON.json"))
    parser.add_argument("--external-csv", type=Path)
    args = parser.parse_args()
    report = evaluate(args.csv, args.external_csv)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    for name, entry in report["models"].items():
        s = entry["summary"]
        print(f"{name}: precision={s['precision']:.3f} recall={s['recall']:.3f} "
              f"f1={s['f1']:.3f} attack_runs={s['incidents']['attack_runs_detected']}/10 "
              f"benign_incidents={s['incidents']['benign_incident_openings']}")
    if "external" in report:
        for name, entry in report["external"]["models"].items():
            w, i = entry["windows"], entry["incidents"]
            print(f"external {name}: precision={w['precision']:.3f} recall={w['recall']:.3f} "
                  f"attack_runs={i['attack_runs_detected']}/{i['attack_runs']} "
                  f"benign_incidents={i['benign_incident_openings']}")


if __name__ == "__main__":
    main()
