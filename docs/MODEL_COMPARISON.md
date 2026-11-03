# RowGuard model comparison

Updated 4 November 2026. This comparison uses measured PMU features from one Intel i5-11400H host and one Google Rowhammer test binary. The positive label means the tester was active; no physical bit flip is required or inferred.

## Method

The [training corpus](../ml/data/rowguard_pmu_training.csv) has 5,703 overlapping one-second windows from ten separately timed capture runs. Five outer folds place two **entire runs** in each test fold. From the other eight runs, six fit the model and two choose a score threshold. The threshold objective first minimizes benign incident openings, then maximizes detected attack runs, then window F1. Each test run is excluded from both fitting and threshold selection in its fold. This follows the non-overlapping-group property of [GroupKFold](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.GroupKFold.html). Each model uses a fixed configuration recorded in the [evaluation script](../ml/evaluate_models.py) and [machine-readable report](MODEL_COMPARISON.json); no broad hyperparameter search was performed.

The same 3-of-5 window vote and five-quiet-window closing policy was replayed for all models. Precision, recall, accuracy, and F1 below are **window-level** measures. The incident columns show what a dashboard user would experience. Mean fold average precision is also in the JSON report; [scikit-learn defines that metric from ranked prediction scores](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.average_precision_score.html). The XGBoost entry uses its official [XGBClassifier](https://xgboost.readthedocs.io/en/stable/python/python_api.html).

| Fixed configuration | Precision | Recall | Accuracy | F1 | Attack runs detected | Benign incidents |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Deployed-style logistic regression | **100.0%** | 92.7% | 96.8% | 96.2% | 10/10 | **0** |
| scikit-learn logistic regression | 99.4% | **95.7%** | **97.8%** | **97.5%** | 10/10 | 3 |
| Random forest | 99.3% | 92.1% | 96.2% | 95.5% | 10/10 | 3 |
| XGBoost | 99.6% | 89.8% | 95.4% | 94.5% | 10/10 | 1 |
| RBF SVM | 99.1% | 89.3% | 95.0% | 94.0% | 10/10 | 2 |
| Fixed PMU rule | 100.0% | 24.7% | 67.1% | 39.7% | 10/10 | 0 |

The deployed-style logistic row retrains the exact equations in `ml/train.py` separately for each fold. It is a fair comparison of the current **model method**, not a claim that the single packaged artifact was used in every fold.

## Later capture checks

Two [previously reviewed sessions](../ml/data/rowguard_external_reviewed.csv) and two [newer prospective sessions](../ml/data/rowguard_prospective.csv) were excluded from the ten-run corpus. For these checks, each candidate was fitted on the same six original training runs and thresholded on the same two validation runs. The exact packaged artifact was evaluated separately. The [earlier](MODEL_COMPARISON.json) and [prospective](MODEL_COMPARISON_PROSPECTIVE.json) JSON reports include per-run results and dataset checksums.

| Model | Earlier two-run recall | Newer two-run recall | Newer precision | Newer attack runs | Newer benign incidents |
| --- | ---: | ---: | ---: | ---: | ---: |
| Deployed-style logistic | 96.5% | 62.6% | 100.0% | 2/2 | 0 |
| scikit-learn logistic | 97.0% | 60.9% | 100.0% | 2/2 | 0 |
| Random forest | 91.7% | 74.5% | 100.0% | 2/2 | 0 |
| XGBoost | 93.4% | 67.5% | 100.0% | 2/2 | 0 |
| RBF SVM | 97.0% | **87.9%** | 100.0% | 2/2 | 0 |
| Exact packaged logistic artifact | 97.7% | 69.2% | 100.0% | 2/2 | 0 |

All newer runs had zero incident openings during baseline and benign memory-copy controls. One live run opened an incident about 0.6 seconds **after** the tester stopped, while its one-second feature window still contained attack measurements. The phase-aware CSV excludes the first two post-test seconds as mixed-label data, so this display timing event is not counted as a benign incident in the table. It remains a user-visible timing issue to improve.

## Recommendation and limits

**Keep the current packaged logistic model for this demo.** It is the strongest tested choice for the earlier requirement to avoid ordinary-activity alerts: zero benign incidents in the ten-run grouped comparison, detection in all ten attack runs, and 92.7% window recall. The scikit-learn logistic variant wins on window accuracy/F1/recall but opens three benign incidents. The RBF SVM is a promising recall candidate in the two newer runs, yet it opens two benign incidents in grouped cross-validation. More independent benign hours and attack families are needed before changing the daemon's default.

These windows overlap heavily, and all runs use one host and one tool. The 3,206 benign corpus windows represent only about five minutes of sampled benign time; zero observed alerts cannot establish a low long-term false-alert rate. The later sessions were short, and model configurations were inspected against earlier data. None of these numbers guarantees precision or recall on another CPU, DRAM module, workload, or Rowhammer pattern.

Evaluation environment: Python 3.12.3, NumPy 2.5.4, scikit-learn 1.9.1, XGBoost 3.4.1. To reproduce the grouped comparison:

```bash
python3 -m pip install -e '.[evaluate]'
OPENBLAS_NUM_THREADS=1 python3 -m ml.evaluate_models \
  --csv ml/data/rowguard_pmu_training.csv \
  --external-csv ml/data/rowguard_prospective.csv \
  --out docs/MODEL_COMPARISON_PROSPECTIVE.json
```
