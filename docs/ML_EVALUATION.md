# Experimental ML detector

Updated 4 November 2026. RowGuard now loads the bundled [logistic model](../rowguard/models/pmu-logistic.json) by default. Its four inputs are measured cache misses/second, cache miss ratio, cache-miss variability, and instructions per cycle from one-second rolling PMU windows. Inference runs inside the daemon; normal use requires only `rowguard serve` and the web dashboard. `ROWGUARD_DETECTOR=rule` explicitly selects the older experimental threshold rule for comparison.

A later [five-model comparison](MODEL_COMPARISON.md) evaluates precision, recall, accuracy, F1, and incident false alerts with run-disjoint folds and two newer capture sessions. It supports keeping the current logistic model for the present single-host demo, while identifying an RBF SVM as a candidate for further recall testing.

## Training data and split

The [corpus builder](../ml/build_corpus.py) used ten bounded Google `rowhammer_test` capture sessions from this Intel i5-11400H host: 5,703 labelled windows, including 3,206 benign and 2,497 tester-active windows. Labels come from harness start/stop times, independent of RowGuard scores. Benign memory-copy startup and stop windows are included because excluding them caused an observed false alert. Attack startup and post-attack transition windows are trimmed to avoid mixed labels.

The [trainer](../ml/train.py) split by complete capture run: six training runs, two validation runs for the alert threshold, and two run-disjoint test runs. It fits standardization and logistic weights only on training runs. The model threshold is 0.76; the existing 3-of-5 policy turns scored windows into incidents. The processed [training CSV](../ml/data/rowguard_pmu_training.csv) and [capture manifest](../ml/data/rowguard_pmu_training.manifest.json) are included for reproduction; CSV SHA-256: `8caa5cc05d292880bdba80e477b3b797a8a966940553e880e3895a5e7f498615`. The [training report](../rowguard/models/pmu-logistic.report.json) records exact run IDs and split counts. Model SHA-256: `0fdaad5808236981370658068ccdb1edc4081b4e2192c9ca74ee4dc6f28a0ee7`.

To regenerate the exact packaged model from the processed data:

```bash
python3 -m ml.train --csv ml/data/rowguard_pmu_training.csv --out rowguard/models/pmu-logistic.json
```

| Evaluation partition | Window precision | Window recall | Attack runs detected | Benign incident openings |
| --- | ---: | ---: | ---: | ---: |
| Validation: 2 runs | 0.995 | 1.000 | 2/2 | 0 |
| Run-disjoint test: 2 runs | 0.998 | 0.885 | 2/2 | 0 |

The first model omitted benign memory-copy transitions and falsely alerted during a later live control. The revised model above includes those known benign windows. It replayed that failed session with attack-only incidents, but that replay was inspected during revision and is not an untouched test. The two run-disjoint test runs were also visible in the earlier model report, so their results are not a blind final evaluation; the separate fresh live check below provides a more useful confirmation after revision.

## Fresh live check

After the revision, a separate 15-second baseline, 15-second benign 128 MiB memory copy, 2-second settling period, 35-second Google test, and 15-second post-test session ran with the packaged ML model active (`state/lab-20261103T184238Z-4fefd3/`). The daemon reported detector `logistic:0fdaad580823`. It opened **one incident during the tester** and **none** in the measured benign phases. Of 330 tester-phase windows, 329 scored at or above 0.76; six post-test windows did, but did not satisfy the incident policy. The incident recorded `rowhammer_test` as the highest CPU process, labelled as an unverified candidate. Independent verification of the local signed audit passed. No bit flip was reported.

The packaged Python runtime score matched the training calculation within `2.3e-16` on sampled corpus rows. The built wheel contains the model and report. All 14 unit/integration tests passed at this snapshot.

## Limits

This is a single-host, single-tool experimental model. The overlapping windows and repeated runs from one machine are highly related, so the measured precision/recall cannot be generalized to other CPUs, DRAM, attack families, or long ordinary workloads. The sigmoid output is **not calibrated as a physical-attack probability**. A high score identifies a pattern resembling the measured tool activity; it does not establish the attacking process or memory corruption. The Duke simulator dataset was not used for deployment because its row/bank access fields have not been shown equivalent to these real PMU counters. More benign soak time, diverse attackers, independent hosts, and calibration are required before production claims.
