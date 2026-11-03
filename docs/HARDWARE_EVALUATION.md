# Initial hardware detector evaluation

Date: 3 November 2026. Host: Intel Core i5-11400H, 12 logical CPUs, Linux x86-64. RowGuard collected system-wide generic PMU counters in 100 ms intervals and scored overlapping one-second windows. This is an initial single-host experiment, not a general detection-accuracy result.

Google's [rowhammer-test](https://github.com/google/rowhammer-test) was built from commit `c1d2bd9f629281402c10bb10e52bc1f1faf59cc4`; the binary SHA-256 begins `792e8520fc7e8d79`. Each test was stopped after 35 seconds by the lab harness. The tool logged about 15 hammering iterations per run. No bit flip was reported in these bounded runs. Tool activity was independently timed by the harness, so `attack` means the hammering tool was active, not confirmed memory corruption.

The original fallback rule falsely alerted in ordinary activity. In the first 20/35/20-second baseline/test/post capture, it scored 172 of 180 baseline windows above its threshold and opened two baseline incidents. A first stricter rule still opened one baseline incident in the next capture. Those failures motivated `experimental_pmu_rule_v3`. A later run fell below its miss-rate cutoff, leading to an experimental v4 rule. Both rules have since been superseded as the default by the packaged [ML detector](ML_EVALUATION.md).

The v3 rule reached the 0.8 alert threshold only when all three one-second features met these conditions: cache misses at least 45 million/second, cache miss ratio at least 0.58, and instructions per cycle at most 0.8. The v4 comparison rule uses a 42-million/second miss cutoff. The 3-of-5 incident policy remains in force for the ML detector. Neither rule is the default now.

Replaying the v3 rule over 679 previously captured ordinary windows also opened no incident. That replay is supporting evidence only because those windows are from the same host and a short period.

| Subsequent run | Phase | Windows | Windows at/above 0.8 | Incidents opened |
| --- | --- | ---: | ---: | ---: |
| `20261103T121901Z-eadcbb` | Ordinary baseline | 191 | 0 | 0 |
|  | Google test | 347 | 208 | 11 |
|  | After test | 198 | 3 | 0 |
| `20261103T122127Z-88f6f1` | Ordinary baseline | 141 | 0 | 0 |
|  | Benign 128 MiB memory copy | 198 | 0 | 0 |
|  | Two-second settling period | 20 | 0 | 0 |
|  | Google test | 347 | 37 | 6 |
|  | After test | 148 | 0 | 0 |

The dashboard's live status API showed an active incident during the third run. The browser receives the same incident through its server-sent event stream and renders a `SUSPICIOUS` badge and incident history. Incidents opened during tool activity in both later runs and none opened in the measured control periods. Repeated opens within a single tool run show that the current five-window quiet-close rule is too sensitive to brief gaps; grouping and alert rate still need work.

Rendered UI validation used a separate synthetic PMU fixture to hold an incident open long enough for browser inspection. Headless Chrome showed the `SUSPICIOUS` badge, one active incident in the overview, and an incident row after selecting the Incidents view. No JavaScript exception appeared. Chrome logged a nonfunctional CSP meta-directive warning and a missing favicon request. The synthetic fixture checks presentation only; the hardware-run incident evidence is in the captured logs above.

Captured manifests, tool output, PMU telemetry, audit records, and signed local checkpoints are under the ignored `state/lab-20261103T121901Z-eadcbb/` and `state/lab-20261103T122127Z-88f6f1/` directories on this host. Local audit verification passed for both captures. No independent off-host anchor was configured for these lab runs, so local verification cannot rule out host-level rollback. The temporary PMU policy change may be lost after reboot.

These observations do not establish that only Rowhammer can trigger the detector. Other memory-intensive workloads, hardware, or backgrounds could satisfy similar generic system-wide PMU conditions. Longer ordinary soaks, more benign memory workloads, more attack families, independent runs across boots, and held-out hosts are needed before a production claim. The dashboard can show top-CPU process candidates, but these are not causal attribution or proof of a bit flip.
