# Implementation status

Updated: 3 November 2026. This is an implementation snapshot, not a validation claim.

| Plan area | Current state |
| --- | --- |
| Daemon and PMU collector | Implemented for Linux x86-64 generic hardware events. Grouped per-CPU counter reads, multiplexing correction, and explicit degraded status are in place. On 3 November 2026, temporary `perf_event_paranoid=0` enabled a live system-wide `perf stat` run and RowGuard's collector; the daemon API reported `MONITORING`, valid quality, and live feature values. This setting is not persistent across reboot. |
| Features | One-second rolling execution, cache, IPC, miss ratio, and miss variability features are implemented. Uncore/LLC-specific event aliases and CPU-family profiles remain. |
| Detector | Experimental, single-host PMU rule plus optional offline-trained logistic artifact. The rule now combines cache miss rate, miss ratio, and low IPC after the earlier fallback produced false alerts. 3-of-5 incident policy, durable open/close, interrupted state, and local history are implemented. No production model is validated. |
| Dashboard | Read-only overview, feature graphs, incidents, evidence, and health with SSE updates. Headless Chrome QA passed at 1487×1059 and an emulated 390×844 mobile viewport; all five navigation items and nine feature rows rendered. Static HTML/CSS/JavaScript is used because Node is unavailable in this workspace. |
| Audit | Hash chain, signed Ed25519 checkpoints, local verification, separate verifier, and optional independent checkpoint receiver are implemented. Canonical JSON is a documented Python-specific v1 format; RFC 8785, key rotation, robust crash recovery, signed telemetry chunks, and retention proofs remain. |
| ML data | Run-grouped logistic trainer and artifact loader are implemented. Duke archive inspection, local attack-labelled traces, four-model comparison, calibration, and hardware transfer evaluation remain. |
| Hardware attack testing | Google's rowhammer-test was run in bounded 35-second sessions on the user's disposable Intel i5-11400H host. Two subsequent current-rule runs alerted during tool activity and not during measured baseline, post-test, or 128 MiB benign-memory-copy controls. No bit flip was reported. See [HARDWARE_EVALUATION.md](HARDWARE_EVALUATION.md). |
| Deployment | Example systemd unit is present. Package installation, privilege validation, reboot/restart tests, and a remote receiver deployment remain. |

The dashboard's “ANCHORED” state means the configured receiver acknowledged the checkpoint. The verifier must independently fetch that receiver's latest checkpoint and use a separately pinned public key to assess rollback protection. No general Rowhammer-only or bit-flip detection accuracy is claimed from the bounded tool runs.
