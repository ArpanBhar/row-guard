"""Capture a bounded, labelled before/during/after Rowhammer test session.

Run only on a disposable, authorised host. The external test may cause bit flips.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def status(port):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/status", timeout=2) as response:
        return json.loads(response.read())


def wait_seconds(seconds, phase, port, stream):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        try:
            report = status(port)
            record = {"time": utc_now(), "phase": phase, "pmu_state": report["pmu_state"],
                      "risk_score": report["risk_score"], "active_incident": bool(report["active_incident"]),
                      "audit_sequence": report["audit_sequence"]}
            stream.write(json.dumps(record) + "\n")
            stream.flush()
        except Exception as exc:
            print(f"{phase}: API unavailable: {exc}", flush=True)
        time.sleep(min(1, max(0, until - time.monotonic())))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tester", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--baseline-seconds", type=int, default=20)
    parser.add_argument("--attack-seconds", type=int, default=35)
    parser.add_argument("--post-seconds", type=int, default=20)
    parser.add_argument("--benign-seconds", type=int, default=0,
                        help="run a memory-copy control before the hammering test")
    parser.add_argument("--port", type=int, default=8769)
    parser.add_argument("--output-dir", type=Path, default=Path("state"))
    args = parser.parse_args()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]
    output = args.output_dir / ("lab-" + run_id)
    output.mkdir(parents=True)
    tester_path = args.tester.resolve()
    metadata = {"run_id": run_id, "source_commit": subprocess.check_output(["git", "-C", str(args.source), "rev-parse", "HEAD"], text=True).strip(),
                "tester_sha256": hashlib.sha256(tester_path.read_bytes()).hexdigest(),
                "tester_path": str(tester_path), "phases": {}, "tool_result": None}
    env = os.environ.copy()
    env.pop("ROWGUARD_MODEL_PATH", None)
    env.pop("ROWGUARD_ANCHOR_URL", None)
    env.pop("ROWGUARD_ANCHOR_TOKEN", None)
    daemon_log = (output / "daemon.log").open("w")
    server = subprocess.Popen([sys.executable, "-m", "rowguard.cli", "serve", "--state-dir", str(output),
                               "--host", "127.0.0.1", "--port", str(args.port)],
                              env=env, stdout=daemon_log, stderr=subprocess.STDOUT, start_new_session=True)
    tester = None
    benign = None
    try:
        for _ in range(60):
            try:
                if status(args.port)["pmu_state"] in {"MONITORING", "DEGRADED"}:
                    break
            except Exception:
                pass
            time.sleep(0.25)
        initial = status(args.port)
        if initial["pmu_state"] != "MONITORING":
            raise RuntimeError("PMU unavailable: " + initial["reason"])
        print(f"run={run_id} state={output} dashboard=http://127.0.0.1:{args.port}", flush=True)
        with (output / "observations.jsonl").open("w") as observations, (output / "tester.log").open("w") as tester_log:
            print("baseline started", flush=True)
            metadata["phases"]["baseline"] = {"start": utc_now()}
            wait_seconds(args.baseline_seconds, "baseline", args.port, observations)
            metadata["phases"]["baseline"]["end"] = utc_now()
            if args.benign_seconds:
                print("benign memory control started", flush=True)
                metadata["phases"]["benign_memory"] = {"start": utc_now()}
                with (output / "benign.log").open("w") as benign_log:
                    benign = subprocess.Popen([sys.executable, str(Path(__file__).with_name("benign_memory.py"))],
                                              stdout=benign_log, stderr=subprocess.STDOUT, start_new_session=True)
                    wait_seconds(args.benign_seconds, "benign_memory", args.port, observations)
                    os.killpg(benign.pid, signal.SIGTERM)
                    benign.wait(timeout=5)
                metadata["phases"]["benign_memory"]["end"] = utc_now()
                metadata["phases"]["settle"] = {"start": utc_now()}
                wait_seconds(2, "settle", args.port, observations)
                metadata["phases"]["settle"]["end"] = utc_now()
            print("tester started", flush=True)
            metadata["phases"]["attack"] = {"start": utc_now()}
            tester = subprocess.Popen([str(tester_path)], cwd=args.source, stdout=tester_log, stderr=subprocess.STDOUT,
                                      start_new_session=True)
            wait_seconds(args.attack_seconds, "attack", args.port, observations)
            if tester.poll() is None:
                os.killpg(tester.pid, signal.SIGTERM)
                try:
                    tester.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(tester.pid, signal.SIGKILL)
                    tester.wait(timeout=5)
            metadata["phases"]["attack"]["end"] = utc_now()
            metadata["tool_result"] = {"returncode": tester.returncode, "bounded_stop": True}
            print(f"tester stopped returncode={tester.returncode}", flush=True)
            metadata["phases"]["post"] = {"start": utc_now()}
            print("post-test control started", flush=True)
            wait_seconds(args.post_seconds, "post", args.port, observations)
            metadata["phases"]["post"]["end"] = utc_now()
        print("capture complete", flush=True)
    finally:
        if benign and benign.poll() is None:
            os.killpg(benign.pid, signal.SIGKILL)
            benign.wait(timeout=5)
        if tester and tester.poll() is None:
            os.killpg(tester.pid, signal.SIGKILL)
            tester.wait(timeout=5)
        if server.poll() is None:
            os.killpg(server.pid, signal.SIGINT)
            try:
                server.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(server.pid, signal.SIGKILL)
        daemon_log.close()
        (output / "manifest.json").write_text(json.dumps(metadata, indent=2) + "\n")
        print(f"manifest={output / 'manifest.json'}", flush=True)


if __name__ == "__main__":
    main()
