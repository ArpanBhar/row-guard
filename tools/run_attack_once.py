"""Run an external Rowhammer tester briefly beside an already-running RowGuard daemon.

The Google tester forks a child and otherwise runs indefinitely. Stopping its
whole process group prevents a hammering child from surviving the time limit.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import urllib.request
from pathlib import Path


def stop_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a bounded external Rowhammer test on this host")
    parser.add_argument("--tester", type=Path, required=True, help="path to the built rowhammer_test binary")
    parser.add_argument("--seconds", type=int, default=35, help="maximum test duration (default: 35)")
    parser.add_argument("--port", type=int, default=8765, help="already-running local RowGuard port (default: 8765)")
    args = parser.parse_args()
    if args.seconds <= 0:
        parser.error("--seconds must be positive")
    try:
        tester = args.tester.resolve(strict=True)
    except FileNotFoundError:
        parser.error(f"tester not found: {args.tester}; build Google's rowhammer-test first")
    if not tester.is_file() or not os.access(tester, os.X_OK):
        parser.error(f"tester is not executable: {tester}")

    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{args.port}/api/v1/status", timeout=3) as response:
            status = json.load(response)
    except (OSError, ValueError) as exc:
        parser.error(f"RowGuard is not reachable on port {args.port}: {exc}")
    if status.get("pmu_state") != "MONITORING" or status.get("model_error"):
        parser.error(f"RowGuard is not ready to detect: {status.get('reason', status.get('pmu_state'))}")

    print(f"RowGuard ready on port {args.port} ({status.get('detector')})", flush=True)
    print(f"Starting {tester} for at most {args.seconds} seconds", flush=True)
    process = subprocess.Popen([str(tester)], cwd=tester.parent, start_new_session=True)
    try:
        process.wait(timeout=args.seconds)
        print(f"Tester exited with status {process.returncode}", flush=True)
    except subprocess.TimeoutExpired:
        print("Time limit reached; stopping tester and its child processes", flush=True)
    except KeyboardInterrupt:
        print("Interrupted; stopping tester and its child processes", flush=True)
    finally:
        stop_group(process)


if __name__ == "__main__":
    main()
