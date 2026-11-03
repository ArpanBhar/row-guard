# RowGuard

RowGuard monitors Linux hardware counters and shows suspected Rowhammer activity in a web dashboard. The detector is experimental: an alert does not prove a bit flip.

## Start the server

From this folder:

```bash
python3 -m pip install -e .
rowguard serve --state-dir ./state --host 127.0.0.1 --port 8765
```

Open **http://127.0.0.1:8765** and wait for `MONITORING`. Leave the server running. If it shows `DEGRADED` because PMU access is denied, run `sudo sysctl -w kernel.perf_event_paranoid=0` and restart the server.

## Run the Rowhammer demo

In a second terminal, from this folder:

```bash
./tools/rowhammer_test
```

The Google test binary is included at `tools/rowhammer_test`. Watch for the dashboard's `SUSPICIOUS` badge and an entry in **Incidents**. Press **Ctrl+C** in that same terminal to stop the test. The tester forks a child, and Ctrl+C in a foreground terminal sends the interrupt to both processes.

Incidents show the top CPU-using process names and PIDs when available. These are **candidates, not confirmed attackers**, because the PMU counters cover the whole machine. Use **Clear visible log** in the Incidents or Evidence view to reset the displayed history; the signed audit file is kept for verification.

For an automatic 35-second stop, use:

```bash
python3 tools/run_attack_once.py --tester ./tools/rowhammer_test --seconds 35
```

The test uses about 1 GiB of RAM and can cause memory errors; run it only on the disposable lab machine. To check the local audit log afterward:

```bash
rowguard verify --state-dir ./state
```
