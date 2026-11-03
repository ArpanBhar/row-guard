# RowGuard

RowGuard is a Linux PMU monitoring daemon with a web dashboard for suspected Rowhammer activity. It scores one-second rolling hardware-counter windows with a bundled logistic-regression model and opens an incident after three suspicious scores in five valid windows. An alert means the measured pattern resembles the test workload; it does **not** prove a bit flip or identify an attacking process.

## Run on the monitored computer

Requires Linux x86-64, Python 3.11+, and PMU access. In this folder:

```bash
python3 -m pip install -e .
rowguard serve --state-dir ./state --host 127.0.0.1 --port 8765
```

Open **http://127.0.0.1:8765** on the same computer. Wait for `MONITORING`. If the dashboard says PMU access is denied, run `sudo sysctl -w kernel.perf_event_paranoid=0`, then restart RowGuard. This sysctl change may reset after reboot. Keep the daemon terminal open during the demo. The [systemd unit](packaging/systemd/rowguard.service) is a starting point for background installation.

## Open the dashboard on another computer

Run [cloudflared](https://developers.cloudflare.com/tunnel/downloads/) **on the monitored computer**, in another terminal. For a short lab demo, use a [Quick Tunnel](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/) restricted to your email:

```bash
cloudflared tunnel --url http://127.0.0.1:8765 --allowed-mail you@example.com
```

Replace the email address and open the printed `https://…trycloudflare.com` URL on the other computer. RowGuard stays bound to loopback; the tunnel forwards its dashboard and `/api/v1` endpoints under **one hostname**, so the browser does not make cross-origin API requests. Quick Tunnels do not support Server-Sent Events; the dashboard automatically polls about every two seconds. The URL ends when `cloudflared` stops.

For a stable hostname, create a [named Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/get-started/), route its public hostname to `http://127.0.0.1:8765`, and protect the hostname with [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/setup/secure-private-apps/private-web-app/). Keep RowGuard on `127.0.0.1`; publish the entire app through the tunnel, including the API. A named tunnel can carry the live event stream. Do not publish a second API hostname.

## Demo the detector

On the **monitored computer**, in a separate foreground terminal:

```bash
./tools/rowhammer_test
```

The bundled Google test binary should cause `SUSPICIOUS` and an incident in the dashboard on the tested host. Press **Ctrl+C** in that terminal to stop it. For a bounded run instead:

```bash
python3 tools/run_attack_once.py --tester ./tools/rowhammer_test --seconds 35
```

The test allocates roughly 1 GiB of RAM and may cause memory errors. Use the disposable lab host. The tool may report no bit flips even when RowGuard detects its activity. Incidents show high-CPU process **candidates**, not confirmed attribution, because PMU counters cover the whole system. **Clear visible log** hides older dashboard entries while preserving the signed audit records.

## Evidence and model choice

```bash
rowguard verify --state-dir ./state
python3 -m unittest discover -s tests -q
```

We chose the packaged logistic model because a run-disjoint comparison found **0 benign incident openings**, **10/10 test runs detected**, and **92.7% window recall** on the original ten-run corpus. A scikit-learn logistic variant had higher window recall but opened three benign incidents. On two later runs, the exact packaged model detected both attack runs, with **69.2% window recall** and no measured benign incidents. These are short, single-host, single-tool experiments, not production accuracy claims. See the [model comparison](docs/MODEL_COMPARISON.md), [ML evaluation](docs/ML_EVALUATION.md), and final report ([DOCX](docs/RowGuard_Final_Report.docx) · [PDF](docs/RowGuard_Final_Report.pdf)).

Audit records are hash-chained and locally signed. Without an independently configured off-host checkpoint receiver, local verification cannot rule out deletion or rollback by someone controlling the monitored host.
