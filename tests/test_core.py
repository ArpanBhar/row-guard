import json
import tempfile
import unittest
import csv
import asyncio
from pathlib import Path

import httpx

from rowguard.audit import AuditLog, verify
from rowguard.anchor import create_receiver
from rowguard.collector import CounterReading, delta
from rowguard.detector import IncidentPolicy
from rowguard.features import FeatureWindow
from rowguard.model import LinearModel
from rowguard.processes import ProcessObserver, parse_stat
from rowguard.service import RowGuardService
from rowguard.webapp import create_app
from ml.train import train
from tools.verify import verify_log


class CounterTests(unittest.TestCase):
    def test_group_scaling_is_per_cpu(self):
        names = ("cycles", "instructions", "cache_references", "cache_misses")
        old = CounterReading(0, {n: 0 for n in names}, 0, 0,
                             (({n: 0 for n in names}, 0, 0), ({n: 0 for n in names}, 0, 0)))
        first = {n: 100 for n in names}
        second = {n: 200 for n in names}
        now = CounterReading(1_000_000_000, {n: 300 for n in names}, 200, 150,
                             ((first, 100, 100), (second, 100, 50)))
        rates, quality = delta(old, now, min_ratio=0.5)
        self.assertEqual(rates["cycles_per_s"], 500.0)
        self.assertEqual(quality["running_ratio"], 0.5)

    def test_quality_gap_never_becomes_zero(self):
        values = {n: 0 for n in ("cycles", "instructions", "cache_references", "cache_misses")}
        before = CounterReading(0, values, 0, 0)
        after = CounterReading(1_000_000_000, values, 100, 0)
        rates, quality = delta(before, after)
        self.assertIsNone(rates)
        self.assertFalse(quality["valid"])

    def test_process_candidate_uses_cpu_delta_and_pid_start_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            process = root / "123"
            process.mkdir()
            now = [0.0]
            observer = ProcessObserver(root, clock=lambda: now[0], ticks_per_second=100)

            def write_stat(ticks, start):
                fields = ["R"] + ["0"] * 19
                fields[11] = str(ticks)
                fields[19] = str(start)
                (process / "stat").write_text(f"123 (rowhammer_test) {' '.join(fields)}\n")

            write_stat(0, 900)
            self.assertEqual(observer.sample(), [])
            now[0] = 1.0
            write_stat(90, 900)
            candidate = observer.sample()[0]
            self.assertEqual((candidate["name"], candidate["pid"], candidate["cpu_percent_one_core"]),
                             ("rowhammer_test", 123, 90.0))
            now[0] = 2.0
            write_stat(180, 901)  # PID reused: no delta across different processes.
            self.assertEqual(observer.sample(), [])
            self.assertIsNone(parse_stat("malformed"))


class PolicyTests(unittest.TestCase):
    def test_three_of_five_opens_then_five_quiet_closes(self):
        policy = IncidentPolicy(0.8)
        events = []
        for i, score in enumerate([0.9, 0.1, 0.9, 0.1, 0.9] + [0.1] * 5):
            event, _ = policy.update(f"t{i}", score, "incident-1")
            if event:
                events.append(event)
        self.assertEqual(events, ["INCIDENT_OPENED", "INCIDENT_CLOSED"])
        self.assertIsNone(policy.active)

    def test_gap_discards_stale_votes(self):
        policy = IncidentPolicy()
        for i in range(4):
            policy.update(str(i), 0.9, "id")
        policy.gap()
        event, _ = policy.update("after", 0.9, "id")
        self.assertIsNone(event)

    def test_feature_window_has_real_variability(self):
        window = FeatureWindow(3)
        features = None
        for misses in [100.0, 200.0, 300.0]:
            features = window.add({"cycles_per_s": 1000, "instructions_per_s": 500,
                                   "cache_references_per_s": 400, "cache_misses_per_s": misses}, 1.0)
        self.assertAlmostEqual(features["ipc"], 0.5)
        self.assertAlmostEqual(features["cache_miss_ratio"], 0.5)
        self.assertGreater(features["cache_miss_cv"], 0)


class AuditTests(unittest.TestCase):
    def test_signature_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            log = AuditLog(path)
            log.append("INCIDENT_OPENED", {"score": 0.91})
            log.append("INCIDENT_CLOSED", {"score": 0.11})
            log.checkpoint()
            log.close()
            good = verify(path / "audit.jsonl", path / "checkpoint.json", path / "signing.pub")
            self.assertTrue(good["ok"])
            self.assertEqual(good["locally_signed_through"], 2)
            independent = verify_log(path / "audit.jsonl", path / "signing.pub", path / "checkpoint.json")
            self.assertTrue(independent["ok"])
            data = (path / "audit.jsonl").read_text().replace('0.91', '0.92')
            (path / "audit.jsonl").write_text(data)
            bad = verify(path / "audit.jsonl", path / "checkpoint.json", path / "signing.pub")
            self.assertFalse(bad["ok"])
            self.assertFalse(verify_log(path / "audit.jsonl", path / "signing.pub", path / "checkpoint.json")["ok"])

    def test_signed_tail_truncation_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            log = AuditLog(path)
            log.append("ONE", {})
            log.append("TWO", {})
            log.checkpoint()
            log.close()
            lines = (path / "audit.jsonl").read_bytes().splitlines(keepends=True)
            (path / "audit.jsonl").write_bytes(lines[0])
            result = verify(path / "audit.jsonl", path / "checkpoint.json", path / "signing.pub")
            self.assertFalse(result["ok"])
            self.assertIn("shorter", result["error"])
            self.assertFalse(verify_log(path / "audit.jsonl", path / "signing.pub", path / "checkpoint.json")["ok"])

    def test_independent_receiver_rejects_conflicting_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            log = AuditLog(source)
            log.append("ONE", {})
            checkpoint = log.checkpoint()
            key_dir = root / "trusted-keys"
            key_dir.mkdir()
            (key_dir / (log.host + ".pub")).write_bytes(log.public_path.read_bytes())
            app = create_receiver(key_dir, root / "receiver.sqlite3", "lab-token")
            async def check_receiver():
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url="http://receiver") as client:
                    headers = {"Authorization": "Bearer lab-token"}
                    self.assertEqual((await client.post("/v1/checkpoints", json=checkpoint)).status_code, 401)
                    self.assertEqual((await client.post("/v1/checkpoints", json=checkpoint, headers=headers)).status_code, 200)
                    self.assertEqual((await client.post("/v1/checkpoints", json=checkpoint, headers=headers)).status_code, 200)
                    log.append("TWO", {})
                    second = log.checkpoint()
                    self.assertEqual((await client.post("/v1/checkpoints", json=second, headers=headers)).status_code, 200)
                    self.assertEqual((await client.post("/v1/checkpoints", json=checkpoint, headers=headers)).status_code, 409)
                    latest = (await client.get(f"/v1/latest/{log.host}", headers=headers)).json()
                    self.assertEqual(latest["signed"]["seq"], 2)
                self.assertEqual(verify_log(log.log_path, log.public_path, log.checkpoint_path, latest)["remote_anchored_through"], 2)
            asyncio.run(check_receiver())
            log.close()


class RuntimeTests(unittest.TestCase):
    def test_dashboard_clear_hides_old_history_but_preserves_signed_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def denied():
                raise PermissionError("fixture PMU unavailable")
            app = create_app(root, denied)

            async def check_app():
                async with app.router.lifespan_context(app):
                    service = app.state.rowguard
                    service.storage.put_incident({"id": "old", "opened_at": "2026-01-01T00:00:00Z",
                                                  "status": "closed", "peak_score": 0.9,
                                                  "suspicious_windows": 3})
                    service.audit.append("INCIDENT_CLOSED", {"incident_id": "old"})
                    service.audit.checkpoint()
                    transport = httpx.ASGITransport(app=app)
                    async with httpx.AsyncClient(transport=transport, base_url="http://app") as client:
                        self.assertEqual(len((await client.get("/api/v1/incidents")).json()), 1)
                        self.assertEqual((await client.post("/api/v1/history/clear")).status_code, 403)
                        response = await client.post("/api/v1/history/clear",
                                                     headers={"X-RowGuard-Action": "clear-visible-history"})
                        self.assertEqual(response.status_code, 200)
                        self.assertEqual((await client.get("/api/v1/incidents")).json(), [])
                        visible = (await client.get("/api/v1/audit")).json()
                        self.assertEqual([record["event"] for record in visible], ["DASHBOARD_HISTORY_CLEARED"])
                        self.assertTrue((await client.get("/api/v1/integrity")).json()["ok"])
                        self.assertIn("INCIDENT_CLOSED", (root / "audit.jsonl").read_text())

            asyncio.run(check_app())

    def test_real_pipeline_fixture_persists_incident_and_history(self):
        with tempfile.TemporaryDirectory() as directory:
            service = RowGuardService(Path(directory), lambda: None)
            names = ("cycles", "instructions", "cache_references", "cache_misses")
            previous = CounterReading(0, {name: 0 for name in names}, 0, 0)
            counters = {name: 0 for name in names}
            for i in range(16):
                counters["cycles"] += 100_000_000
                counters["instructions"] += 50_000_000
                counters["cache_references"] += 10_000_000
                counters["cache_misses"] += 6_000_000
                current = CounterReading((i + 1) * 100_000_000, counters.copy(),
                                         (i + 1) * 100_000_000, (i + 1) * 100_000_000)
                service.ingest(current, previous)
                previous = current
            incidents = service.storage.incidents()
            self.assertEqual(len(incidents), 1)
            self.assertEqual(incidents[0]["status"], "active")
            self.assertEqual(incidents[0]["suspicious_windows"], 7)
            self.assertGreater(service.last_score, service.policy.threshold)
            self.assertTrue(service.storage.samples("2000", 100))
            self.assertTrue(verify(service.audit.log_path, service.audit.checkpoint_path, service.audit.public_path)["ok"])
            service.audit.close()
            service.storage.close()

    def test_dashboard_api_reports_real_permission_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            def denied():
                raise PermissionError("PMU denied by test")
            app = create_app(Path(directory), denied)
            async def check_app():
                async with app.router.lifespan_context(app):
                    await asyncio.sleep(0.02)
                    transport = httpx.ASGITransport(app=app)
                    async with httpx.AsyncClient(transport=transport, base_url="http://app") as client:
                        status = (await client.get("/api/v1/status")).json()
                        self.assertEqual(status["pmu_state"], "DEGRADED")
                        self.assertIsNone(status["risk_score"])
                        self.assertIn("PMU denied", status["reason"])
                        self.assertEqual(len((await client.get("/api/v1/features")).json()), 9)
                        self.assertEqual((await client.get("/api/v1/timeseries?feature=risk_score")).json(), [])
            asyncio.run(check_app())

    def test_train_and_load_run_grouped_model(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_path = root / "train.csv"
            with csv_path.open("w", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(["run_id", "label", "cache_misses_per_s", "cache_miss_ratio", "cache_miss_cv", "ipc"])
                for run in range(12):
                    label = run % 2
                    for step in range(10):
                        writer.writerow([f"run-{run}", label, 100_000 + label * 3_000_000 + step * 1000,
                                         0.05 + label * 0.3, 0.7 - label * 0.6, 1.5 - label * 0.5])
            artifact = root / "model.json"
            report = train(csv_path, artifact)
            self.assertEqual(sum(report["run_counts"].values()), 12)
            model = LinearModel(artifact)
            low = model.score({"cache_misses_per_s": 100_000, "cache_miss_ratio": 0.05,
                               "cache_miss_cv": 0.7, "ipc": 1.5})
            high = model.score({"cache_misses_per_s": 3_100_000, "cache_miss_ratio": 0.35,
                                "cache_miss_cv": 0.1, "ipc": 1.0})
            self.assertGreater(high, low)


if __name__ == "__main__":
    unittest.main()
