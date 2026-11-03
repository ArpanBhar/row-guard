"""The monitoring daemon's in-process state and collection loop."""
from __future__ import annotations

import asyncio
import json
import os
import platform
import socket
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .audit import AuditLog, verify
from .anchor import AnchorClient
from .collector import PerfCollector, delta
from .detector import IncidentPolicy, experimental_score
from .features import FEATURES, FeatureWindow
from .model import LinearModel
from .processes import ProcessObserver
from .storage import Storage


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class RowGuardService:
    def __init__(self, state_dir: Path, collector_factory=PerfCollector):
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.audit = AuditLog(state_dir)
        anchor_url = os.environ.get("ROWGUARD_ANCHOR_URL")
        self.anchor = AnchorClient(state_dir, anchor_url, os.environ.get("ROWGUARD_ANCHOR_TOKEN", "")) if anchor_url else None
        self.storage = Storage(state_dir / "telemetry.sqlite3")
        self.collector_factory = collector_factory
        self.collector = None
        self.window = FeatureWindow()
        self.policy = IncidentPolicy()
        self.process_observer = ProcessObserver(exclude_pid=os.getpid())
        self.process_observer.sample()
        model_path = os.environ.get("ROWGUARD_MODEL_PATH")
        self.model = None
        self.model_error = None
        if model_path:
            try:
                self.model = LinearModel(Path(model_path))
                self.policy.threshold = self.model.threshold
            except (OSError, ValueError) as exc:
                self.model_error = str(exc)
        self.host = socket.gethostname()
        self.boot_id = self._boot_id()
        self.session_id = str(uuid.uuid4())
        self.pmu_state = "STARTING"
        self.reason = "Waiting for PMU discovery"
        self.last_sample: str | None = None
        self.last_values: dict = {}
        self.last_quality: dict = {}
        self.last_score: float | None = None
        self.dropped_windows = 0
        self._task: asyncio.Task | None = None
        self._maintenance_task: asyncio.Task | None = None
        self._anchor_task: asyncio.Task | None = None
        self._subscribers: set[asyncio.Queue] = set()
        self._last_checkpoint = 0.0
        for row in self.storage.incidents():
            if row["status"] == "active":
                row["status"] = "interrupted"
                self.audit.append("INCIDENT_INTERRUPTED", {"incident": row, "reason": "daemon restarted"})
                self.storage.put_incident(row)
        self.audit.append("DAEMON_STARTED", {"host": self.host, "boot_id": self.boot_id, "session_id": self.session_id,
                                             "kernel": platform.release()})
        self.audit.checkpoint()

    @staticmethod
    def _boot_id() -> str:
        try:
            return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        except OSError:
            return "unknown"

    def status(self) -> dict:
        checkpoint = self._checkpoint_summary()
        return {"host": self.host, "boot_id": self.boot_id, "session_id": self.session_id,
                "pmu_state": self.pmu_state, "reason": self.reason, "last_sample": self.last_sample,
                "values": self.last_values, "quality": self.last_quality, "risk_score": self.last_score,
                "detector": self.model.id if self.model else "experimental_pmu_rule_v4",
                "model_error": self.model_error, "model_sha256": self.model.sha256 if self.model else None,
                "threshold": self.policy.threshold,
                "active_incident": self.policy.active.as_dict() if self.policy.active else None,
                "visible_audit_from": self.storage.visible_audit_from(),
                "dropped_windows": self.dropped_windows, "audit_sequence": self.audit.sequence,
                "local_checkpoint": checkpoint,
                "external_anchor": ({"state": "ACKNOWLEDGED" if self.anchor.acked_sequence > 0
                                     and self.anchor.acked_sequence >= checkpoint["sequence"]
                                     and not self.anchor.last_error else "STALE",
                                     "sequence": self.anchor.acked_sequence,
                                     "error": self.anchor.last_error} if self.anchor else
                                    {"state": "NOT_CONFIGURED", "sequence": 0})}

    def _checkpoint_summary(self) -> dict:
        try:
            record = json.loads(self.audit.checkpoint_path.read_bytes())
            return {"sequence": record["signed"]["seq"], "timestamp": record["signed"]["timestamp_utc"]}
        except (OSError, ValueError, KeyError):
            return {"sequence": 0, "timestamp": None}

    def integrity(self) -> dict:
        result = verify(self.audit.log_path, self.audit.checkpoint_path, self.audit.public_path)
        result["trust_level"] = "local_signature_only" if not self.anchor else "receiver_acknowledged_not_independently_verified"
        result["external_anchor"] = self.status()["external_anchor"]
        result["checked_at"] = utc_now()
        return result

    def clear_display_history(self) -> dict:
        active_id = self.policy.active.id if self.policy.active else None
        record = self.audit.append("DASHBOARD_HISTORY_CLEARED", {"active_incident_id": active_id,
                                                                  "scope": "visible_incidents_and_audit"})
        self.audit.checkpoint()
        self.storage.clear_display_history(record["seq"])
        result = {"cleared_at": record["timestamp_utc"], "visible_audit_from": record["seq"],
                  "active_incident_retained": active_id is not None}
        self.publish("history", result)
        return result

    def publish(self, name: str, data: dict) -> None:
        for queue in tuple(self._subscribers):
            try:
                queue.put_nowait((name, data))
            except asyncio.QueueFull:
                # Slow clients must resynchronize from the current snapshot.
                try:
                    queue.get_nowait()
                    queue.put_nowait(("reset", self.status()))
                except asyncio.QueueEmpty:
                    pass

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=16)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    def _set_degraded(self, reason: str) -> None:
        changed = self.pmu_state != "DEGRADED" or self.reason != reason
        self.pmu_state = "DEGRADED"
        self.reason = reason
        self.last_score = None
        self.last_values = {}
        self.window.clear()
        if self.policy.active:
            incident = self.policy.active
            incident.status = "interrupted"
            self.audit.append("INCIDENT_INTERRUPTED", {"incident": incident.as_dict(), "reason": reason})
            self.storage.put_incident(incident.as_dict())
            self.policy.active = None
            self.publish("incident", incident.as_dict())
        self.policy.gap()
        if changed:
            self.audit.append("COLLECTOR_DEGRADED", {"reason": reason, "host": self.host})
            self.publish("status", self.status())

    def ingest(self, current, previous) -> None:
        rates, quality = delta(previous, current)
        self.last_quality = quality
        if rates is None:
            self.dropped_windows += 1
            self._set_degraded(quality["reason"] or "invalid PMU sample")
            return
        self.pmu_state = "MONITORING"
        self.reason = ("Model unavailable: " + self.model_error if self.model_error else
                       "Real PMU counters available; " + ("trained model active" if self.model else "experimental PMU rule active"))
        timestamp = utc_now()
        self.last_sample = timestamp
        features = self.window.add(rates, quality["running_ratio"])
        if features is None:
            self.publish("status", self.status())
            return
        if self.model_error:
            self.last_values = features
            self.last_score = None
            self.storage.add_sample(timestamp, features, quality)
            self.policy.gap()
            self.publish("status", self.status())
            return
        try:
            score = self.model.score(features) if self.model else experimental_score(features)
        except ValueError as exc:
            self.model_error = str(exc)
            self._set_degraded("model inference failed: " + str(exc))
            return
        features["risk_score"] = score
        self.last_values = features
        self.last_score = score
        self.storage.add_sample(timestamp, features, quality)
        event, incident = self.policy.update(timestamp, score, str(uuid.uuid4()))
        candidates_added = False
        if incident and not incident.process_candidates:
            candidates = self.process_observer.fresh_candidates()
            if candidates:
                incident.process_candidates = candidates
                candidates_added = event != "INCIDENT_OPENED"
        if incident:
            self.storage.put_incident(incident.as_dict())
        if candidates_added:
            self.audit.append("INCIDENT_PROCESS_CANDIDATES", {"incident_id": incident.id,
                                                               "process_candidates": incident.process_candidates,
                                                               "attribution": "unverified_cpu_activity"})
            self.publish("incident", incident.as_dict())
        if event:
            self.audit.append(event, {"incident": incident.as_dict(), "features": features,
                                      "quality": quality, "detector": self.model.id if self.model else "experimental_pmu_rule_v4",
                                      "model_sha256": self.model.sha256 if self.model else None})
            self.audit.checkpoint()
            self._last_checkpoint = time.monotonic()
            self.publish("incident", incident.as_dict())
        self.publish("sample", {"timestamp": timestamp, "values": features, "quality": quality,
                                "risk_score": score})

    async def _loop(self) -> None:
        previous = None
        while True:
            if self.collector is None:
                try:
                    self.collector = self.collector_factory()
                    previous = self.collector.read()
                    self.pmu_state = "STARTING"
                    self.reason = "Collecting first window"
                    self.publish("status", self.status())
                except (OSError, RuntimeError) as exc:
                    self._set_degraded(str(exc))
                    await asyncio.sleep(5)
                    continue
            await asyncio.sleep(0.1)
            try:
                if self.process_observer.due():
                    self.process_observer.sample()
                current = self.collector.read()
                self.ingest(current, previous)
                previous = current
            except (OSError, ValueError) as exc:
                self.collector.close()
                self.collector = None
                previous = None
                self._set_degraded(str(exc))

    async def _maintenance_loop(self) -> None:
        while True:
            await asyncio.sleep(30)
            self.audit.checkpoint()
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat().replace("+00:00", "Z")
            self.storage.prune_samples(cutoff)
            self.publish("status", self.status())

    async def _anchor_loop(self) -> None:
        while True:
            await asyncio.to_thread(self.anchor.send_pending)
            self.publish("status", self.status())
            await asyncio.sleep(5)

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop())
        self._maintenance_task = asyncio.create_task(self._maintenance_loop())
        if self.anchor:
            self._anchor_task = asyncio.create_task(self._anchor_loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self._anchor_task:
            self._anchor_task.cancel()
            try:
                await self._anchor_task
            except asyncio.CancelledError:
                pass
        if self._maintenance_task:
            self._maintenance_task.cancel()
            try:
                await self._maintenance_task
            except asyncio.CancelledError:
                pass
        if self.collector:
            self.collector.close()
        self.audit.append("DAEMON_STOPPED", {"session_id": self.session_id})
        self.audit.checkpoint()
        self.audit.close()
        self.storage.close()
