"""Bounded, rebuildable telemetry and incident query storage."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path


class Storage:
    def __init__(self, path: Path):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS samples (timestamp TEXT PRIMARY KEY, values_json TEXT NOT NULL, quality_json TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, data_json TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS dashboard_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.db.commit()

    def add_sample(self, timestamp: str, values: dict, quality: dict) -> None:
        self.db.execute("INSERT OR REPLACE INTO samples VALUES (?, ?, ?)",
                        (timestamp, json.dumps(values, allow_nan=False), json.dumps(quality, allow_nan=False)))
        self.db.commit()

    def put_incident(self, incident: dict) -> None:
        self.db.execute("INSERT OR REPLACE INTO incidents VALUES (?, ?)",
                        (incident["id"], json.dumps(incident, allow_nan=False)))
        self.db.commit()

    def samples(self, since: str, limit: int = 600) -> list[dict]:
        rows = self.db.execute("SELECT timestamp, values_json, quality_json FROM samples WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT ?", (since, limit)).fetchall()
        return [{"timestamp": t, "values": json.loads(v), "quality": json.loads(q)} for t, v, q in reversed(rows)]

    def incidents(self, limit: int = 100) -> list[dict]:
        rows = self.db.execute("SELECT data_json FROM incidents ORDER BY json_extract(data_json, '$.opened_at') DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def visible_audit_from(self) -> int:
        row = self.db.execute("SELECT value FROM dashboard_state WHERE key = 'visible_audit_from'").fetchone()
        return int(row[0]) if row else 1

    def clear_display_history(self, marker_sequence: int) -> None:
        # The signed audit file remains the source of truth. This only resets
        # the dashboard's rebuildable incident index and visible audit range.
        with self.db:
            self.db.execute("DELETE FROM incidents WHERE json_extract(data_json, '$.status') != 'active'")
            self.db.execute("INSERT OR REPLACE INTO dashboard_state VALUES ('visible_audit_from', ?)",
                            (str(marker_sequence),))

    def prune_samples(self, before: str) -> None:
        self.db.execute("DELETE FROM samples WHERE timestamp < ?", (before,))
        self.db.commit()

    def close(self) -> None:
        self.db.close()
