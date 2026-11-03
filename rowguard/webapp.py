"""Monitoring API and bundled dashboard with an audited display reset."""
from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, StreamingResponse

from .features import FEATURES
from .service import RowGuardService

ROOT = Path(__file__).resolve().parent.parent


def create_app(state_dir: Path, collector_factory=None) -> FastAPI:
    service = RowGuardService(state_dir, collector_factory) if collector_factory else RowGuardService(state_dir)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await service.start()
        yield
        await service.stop()

    app = FastAPI(title="RowGuard", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.rowguard = service

    @app.get("/api/v1/status")
    async def status():
        return service.status()

    @app.get("/api/v1/features")
    async def features():
        return [{"id": key, "label": label, "unit": unit,
                 "available": key in service.last_values} for key, label, unit in FEATURES]

    @app.get("/api/v1/timeseries")
    async def timeseries(feature: str, hours: int = Query(1, ge=1, le=24), limit: int = Query(600, ge=1, le=3600)):
        if feature not in {f[0] for f in FEATURES}:
            raise HTTPException(400, "unknown feature")
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")
        points = []
        previous = None
        for row in service.storage.samples(since, limit):
            instant = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
            if previous and (instant - previous).total_seconds() > 2:
                points.append({"timestamp": (previous + (instant - previous) / 2).isoformat().replace("+00:00", "Z"), "value": None})
            points.append({"timestamp": row["timestamp"], "value": row["values"].get(feature)})
            previous = instant
        return points

    @app.get("/api/v1/incidents")
    async def incidents():
        return service.storage.incidents()

    @app.get("/api/v1/audit")
    async def audit(limit: int = Query(50, ge=1, le=200)):
        # Bounded to avoid streaming unbounded evidence to a browser.
        with service.audit.log_path.open("rb") as stream:
            from collections import deque
            lines = deque(stream, maxlen=limit)
        visible_from = service.storage.visible_audit_from()
        return [record for line in reversed(lines) if (record := json.loads(line))["seq"] >= visible_from]

    @app.post("/api/v1/history/clear")
    async def clear_history(request: Request):
        # A custom header prevents cross-site form POSTs from clearing the UI.
        if request.headers.get("X-RowGuard-Action") != "clear-visible-history":
            raise HTTPException(403, "clear action header required")
        return service.clear_display_history()

    @app.get("/api/v1/integrity")
    async def integrity():
        return service.integrity()

    @app.get("/api/v1/events")
    async def events(request: Request):
        queue = service.subscribe()

        async def stream():
            try:
                yield "event: reset\ndata: " + json.dumps(service.status()) + "\n\n"
                while not await request.is_disconnected():
                    try:
                        name, payload = await asyncio.wait_for(queue.get(), timeout=15)
                        yield f"event: {name}\ndata: {json.dumps(payload)}\n\n"
                    except asyncio.TimeoutError:
                        yield ": heartbeat\n\n"
            finally:
                service.unsubscribe(queue)
        return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-store"})

    @app.get("/")
    async def index():
        return FileResponse(ROOT / "web" / "index.html")

    @app.get("/{asset_name}")
    async def asset(asset_name: str):
        if asset_name not in {"app.js", "styles.css"}:
            raise HTTPException(404)
        return FileResponse(ROOT / "web" / asset_name)

    return app
