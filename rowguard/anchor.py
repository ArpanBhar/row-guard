"""Optional independent signed-checkpoint receiver and delivery client."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, Header, HTTPException

from .audit import GENESIS, _atomic_write, canonical


def create_receiver(public_keys_dir: Path, database_path: Path, token: str) -> FastAPI:
    if not token:
        raise ValueError("receiver bearer token required")
    public_keys_dir.mkdir(parents=True, exist_ok=True)
    database_path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(database_path, check_same_thread=False)
    db.execute("CREATE TABLE IF NOT EXISTS checkpoints (host TEXT NOT NULL, seq INTEGER NOT NULL, digest TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY(host,seq))")
    db.commit()
    app = FastAPI(title="RowGuard checkpoint receiver", docs_url=None, redoc_url=None)

    def authorize(authorization: str | None):
        if not hmac.compare_digest(authorization or "", "Bearer " + token):
            raise HTTPException(401, "unauthorized")

    @app.post("/v1/checkpoints")
    async def append_checkpoint(checkpoint: dict, authorization: str | None = Header(default=None)):
        authorize(authorization)
        try:
            signed = checkpoint["signed"]
            host = signed["host"]
            if not re.fullmatch(r"[A-Za-z0-9.-]{1,128}", host) or ".." in host:
                raise ValueError("invalid host identity")
            key = Ed25519PublicKey.from_public_bytes((public_keys_dir / (host + ".pub")).read_bytes())
            key.verify(bytes.fromhex(checkpoint["signature"]), canonical(signed))
            seq = signed["seq"]
            if not isinstance(seq, int) or seq < 0:
                raise ValueError("invalid sequence")
            digest = hashlib.sha256(canonical(checkpoint)).hexdigest()
            latest = db.execute("SELECT seq,digest,body FROM checkpoints WHERE host=? ORDER BY seq DESC LIMIT 1", (host,)).fetchone()
            if latest and latest[0] == seq and latest[1] == digest:
                return {"accepted": True, "host": host, "seq": seq, "digest": digest}
            if latest and signed["chain_id"] != json.loads(latest[2])["signed"]["chain_id"]:
                raise HTTPException(409, "chain identity changed")
            if latest and (seq <= latest[0] or signed["previous_checkpoint_hash"] != latest[1]):
                raise HTTPException(409, "conflicting or non-linked checkpoint")
            if not latest and signed["previous_checkpoint_hash"] != GENESIS:
                raise HTTPException(409, "first checkpoint must start at genesis")
            db.execute("INSERT INTO checkpoints VALUES (?,?,?,?)", (host, seq, digest, canonical(checkpoint).decode()))
            db.commit()
            return {"accepted": True, "host": host, "seq": seq, "digest": digest}
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/v1/latest/{host}")
    async def latest(host: str, authorization: str | None = Header(default=None)):
        authorize(authorization)
        row = db.execute("SELECT body FROM checkpoints WHERE host=? ORDER BY seq DESC LIMIT 1", (host,)).fetchone()
        if not row:
            raise HTTPException(404, "no checkpoint")
        return json.loads(row[0])

    return app


class AnchorClient:
    def __init__(self, state_dir: Path, url: str, token: str):
        if not url.startswith("https://") and not url.startswith("http://127.0.0.1:"):
            raise ValueError("anchor URL must use HTTPS, except for loopback lab tests")
        self.state_dir = state_dir
        self.url = url.rstrip("/")
        self.token = token
        self.ack_path = state_dir / "anchor-ack.json"
        self.acked_sequence = 0
        self.last_error: str | None = None
        if self.ack_path.exists():
            self.acked_sequence = json.loads(self.ack_path.read_bytes())["sequence"]

    def send_pending(self) -> None:
        history = self.state_dir / "checkpoints.jsonl"
        if not history.exists():
            return
        for line in history.read_bytes().splitlines():
            checkpoint = json.loads(line)
            seq = checkpoint["signed"]["seq"]
            if seq <= self.acked_sequence:
                continue
            request = urllib.request.Request(self.url + "/v1/checkpoints", data=canonical(checkpoint),
                headers={"Content-Type": "application/json", "Authorization": "Bearer " + self.token}, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    receipt = json.loads(response.read())
                digest = hashlib.sha256(canonical(checkpoint)).hexdigest()
                if receipt.get("seq") != seq or receipt.get("digest") != digest or not receipt.get("accepted"):
                    raise ValueError("anchor receipt mismatch")
                self.acked_sequence = seq
                _atomic_write(self.ack_path, canonical({"sequence": seq, "digest": digest}) + b"\n")
                self.last_error = None
            except Exception as exc:
                self.last_error = str(exc)
                return
