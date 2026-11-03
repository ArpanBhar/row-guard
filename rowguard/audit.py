"""Append-only hash chain with Ed25519-signed local checkpoints.

The byte format is RowGuard JSON v1, not RFC 8785. That difference is explicit
so a future cross-language format migration cannot silently change hashes.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import time
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DOMAIN = b"RowGuard/audit-json-v1\0"
GENESIS = "0" * 64


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(record: dict) -> str:
    body = {key: value for key, value in record.items() if key != "record_hash"}
    return hashlib.sha256(DOMAIN + canonical(body)).hexdigest()


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def verify(log_path: Path, checkpoint_path: Path | None = None, public_key_path: Path | None = None) -> dict:
    sequence = 0
    previous = GENESIS
    expected_chain = None
    expected_host = None
    try:
        if log_path.exists():
            with log_path.open("rb") as stream:
                for line_number, line in enumerate(stream, 1):
                    if not line.endswith(b"\n"):
                        raise ValueError(f"incomplete record at line {line_number}")
                    record = json.loads(line)
                    if sequence == 0:
                        expected_chain = record.get("chain_id")
                        expected_host = record.get("host")
                    if record.get("chain_id") != expected_chain or record.get("host") != expected_host:
                        raise ValueError(f"identity changed at sequence {sequence + 1}")
                    if record.get("seq") != sequence + 1:
                        raise ValueError(f"sequence gap at line {line_number}")
                    if record.get("previous_hash") != previous:
                        raise ValueError(f"chain mismatch at sequence {sequence + 1}")
                    if digest(record) != record.get("record_hash"):
                        raise ValueError(f"record hash mismatch at sequence {sequence + 1}")
                    if canonical(record) + b"\n" != line:
                        raise ValueError(f"noncanonical record at sequence {sequence + 1}")
                    sequence += 1
                    previous = record["record_hash"]
        anchored = 0
        if checkpoint_path and checkpoint_path.exists():
            if not public_key_path or not public_key_path.exists():
                raise ValueError("checkpoint present but trusted public key unavailable")
            checkpoint = json.loads(checkpoint_path.read_bytes())
            signed = checkpoint["signed"]
            signature = bytes.fromhex(checkpoint["signature"])
            public = Ed25519PublicKey.from_public_bytes(public_key_path.read_bytes())
            public.verify(signature, canonical(signed))
            if signed["seq"] > sequence:
                raise ValueError("log shorter than signed checkpoint")
            if signed.get("chain_id") != expected_chain or signed.get("host") != expected_host:
                raise ValueError("checkpoint host or chain mismatch")
            # A full verification must compare the checkpoint's historical head,
            # not just the final head. Re-scan until the signed boundary.
            if signed["seq"] == 0:
                head_at_checkpoint = GENESIS
            else:
                with log_path.open("rb") as stream:
                    for number, line in enumerate(stream, 1):
                        if number == signed["seq"]:
                            head_at_checkpoint = json.loads(line)["record_hash"]
                            break
            if head_at_checkpoint != signed["head"]:
                raise ValueError("signed checkpoint head mismatch")
            anchored = signed["seq"]
        return {"ok": True, "sequence": sequence, "head": previous, "locally_signed_through": anchored,
                "externally_anchored_through": 0, "error": None}
    except Exception as exc:
        return {"ok": False, "sequence": sequence, "head": previous, "locally_signed_through": 0,
                "externally_anchored_through": 0, "error": str(exc)}


class AuditLog:
    def __init__(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True)
        self.log_path = directory / "audit.jsonl"
        self.checkpoint_path = directory / "checkpoint.json"
        self.checkpoint_history_path = directory / "checkpoints.jsonl"
        self.chain_id_path = directory / "chain_id"
        self.private_path = directory / "signing.key"
        self.public_path = directory / "signing.pub"
        if not self.chain_id_path.exists():
            _atomic_write(self.chain_id_path, (str(uuid.uuid4()) + "\n").encode())
        self.chain_id = self.chain_id_path.read_text().strip()
        self.host = socket.gethostname()
        try:
            self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        except OSError:
            self.boot_id = "unknown"
        if not self.private_path.exists():
            private = Ed25519PrivateKey.generate()
            raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            _atomic_write(self.private_path, raw)
            _atomic_write(self.public_path, private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), 0o644)
        self.private = Ed25519PrivateKey.from_private_bytes(self.private_path.read_bytes())
        result = verify(self.log_path, self.checkpoint_path, self.public_path)
        if not result["ok"]:
            raise ValueError(f"audit history verification failed: {result['error']}")
        self.sequence = result["sequence"]
        self.head = result["head"]
        self._fd = os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)

    def append(self, event: str, payload: dict, *, durable: bool = True) -> dict:
        from datetime import datetime, timezone
        record = {"schema": 1, "seq": self.sequence + 1,
                  "timestamp_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                  "monotonic_ns": str(time.monotonic_ns()), "boot_id": self.boot_id,
                  "chain_id": self.chain_id, "host": self.host,
                  "event": event, "payload": payload, "previous_hash": self.head}
        record["record_hash"] = digest(record)
        line = canonical(record) + b"\n"
        written = os.write(self._fd, line)
        if written != len(line):
            raise OSError("short audit write")
        if durable:
            os.fsync(self._fd)
        self.sequence += 1
        self.head = record["record_hash"]
        return record

    def checkpoint(self) -> dict:
        from datetime import datetime, timezone
        os.fsync(self._fd)
        if self.checkpoint_path.exists():
            prior = json.loads(self.checkpoint_path.read_bytes())
            if prior["signed"]["seq"] == self.sequence:
                return prior
        previous_checkpoint_hash = GENESIS
        if self.checkpoint_history_path.exists():
            with self.checkpoint_history_path.open("rb") as stream:
                for line in stream:
                    if line.strip():
                        previous_checkpoint_hash = hashlib.sha256(line.rstrip(b"\n")).hexdigest()
        signed = {"schema": 1, "seq": self.sequence, "head": self.head,
                  "host": self.host, "chain_id": self.chain_id,
                  "key_id": hashlib.sha256(self.public_path.read_bytes()).hexdigest()[:16],
                  "previous_checkpoint_hash": previous_checkpoint_hash,
                  "timestamp_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        checkpoint = {"signed": signed, "signature": self.private.sign(canonical(signed)).hex()}
        history_fd = os.open(self.checkpoint_history_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            line = canonical(checkpoint) + b"\n"
            if os.write(history_fd, line) != len(line):
                raise OSError("short checkpoint history write")
            os.fsync(history_fd)
        finally:
            os.close(history_fd)
        _atomic_write(self.checkpoint_path, canonical(checkpoint) + b"\n")
        return checkpoint

    def close(self) -> None:
        os.close(self._fd)
