"""Independent verifier for RowGuard JSON v1 audit and checkpoint records.

This tool intentionally does not import the daemon or its audit implementation.
Keep a trusted copy of the host's public key outside the monitored machine.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ZERO = "0" * 64
PREFIX = b"RowGuard/audit-json-v1\0"


def serialized(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def verify_checkpoint(checkpoint, public_key, heads, host, chain_id):
    signed = checkpoint["signed"]
    public_key.verify(bytes.fromhex(checkpoint["signature"]), serialized(signed))
    sequence = signed["seq"]
    if signed["host"] != host or signed["chain_id"] != chain_id:
        raise ValueError("checkpoint host or chain mismatch")
    if sequence not in heads:
        raise ValueError(f"checkpoint #{sequence} is beyond the available log")
    if heads[sequence] != signed["head"]:
        raise ValueError(f"checkpoint head mismatch at #{sequence}")
    return sequence


def verify_log(log_path: Path, trusted_key_path: Path, local_checkpoint_path: Path | None = None,
               remote_checkpoint: dict | None = None) -> dict:
    public_key = Ed25519PublicKey.from_public_bytes(trusted_key_path.read_bytes())
    heads = {0: ZERO}
    previous = ZERO
    host = chain_id = None
    sequence = 0
    try:
        with log_path.open("rb") as stream:
            for line in stream:
                if not line.endswith(b"\n"):
                    raise ValueError(f"incomplete record after #{sequence}")
                record = json.loads(line)
                if serialized(record) + b"\n" != line:
                    raise ValueError(f"noncanonical record at #{sequence + 1}")
                if record["seq"] != sequence + 1 or record["previous_hash"] != previous:
                    raise ValueError(f"broken sequence or chain at #{sequence + 1}")
                if sequence == 0:
                    host, chain_id = record["host"], record["chain_id"]
                if record["host"] != host or record["chain_id"] != chain_id:
                    raise ValueError(f"identity changed at #{sequence + 1}")
                body = {key: value for key, value in record.items() if key != "record_hash"}
                current = hashlib.sha256(PREFIX + serialized(body)).hexdigest()
                if current != record["record_hash"]:
                    raise ValueError(f"record hash mismatch at #{sequence + 1}")
                sequence += 1
                previous = current
                heads[sequence] = current
        local_signed_through = remote_anchored_through = 0
        if local_checkpoint_path and local_checkpoint_path.exists():
            local_signed_through = verify_checkpoint(json.loads(local_checkpoint_path.read_bytes()), public_key, heads, host, chain_id)
        if remote_checkpoint:
            remote_anchored_through = verify_checkpoint(remote_checkpoint, public_key, heads, host, chain_id)
        return {"ok": True, "sequence": sequence, "host": host, "chain_id": chain_id,
                "local_signed_through": local_signed_through, "remote_anchored_through": remote_anchored_through,
                "unanchored_tail": sequence - remote_anchored_through, "error": None}
    except Exception as exc:
        return {"ok": False, "sequence": sequence, "host": host, "chain_id": chain_id,
                "local_signed_through": 0, "remote_anchored_through": 0,
                "unanchored_tail": None, "error": str(exc)}


def fetch_latest(url: str, host: str, token: str):
    if not url.startswith("https://") and not url.startswith("http://127.0.0.1:"):
        raise ValueError("remote URL must use HTTPS, except loopback lab tests")
    request = urllib.request.Request(url.rstrip("/") + "/v1/latest/" + urllib.parse.quote(host, safe=""),
                                     headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def main():
    parser = argparse.ArgumentParser(description="Verify RowGuard evidence against an independently trusted key")
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--trusted-key", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--remote-url", help="independent checkpoint receiver URL")
    parser.add_argument("--host", help="host identity at receiver; required with --remote-url")
    parser.add_argument("--token-env", default="ROWGUARD_ANCHOR_TOKEN")
    args = parser.parse_args()
    if args.remote_url and not args.host:
        parser.error("--host is required with --remote-url")
    remote = fetch_latest(args.remote_url, args.host, os.environ.get(args.token_env, "")) if args.remote_url else None
    result = verify_log(args.log, args.trusted_key, args.checkpoint, remote)
    print(json.dumps(result, indent=2))
    if not result["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
