"""Daemon startup and offline evidence verification."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import uvicorn
import os

from .audit import verify
from .anchor import create_receiver
from .webapp import create_app


def main() -> None:
    parser = argparse.ArgumentParser(prog="rowguard")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="run the daemon and dashboard")
    serve.add_argument("--state-dir", type=Path, default=Path("state"))
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    check = commands.add_parser("verify", help="independently verify a local audit chain")
    check.add_argument("--state-dir", type=Path, default=Path("state"))
    receiver = commands.add_parser("anchor-receiver", help="run on an independent trusted host")
    receiver.add_argument("--keys-dir", type=Path, required=True)
    receiver.add_argument("--database", type=Path, required=True)
    receiver.add_argument("--host", default="127.0.0.1")
    receiver.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    if args.command == "serve":
        uvicorn.run(create_app(args.state_dir), host=args.host, port=args.port, log_level="info")
    elif args.command == "anchor-receiver":
        uvicorn.run(create_receiver(args.keys_dir, args.database, os.environ.get("ROWGUARD_RECEIVER_TOKEN", "")),
                    host=args.host, port=args.port, log_level="info")
    else:
        result = verify(args.state_dir / "audit.jsonl", args.state_dir / "checkpoint.json", args.state_dir / "signing.pub")
        print(json.dumps(result, indent=2))
        if not result["ok"]:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
