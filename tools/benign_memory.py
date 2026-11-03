"""Bounded by its parent process: copy two large buffers as a benign PMU control."""
from __future__ import annotations

import time


def main() -> None:
    source = bytearray(128 * 1024 * 1024)
    target = bytearray(len(source))
    copies = 0
    started = time.monotonic()
    while True:
        target[:] = source
        copies += 1
        if copies % 100 == 0:
            print(f"copies={copies} elapsed_s={time.monotonic() - started:.1f}", flush=True)


if __name__ == "__main__":
    main()
