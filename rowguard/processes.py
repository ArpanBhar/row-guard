"""Best-effort CPU process candidates for system-wide PMU incidents.

These observations are not PMU attribution. A busy process may be unrelated to
the cache activity that triggered an incident.
"""
from __future__ import annotations

import os
import time
from pathlib import Path


def parse_stat(text: str) -> tuple[str, int, int] | None:
    """Return comm, CPU ticks, and start ticks from /proc/PID/stat."""
    left = text.find("(")
    right = text.rfind(")")
    if left < 0 or right <= left:
        return None
    fields = text[right + 2:].split()
    if len(fields) < 20:
        return None
    try:
        return text[left + 1:right], int(fields[11]) + int(fields[12]), int(fields[19])
    except ValueError:
        return None


class ProcessObserver:
    def __init__(self, root: Path = Path("/proc"), *, exclude_pid: int | None = None,
                 clock=time.monotonic, ticks_per_second: int | None = None):
        self.root = root
        self.exclude_pid = exclude_pid
        self.clock = clock
        self.ticks_per_second = ticks_per_second or os.sysconf("SC_CLK_TCK")
        self.previous: dict[tuple[int, int], tuple[str, int]] = {}
        self.last_time: float | None = None
        self.candidates: list[dict] = []

    def due(self) -> bool:
        return self.last_time is None or self.clock() - self.last_time >= 1.0

    def fresh_candidates(self) -> list[dict]:
        if self.last_time is None or self.clock() - self.last_time > 2.0:
            return []
        return [candidate.copy() for candidate in self.candidates]

    def sample(self) -> list[dict]:
        now = self.clock()
        current: dict[tuple[int, int], tuple[str, int]] = {}
        try:
            entries = list(self.root.iterdir())
        except OSError:
            self.candidates = []
            self.last_time = now
            return []
        for entry in entries:
            if not entry.name.isdecimal():
                continue
            pid = int(entry.name)
            if pid == self.exclude_pid:
                continue
            try:
                parsed = parse_stat((entry / "stat").read_text())
            except (OSError, UnicodeError):
                continue
            if parsed is None:
                continue
            name, ticks, start_ticks = parsed
            current[(pid, start_ticks)] = (name, ticks)
        candidates = []
        if self.last_time is not None:
            elapsed = now - self.last_time
            if elapsed > 0:
                for (pid, start_ticks), (name, ticks) in current.items():
                    prior = self.previous.get((pid, start_ticks))
                    if prior is None or ticks < prior[1]:
                        continue
                    cpu_percent = 100 * (ticks - prior[1]) / self.ticks_per_second / elapsed
                    if cpu_percent >= 10:
                        candidates.append({"pid": pid, "name": name, "start_ticks": start_ticks,
                                           "cpu_percent_one_core": round(cpu_percent, 1)})
        self.previous = current
        self.last_time = now
        self.candidates = sorted(candidates, key=lambda item: item["cpu_percent_one_core"], reverse=True)[:3]
        return self.fresh_candidates()
