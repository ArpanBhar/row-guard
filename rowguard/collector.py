"""Small Linux x86-64 perf_event_open grouped counter collector."""
from __future__ import annotations

import ctypes
import os
import platform
import struct
import time
from dataclasses import dataclass

EVENTS = ("cycles", "instructions", "cache_references", "cache_misses")
PERF_FORMAT_TOTAL_TIME_ENABLED = 1 << 0
PERF_FORMAT_TOTAL_TIME_RUNNING = 1 << 1
PERF_FORMAT_GROUP = 1 << 3
PERF_TYPE_HARDWARE = 0
SYS_PERF_EVENT_OPEN_X86_64 = 298


class PerfEventAttr(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("config", ctypes.c_uint64),
        ("sample_period", ctypes.c_uint64),
        ("sample_type", ctypes.c_uint64),
        ("read_format", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
        ("wakeup_events", ctypes.c_uint32),
        ("bp_type", ctypes.c_uint32),
        ("config1", ctypes.c_uint64),
    ]


@dataclass(frozen=True)
class CounterReading:
    monotonic_ns: int
    values: dict[str, int]
    time_enabled: int
    time_running: int
    groups: tuple[tuple[dict[str, int], int, int], ...] = ()


class PerfCollector:
    def __init__(self) -> None:
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            raise RuntimeError("perf collector requires Linux x86-64")
        self._fds: list[int] = []
        self._libc = ctypes.CDLL(None, use_errno=True)
        self._libc.syscall.restype = ctypes.c_long
        try:
            for cpu in range(os.cpu_count() or 1):
                # One group per CPU keeps counters and running time in the same scope.
                leader = self._open(0, cpu, -1)
                self._fds.append(leader)
                for event_id in (1, 2, 3):
                    self._fds.append(self._open(event_id, cpu, leader))
        except Exception:
            self.close()
            raise
        self._groups = [self._fds[i] for i in range(0, len(self._fds), 4)]

    def _open(self, event_id: int, cpu: int, group_fd: int) -> int:
        attr = PerfEventAttr()
        attr.type = PERF_TYPE_HARDWARE
        attr.size = ctypes.sizeof(PerfEventAttr)
        attr.config = event_id
        attr.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING
        # enabled immediately; user and kernel counts are included.
        fd = self._libc.syscall(SYS_PERF_EVENT_OPEN_X86_64, ctypes.byref(attr), -1, cpu, group_fd, 0)
        if fd < 0:
            error = ctypes.get_errno()
            raise OSError(error, f"perf_event_open({EVENTS[event_id]}, cpu={cpu}): {os.strerror(error)}")
        return int(fd)

    def read(self) -> CounterReading:
        values = {name: 0 for name in EVENTS}
        enabled = running = 0
        groups = []
        for fd in self._groups:
            raw = os.read(fd, (3 + len(EVENTS)) * 8)
            if len(raw) != (3 + len(EVENTS)) * 8:
                raise OSError("short perf counter group read")
            words = struct.unpack("<7Q", raw)
            if words[0] != len(EVENTS):
                raise OSError("perf group membership changed")
            enabled += words[1]
            running += words[2]
            group_values = dict(zip(EVENTS, words[3:]))
            groups.append((group_values, words[1], words[2]))
            for name, count in zip(EVENTS, words[3:]):
                values[name] += count
        return CounterReading(time.monotonic_ns(), values, enabled, running, tuple(groups))

    def close(self) -> None:
        for fd in self._fds:
            os.close(fd)
        self._fds.clear()


def delta(previous: CounterReading, current: CounterReading, min_ratio: float = 0.8) -> tuple[dict[str, float] | None, dict]:
    elapsed = (current.monotonic_ns - previous.monotonic_ns) / 1e9
    quality = {"valid": False, "running_ratio": None, "reason": None, "elapsed_s": elapsed}
    if elapsed <= 0:
        quality["reason"] = "invalid counter timing"
        return None, quality
    if previous.groups or current.groups:
        if len(previous.groups) != len(current.groups):
            quality["reason"] = "CPU group set changed"
            return None, quality
        pairs = zip(previous.groups, current.groups)
    else:
        pairs = [((previous.values, previous.time_enabled, previous.time_running),
                  (current.values, current.time_enabled, current.time_running))]
    totals = {name: 0.0 for name in EVENTS}
    ratios = []
    for (old_values, old_enabled, old_running), (new_values, new_enabled, new_running) in pairs:
        de = new_enabled - old_enabled
        dr = new_running - old_running
        if de <= 0 or dr <= 0 or dr > de:
            quality["reason"] = "invalid counter timing"
            return None, quality
        ratio = dr / de
        ratios.append(ratio)
        if ratio < min_ratio:
            quality["running_ratio"] = min(ratios)
            quality["reason"] = "counter multiplexed below quality threshold"
            return None, quality
        for name in EVENTS:
            difference = new_values[name] - old_values[name]
            if difference < 0:
                quality["reason"] = "counter reset or wrap"
                return None, quality
            totals[name] += difference * de / dr
    quality["running_ratio"] = min(ratios)
    quality["valid"] = True
    return {name + "_per_s": value / elapsed for name, value in totals.items()}, quality
