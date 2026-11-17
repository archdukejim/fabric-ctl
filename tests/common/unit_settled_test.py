#!/usr/bin/env python3
"""Waiting for a unit systemd is moving (common/unit_settled, 2.3.2.5, 2.3.1.57): pure logic, `systemctl show` stood
in for.

    python3 tests/common/unit_settled_test.py
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "src"))
from fabriclib.common.unit_settled import unit_settled  # noqa: E402

FAILED = 0


def check(name, got, want):
    global FAILED
    FAILED += got != want
    print(("PASS " if got == want else "FAIL ") + name + ("" if got == want else f"  -> {got!r}"))


def settle(states, clock=None):
    """unit_settled over a unit whose `systemctl show` answers states in turn (the last one repeated)."""
    left = list(states)

    def show(cmd, **kw):
        state, sub = left.pop(0) if len(left) > 1 else left[0]
        return subprocess.CompletedProcess(cmd, 0, f"ActiveState={state}\nSubState={sub}\n", "")

    real = subprocess.run, time.sleep, time.monotonic
    subprocess.run, time.sleep = show, lambda s: None
    if clock:
        time.monotonic = clock
    try:
        return unit_settled("bind9")
    finally:
        subprocess.run, time.sleep, time.monotonic = real


check("positive: a starting unit is waited for until it is active",
      settle([("activating", "start"), ("activating", "start-post"), ("active", "running")]), ("active", "running"))
check("positive: a unit that settles failed is returned as failed",
      settle([("deactivating", "stop"), ("failed", "failed")]), ("failed", "failed"))
check("negative: a unit in its automatic-restart loop is not waited for",
      settle([("activating", "auto-restart"), ("active", "running")]), ("activating", "auto-restart"))
ticks = iter(range(0, 10000, 400))
check("negative: a unit that never settles is returned as it is at the timeout",
      settle([("activating", "start")], clock=lambda: next(ticks)), ("activating", "start"))
check("negative: systemctl answers nothing: empty states, no wait", settle([("", "")]), ("", ""))
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
