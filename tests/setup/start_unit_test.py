#!/usr/bin/env python3
"""start_unit never interrupts a unit systemd is already starting (2.3.2.5): pure logic, systemctl and the
health wait stood in for. Restarting Postgres makes systemd restart Keycloak, which Requires it; start_unit used to
see Keycloak "activating", send it a stop mid-start and start it again, and the second start raced the first's
container removal. The sandbox and the lab run the real units.

    python3 tests/setup/start_unit_test.py
"""
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
import fabriclib.setup.start_unit as su  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def run(states, restart, final_active=True):
    """start_unit over a unit whose `systemctl show` answers states in turn; returns (result, systemctl verbs)."""
    seen, left = [], list(states)

    def sysrun(cmd, **kw):
        verb = cmd[1]
        if verb == "show":
            state, sub = left.pop(0) if len(left) > 1 else left[0]
            return subprocess.CompletedProcess(cmd, 0, f"ActiveState={state}\nSubState={sub}\n", "")
        seen.append(verb)
        if verb == "is-active":
            return subprocess.CompletedProcess(cmd, 0 if final_active else 3)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    real_run, real_wait, real_sleep = su.subprocess.run, su.wait_healthy, su.time.sleep
    su.subprocess.run, su.wait_healthy, su.time.sleep = sysrun, lambda c, timeout: (True, ""), lambda s: None
    try:
        return su.start_unit("keycloak", "keycloak", restart), seen
    finally:
        su.subprocess.run, su.wait_healthy, su.time.sleep = real_run, real_wait, real_sleep


res, seen = run([("activating", "start-pre"), ("activating", "start-post"), ("active", "running")], restart=True)
check("positive: a unit systemd is starting is waited for, then restarted as asked; never stopped mid-start",
      res == "restarted" and "stop" not in seen and seen[-1] == "restart", (res, seen))
res, seen = run([("activating", "start"), ("active", "running")], restart=False)
check("positive: a unit systemd started meanwhile, with no restart asked, is left running",
      res == "running" and seen == ["enable", "is-active"], (res, seen))
res, seen = run([("activating", "auto-restart")], restart=False, final_active=False)
check("negative: a unit in its automatic-restart loop is not waited for: stopped, then started (2.3.6.2.9)",
      res == "started" and seen == ["enable", "is-active", "stop", "reset-failed", "start"], (res, seen))
res, seen = run([("failed", "failed")], restart=False, final_active=False)
check("negative: a failed unit is stopped, its failed state cleared, then started",
      res == "started" and seen == ["enable", "is-active", "stop", "reset-failed", "start"], (res, seen))
real = su.time.monotonic
ticks = iter(range(0, 10000, 400))
su.time.monotonic = lambda: next(ticks)
try:
    res, seen = run([("activating", "start-post")], restart=False, final_active=False)
finally:
    su.time.monotonic = real
check("negative: a start that never ends is waited for only until the timeout, then handled as not active",
      res == "started" and "stop" in seen, (res, seen))
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
