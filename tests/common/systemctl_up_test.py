#!/usr/bin/env python3
"""A start cut short from outside does not fail fabric (common/systemctl_up, 2.3.1.57): pure logic, systemctl stood
in for. On the 0.10.0 rehearsal's VM, unattended-upgrades made systemd re-execute while bind9 was starting; the
re-exec killed the start, systemd started bind9 again itself, and setup had already failed on systemctl's answer.
The rehearsal and the host suite run the real units.

    python3 tests/common/systemctl_up_test.py
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "src"))
from fabriclib.common.systemctl_up import systemctl_up  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def run(states, fails=0, **kw):
    """systemctl_up(["bind9", "stepca"], **kw) where each unit settles in the state states gives it and the first
    `fails` start, restart or enable calls fail; returns (error or None, systemctl calls as lists)."""
    calls, failing = [], [fails]

    def sysrun(cmd, **opts):
        if cmd[1] == "show":
            state = states.get(cmd[-1], "active")
            return subprocess.CompletedProcess(cmd, 0, f"ActiveState={state}\nSubState=x\n", "")
        calls.append(cmd[1:])
        code = 0
        if cmd[1] in ("start", "restart", "enable") and failing[0]:
            failing[0] -= 1
            code = 1
        if code and opts.get("check"):
            raise subprocess.CalledProcessError(code, cmd)
        return subprocess.CompletedProcess(cmd, code, "", "")

    real_run, real_sleep = subprocess.run, time.sleep
    subprocess.run, time.sleep = sysrun, lambda s: None
    try:
        systemctl_up(["bind9", "stepca"], **kw)
        return None, calls
    except subprocess.CalledProcessError as exc:
        return exc, calls
    finally:
        subprocess.run, time.sleep = real_run, real_sleep


err, calls = run({}, enable=True)
check("positive: enable, then start, once each, when systemctl says yes",
      err is None and calls == [["enable", "bind9", "stepca"], ["start", "bind9", "stepca"]], calls)
err, calls = run({}, restart=True)
check("positive: restart asked: one restart", err is None and calls == [["restart", "bind9", "stepca"]], calls)
err, calls = run({"bind9": "active", "stepca": "active"}, fails=1)
check("positive: a start cut short, both units active once settled (systemd started them again): no second start",
      err is None and calls == [["start", "bind9", "stepca"]], calls)
err, calls = run({"bind9": "failed", "stepca": "active"}, fails=1)
check("negative: a start cut short, one unit down after it: only that one cleared and started once more",
      err is None and calls[1:] == [["reset-failed", "bind9"], ["start", "bind9"]], calls)
err, calls = run({"bind9": "failed"}, fails=2)
check("negative: the second start fails too: an error (CalledProcessError)",
      isinstance(err, subprocess.CalledProcessError) and calls[-1] == ["start", "bind9"], calls)
err, calls = run({}, fails=1, enable=True)
check("negative: enable fails: an error at once, nothing started",
      isinstance(err, subprocess.CalledProcessError) and calls == [["enable", "bind9", "stepca"]], calls)
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
