#!/usr/bin/env python3
"""The running services that depend on what a section restore stops (backup/running_dependents; manual 1.3.7.8): Kea,
whose unit Requires= bind9, found for a dns restore and so started again after it (found by the sandbox, 2026-11-23);
a dependent that is not running, a target, or a unit already stopped by the restore is not added; each once.
systemctl is stood in for (the real restart: the sandbox's section restores, tests/sandbox/run.sh).

    python3 tests/backup/running_dependents_test.py
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from fabriclib.backup.running_dependents import running_dependents  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


REVERSE = {"bind9.service": "bind9.service\n  kea.service\n  fabric.target\n  multi-user.target\n  radius.service\n",
           "bind9-resolver.service": "bind9-resolver.service\n  kea.service\n  bind9.service\n"}
ACTIVE = {"kea", "bind9", "bind9-resolver"}


def run(cmd, **kw):
    if cmd[1] == "list-dependencies":
        return subprocess.CompletedProcess(cmd, 0, REVERSE.get(cmd[-1], cmd[-1] + "\n"), "")
    return subprocess.CompletedProcess(cmd, 0 if cmd[-1] in ACTIVE else 3, "", "")


got = running_dependents(["bind9", "bind9-resolver"], run)
check("Kea (Requires= bind9, running) is found once, to be started again", got == ["kea"], got)
check("negative: a dependent not running (radius), targets and the stopped units themselves are left out",
      "radius" not in got and not any(g.endswith("target") for g in got) and "bind9" not in got, got)
check("negative: a unit nothing depends on: none", running_dependents(["stepca"], run) == [])

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
