#!/usr/bin/env python3
"""The schedule as the Backups page shows it (backup/schedule_status; manual 1.3.7.9): its settings, and its runs read
from systemd's words. systemd stood in for: the real timer is tests/sandbox/run.sh's.

    python3 tests/backup/schedule_status_test.py
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from fabriclib.backup.schedule_status import schedule_status  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def systemd(timer, service):
    def run(cmd, **kw):
        out = timer if cmd[2].endswith(".timer") else service
        return subprocess.CompletedProcess(cmd, 0, out, "")
    return run


ON = {"backup_public_key": "age1abc", "backup_schedule_time": "04:15", "backup_keep": 3}
s = schedule_status(ON, systemd("NextElapseUSecRealtime=Mon 2026-11-23 04:15:00 UTC\nLastTriggerUSec=Sun 2026-11-22 "
                                "04:15:00 UTC\n", "Result=success\nExecMainStatus=0\nExecMainExitTimestamp=Sun "
                                "2026-11-22 04:17:31 UTC\n"))
check("on: its settings and runs, the last one done", s["on"] and s["time"] == "04:15" and s["keep"] == 3
      and s["next"].startswith("Mon") and s["last"].startswith("Sun") and s["last_result"] == "ok", s)
s = schedule_status(ON, systemd("NextElapseUSecRealtime=Mon 2026-11-23 04:15:00 UTC\nLastTriggerUSec=n/a\n",
                                "Result=exit-code\nExecMainStatus=1\nExecMainExitTimestamp=Sun 2026-11-22 04:17 UTC\n"))
check("a failed last run is said failed; no trigger yet is no last run", s["last_result"] == "failed"
      and s["last"] == "", s)
s = schedule_status(ON, systemd("NextElapseUSecRealtime=\nLastTriggerUSec=n/a\n",
                                "Result=success\nExecMainStatus=0\nExecMainExitTimestamp=n/a\n"))
check("before a first run: no result", s["last_result"] == "" and s["next"] == "", s)


def broken(cmd, **kw):
    raise FileNotFoundError("systemctl")


s = schedule_status(ON, broken)
check("negative: systemd not there: no runs shown, no error", s["on"] and s["next"] == "" and s["last_result"] == "", s)
s = schedule_status({}, broken)
check("off: the defaults, systemd not asked", not s["on"] and s["time"] == "03:00" and s["keep"] == 7, s)
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
