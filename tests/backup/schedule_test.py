#!/usr/bin/env python3
"""The backup schedule (backup/set_backup_schedule, install_backup_timer; manual 1.3.7.5): vars.yaml and the timer's
units in a temporary folder, systemctl stood in for.

    python3 tests/backup/schedule_test.py
"""
import contextlib
import os
import sys
import tempfile

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
import fabriclib.backup.set_backup_schedule as sbs  # noqa: E402
from fabriclib.backup.install_backup_timer import install_backup_timer  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402

FAILED = 0
KEY = "age1" + "q" * 58


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


tmp = tempfile.mkdtemp()
units = os.path.join(tmp, "units")
os.makedirs(units)
vars_file = os.path.join(tmp, "vars.yaml")
with open(vars_file, "w") as f:
    yaml.safe_dump({"hostname": "fabric-1"}, f)
calls, audits = [], []
sbs.vars_lock = contextlib.nullcontext
sbs.write_audit = lambda *a, **k: audits.append(a)


def install(v):
    return install_backup_timer(v, units=units, run=lambda cmd, **kw: calls.append(cmd[1:]))


def schedule(**kw):
    try:
        return sbs.set_backup_schedule("root", path=vars_file, install=install, **kw), None
    except ValidationError as exc:
        return None, str(exc)


def saved():
    with open(vars_file) as f:
        return yaml.safe_load(f)


out, err = schedule(time="02:15", keep=10, public_key=KEY)
timer_file = os.path.join(units, "fabric-backup.timer")
timer = open(timer_file).read() if os.path.exists(timer_file) else ""
# covers: setting:backup_public_key setting:backup_schedule_time setting:backup_keep +
check("positive: on at 02:15, 10 kept, the key saved, the timer written and enabled",
      err is None and out["schedule"] == "on 02:15" and saved()["backup_keep"] == 10
      and saved()["backup_public_key"] == KEY and "OnCalendar=*-*-* 02:15:00" in timer
      and ["enable", "--now", "fabric-backup.timer"] in calls, (out, err, calls))
check("positive: the service runs `fabricctl backup --scheduled`",
      "ExecStart=/usr/bin/fabricctl backup --scheduled" in open(os.path.join(units, "fabric-backup.service")).read())
out, err = schedule(time="04:00")
check("positive: only the time changed; key and keep kept", out and out["schedule"] == "on 04:00"
      and saved()["backup_keep"] == 10 and saved()["backup_public_key"] == KEY, (out, err))
# covers: setting:backup_schedule_time -
for bad in ("4:00", "24:00", "03:60", "noon"):
    out, err = schedule(time=bad)
    check(f"negative: the time {bad!r} is refused, nothing changed", err and "HH:MM" in err
          and saved()["backup_schedule_time"] == "04:00", (out, err))
# covers: setting:backup_keep -
for bad in (0, 366, "7"):
    out, err = schedule(keep=bad)
    check(f"negative: keep {bad!r} is refused", err is not None and saved()["backup_keep"] == 10, (out, err))
# covers: setting:backup_public_key -
for bad in ("ssh-ed25519 AAAA", "age1short", "AGE-SECRET-KEY-1" + "Q" * 58):
    out, err = schedule(public_key=bad)
    check(f"negative: {bad[:18]!r} is not a public key: refused", err and "age public key" in err
          and saved()["backup_public_key"] == KEY, (out, err))
calls.clear()
out, err = schedule(off=True)
check("positive: off: the key removed, the timer disabled and its units removed, keep kept",
      out and out["schedule"] == "off" and saved()["backup_public_key"] is None and saved()["backup_keep"] == 10
      and ["disable", "--now", "fabric-backup.timer"] in calls and not os.listdir(units),
      (out, calls, os.listdir(units)))
out, err = schedule(time="03:00")
check("negative: the schedule turned on again with no public key is refused, naming age-keygen",
      err and "age-keygen" in err, (out, err))
check("positive: each change is audited (BACKUP_SCHEDULE)", len(audits) == 3 and audits[0][1] == "BACKUP_SCHEDULE",
      audits)
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
