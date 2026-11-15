#!/usr/bin/env python3
"""The host's memory as setup measures it (system/host_ram_gb, manual 1.2.4.2.1): MemTotal rounded, the crash kernel's
reservation counted in (a 4 GB Ubuntu Server reports 3.32 GiB, 512 MB set aside: the 0.10.0 rc, 2.3.1.57), so a 4 GB
host is 4; a Pi's 3.88 GiB with no reservation is 4; 0 when MemTotal cannot be read. Real files, written here.

    python3 tests/system/host_ram_gb_test.py
"""
import os
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.system.host_ram_gb import host_ram_gb  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


D = tempfile.mkdtemp(prefix="fabric-ram-")


def files(memtotal_kb, crash=None):
    m = os.path.join(D, "meminfo")
    with open(m, "w") as f:
        f.write("" if memtotal_kb is None else f"MemTotal:       {memtotal_kb} kB\nMemFree:  1 kB\n")
    c = os.path.join(D, "crash")
    if crash is None:
        if os.path.exists(c):
            os.remove(c)
    else:
        with open(c, "w") as f:
            f.write(f"{crash}\n")
    return m, c


got = host_ram_gb(*files(3478964, 536870912))
check("positive: a 4 GB Ubuntu host with 512 MB for the crash kernel is 4 GB (not refused as 3)", got == 4, got)
got = host_ram_gb(*files(3478964))
check("positive: the same MemTotal with no crash file is 3 (nothing added)", got == 3, got)
got = host_ram_gb(*files(4068000, 0))
check("positive: a Pi's 3.88 GiB, no reservation, is 4", got == 4, got)
got = host_ram_gb(*files(7548000, 536870912))
check("positive: an 8 GB host with its reservation is 8", got == 8, got)
got = host_ram_gb(*files(None))
check("negative: no MemTotal: 0 (setup then refuses, as before)", got == 0, got)
m, c = files(3478964)
with open(c, "w") as f:
    f.write("not a number\n")
got = host_ram_gb(m, c)
check("negative: an unreadable crash size adds nothing", got == 3, got)
got = host_ram_gb(os.path.join(D, "absent"), c)
check("negative: no meminfo at all: 0", got == 0, got)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
