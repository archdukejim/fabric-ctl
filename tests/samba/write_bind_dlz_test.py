#!/usr/bin/env python3
"""BIND's include for the AD zone (samba/write_bind_dlz; manual 1.6.5.6, 1.3.7.6): off until the domain is provisioned
and its DNS database is there, so BIND starts without the DC, also after an online bundle's restore, which brings the
marker back before the DC's databases (found by the sandbox, 2026-11-23); on once both are; changed only when it changes.
The files' ownership is stood in for (the real DLZ in BIND: tests/samba/dc.py).

    python3 tests/samba/write_bind_dlz_test.py
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
import fabriclib.samba.write_bind_dlz as wbd  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


wbd.ensure_dir = lambda path, mode, uid, gid: os.makedirs(path, exist_ok=True)


def write_if_changed(path, text, mode):
    old = open(path).read() if os.path.exists(path) else None
    if old != text:
        open(path, "w").write(text)
    return old != text


wbd.write_file_if_changed = write_if_changed
base = tempfile.mkdtemp()
v = {"deploy_base_dir": base}
data = os.path.join(base, "samba", "data")
os.makedirs(data)


def dlz():
    return open(os.path.join(base, "samba", "bind", "dlz.conf")).read()


wbd.write_bind_dlz(v)
check("not provisioned: off", "dlopen" not in dlz())
open(os.path.join(data, ".fabric-provisioned"), "w").close()
check("negative: the marker back but no DNS database yet (an online restore before the DC loads): still off",
      wbd.write_bind_dlz(v) is False and "dlopen" not in dlz(), dlz())
os.makedirs(os.path.join(data, "bind-dns", "dns"))
open(os.path.join(data, "bind-dns", "dns", "sam.ldb"), "w").close()
check("provisioned with its DNS database: on, and BIND must restart", wbd.write_bind_dlz(v) is True
      and "dlopen" in dlz() and "/data/bind-dns/dns/sam.ldb" in dlz(), dlz())
check("and again: nothing changes", wbd.write_bind_dlz(v) is False)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
