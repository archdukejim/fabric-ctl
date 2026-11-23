#!/usr/bin/env python3
"""BIND's DLZ files at apply (samba/deploy_samba; manual 1.6.5.6, 1.3.7.6): written when missing, and turned off again
when a restored bundle brought back an include that names a DNS database not loaded yet (found by the sandbox,
2026-11-23: BIND failed at bootstrap); never turned on here, that waits for the converged domain. Ownership, the
chrony group and the file writes are stood in for (the real DC: tests/samba/dc.py).

    python3 tests/samba/deploy_samba_test.py
"""
import os
import sys
import tempfile
import types

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
import fabriclib.samba.deploy_samba as ds  # noqa: E402
import fabriclib.samba.write_bind_dlz as wbd  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def ensure_dir(path, mode, uid, gid):
    os.makedirs(path, exist_ok=True)


def write_if_changed(path, text, mode):
    old = open(path).read() if os.path.exists(path) else None
    if old != text:
        open(path, "w").write(text)
    return old != text


for m in (ds, wbd):
    m.ensure_dir, m.write_file_if_changed = ensure_dir, write_if_changed
ds._chrony_gid = lambda: 0
base = tempfile.mkdtemp()
v = {"deploy_base_dir": base, "host_ip": "10.0.0.5", "ad_domain": "ad.lan.test", "ad_netbios": "AD",
     "ad_ntp_signd_dir": os.path.join(base, "ntp_signd")}
secrets = {"ad_admin_password": "x"}
ENV = types.SimpleNamespace(loader=types.SimpleNamespace(searchpath=[os.path.join(ROOT, "templates")]))   # a checkout
dlz_file = os.path.join(base, "samba", "bind", "dlz.conf")
ON = 'dlz "AD DNS Zone" { database "dlopen /usr/lib/fabric/dlz_bind9.so --url=/data/bind-dns/dns/sam.ldb"; };\n'


def dlz():
    return open(dlz_file).read()


ds.deploy_samba(v, secrets, ENV)
check("a first install: the include written, off", os.path.exists(dlz_file) and "dlopen" not in dlz(), dlz())

open(os.path.join(base, "samba", "data", ".fabric-provisioned"), "w").close()
open(dlz_file, "w").write(ON)
ds.deploy_samba(v, secrets, ENV)
check("negative: a restored include whose DNS database is not loaded yet is turned off", "dlopen" not in dlz(), dlz())

os.makedirs(os.path.join(base, "samba", "data", "bind-dns", "dns"))
open(os.path.join(base, "samba", "data", "bind-dns", "dns", "sam.ldb"), "w").close()
ds.deploy_samba(v, secrets, ENV)
check("the domain is there: the apply leaves the include off (on waits for the converged domain)",
      "dlopen" not in dlz(), dlz())
open(dlz_file, "w").write(ON)
ds.deploy_samba(v, secrets, ENV)
check("and an include that is on, with its database, stays on", dlz() == ON, dlz())

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
