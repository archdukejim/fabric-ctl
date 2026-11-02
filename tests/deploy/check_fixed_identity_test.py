#!/usr/bin/env python3
"""check_fixed_identity (manual 1.6.11.14, decision 2.1.6.104): a domain controller's host keeps the name recorded at
its first deploy, so an apply with another name is refused and only break glass (`fabricctl admin rename-host`, its
own test in tests/openbao/local_admin.py) moves the record; a host without a DC is not held to it. Real files in a
folder of the test's own."""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.deploy.check_fixed_identity import check_fixed_identity  # noqa: E402

FAILED = PASSED = 0
CFG = tempfile.mkdtemp(prefix="fixed-identity-")
V = {"site_name": "lan", "org_domain": "lan.test", "ldap_base_dn": "dc=lan,dc=test", "hostname": "fabric",
     "hostname_dc": "dc-0001.ad.lan.test"}


def check(name, cond, detail=""):
    global FAILED, PASSED
    FAILED += not cond
    PASSED += bool(cond)
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def refused(v, cfg=CFG):
    try:
        check_fixed_identity(v, cfg)
        return ""
    except ValidationError as e:
        return str(e)


def marker(cfg=CFG):
    path = os.path.join(cfg, ".hostname")
    return open(path).read().strip() if os.path.exists(path) else None


check("a DC's host: the first deploy records its name", refused(V) == "" and marker() == "fabric", marker())
check("…the same name applies again", refused(V) == "")
before = sorted(os.listdir(CFG))
msg = refused({**V, "hostname": "fabric2"})
# covers: setting:hostname -
check("negative: another name on a DC's host refused, naming the DC, break glass and 4.2.4.3; the record kept",
      "runs the domain controller dc-0001" in msg and "renamed only through break glass" in msg
      and "sudo fabricctl admin rename-host fabric2" in msg and "4.2.4.3" in msg and "set hostname: fabric" in msg
      and marker() == "fabric", msg)
check("…nothing written by the refusal", sorted(os.listdir(CFG)) == before, os.listdir(CFG))
with open(os.path.join(CFG, ".hostname"), "w") as f:
    f.write("fabric2\n")
# covers: setting:hostname +
check("once break glass moved the record, the new name applies", refused({**V, "hostname": "fabric2"}) == "")
fresh = tempfile.mkdtemp(prefix="fixed-identity-nodc-")
no_dc = {**V, "hostname_dc": ""}
check("a host without a DC: no record, and a new name applies (4.2.4.3 without break glass)",
      refused(no_dc, fresh) == "" and marker(fresh) is None and refused({**no_dc, "hostname": "other"}, fresh) == "")
msg = refused({**V, "hostname": "fabric2", "site_name": "other"})
check("negative: the other fixed settings are still refused as before (site_name)", "cannot change" in msg, msg)
shutil.rmtree(CFG, ignore_errors=True)
shutil.rmtree(fresh, ignore_errors=True)
print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
