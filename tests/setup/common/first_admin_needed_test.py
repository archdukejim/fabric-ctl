#!/usr/bin/env python3
"""Whether setup creates the first admin (setup/common/first_admin_needed; 2.1.6.33, manual 1.3.7.6): a new root site
with the console does; a DC already provisioned, a joining site, or a restore whose directory dump is still to load
does not (an online bundle's restore: found by the sandbox's whole restore from the console, 2026-11-23).

    python3 tests/setup/common/first_admin_needed_test.py
"""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from fabriclib.setup.common.first_admin_needed import first_admin_needed  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


class Ctx:
    def __init__(self, base, join=None):
        self.deploy_base, self.config_dir, self.join_invitation = base, os.path.join(base, "config"), join
        self.vars = {"install_webui": True, "install_keycloak": True}
        os.makedirs(self.config_dir, exist_ok=True)


ctx = Ctx(tempfile.mkdtemp())
check("a new root site with the console: the first admin is made", first_admin_needed(ctx) is True)
with open(os.path.join(ctx.config_dir, "restore-pending.json"), "w") as f:
    json.dump({"directory": "/dev/shm/fabric-restore/directory.tar.bz2", "signin": "/dev/shm/x"}, f)
check("an online bundle restored, its directory still to load: no first admin (the bundle's admins come back)",
      first_admin_needed(ctx) is False)
with open(os.path.join(ctx.config_dir, "restore-pending.json"), "w") as f:
    json.dump({"signin": "/dev/shm/x"}, f)
check("negative: something else pending, not the directory: still decided by the DC's marker",
      first_admin_needed(ctx) is True)
os.makedirs(os.path.join(ctx.deploy_base, "samba", "data"))
open(os.path.join(ctx.deploy_base, "samba", "data", ".fabric-provisioned"), "w").close()
check("a DC already provisioned: no first admin", first_admin_needed(ctx) is False)
check("a joining site: no first admin", first_admin_needed(Ctx(tempfile.mkdtemp(), join="x")) is False)
plain = Ctx(tempfile.mkdtemp())
plain.vars["install_keycloak"] = False
check("no sign-in service: no first admin", first_admin_needed(plain) is False)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
