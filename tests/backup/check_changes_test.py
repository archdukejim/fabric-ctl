#!/usr/bin/env python3
"""What a whole restore or a reinstall may change (backup/check_changes; manual 1.3.7.7): the new subnet's collisions
with fabric's container network and the address plan (decision 2.1.1.107), and the refusals before them.

    python3 tests/backup/check_changes_test.py
"""
import contextlib
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from fabriclib.backup.check_changes import check_changes  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


OLD = {"host_ip": "10.0.0.5", "lan_cidr": "10.0.0.0/24", "lan_gateway": "10.0.0.1", "dns_server": "10.0.0.1",
       "fabric_subnet": "10.255.0.0/24",
       "plan_subnets": [{"name": "lan", "cidr": "10.0.0.0/24"}, {"name": "iot", "cidr": "10.20.0.0/24"}]}
MOVE = {"host_ip": "10.30.0.5", "lan_cidr": "10.30.0.0/24", "lan_gateway": "10.30.0.1"}


def refused(changes, manifest=OLD):
    said = io.StringIO()
    try:
        with contextlib.redirect_stdout(said):
            check_changes(changes, manifest)
    except ValidationError as exc:
        return str(exc), said.getvalue()
    return None, said.getvalue()


check("positive: another VLAN and subnet that collides with nothing: the three changes",
      check_changes(MOVE, OLD) == {k: (OLD[k], MOVE[k]) for k in MOVE})
err, _ = refused({"host_ip": "10.20.0.5", "lan_cidr": "10.20.0.0/24", "lan_gateway": "10.20.0.1"})
check("negative: the subnet of another VLAN in the plan: refused, naming it, before anything is unpacked",
      err and "10.20.0.0/24 (iot)" in err and "Choose another subnet" in err, err)
err, _ = refused({"host_ip": "10.255.0.50", "lan_cidr": "10.255.0.0/24", "lan_gateway": "10.255.0.1"})
check("negative: fabric's container network: refused", err and "fabric_subnet" in err, err)
err, _ = refused({"host_ip": "10.0.0.9"})
check("positive: a new address on the same subnet is no subnet change: nothing to collide with", err is None, err)
bare = {k: v for k, v in OLD.items() if k not in ("fabric_subnet", "plan_subnets")}
err, said = refused({"host_ip": "10.20.0.5", "lan_cidr": "10.20.0.0/24", "lan_gateway": "10.20.0.1"}, bare)
check("a bundle without them (0.10.1's): not refused here, and it says the check comes later",
      err is None and "checked against them when setup writes it" in said, (err, said))
err, _ = refused(dict(MOVE, hostname="other"))
check("negative: the host's name: refused, renamed after the restore (4.2.4.3)", err and "4.2.4.3" in err, err)
err, _ = refused(MOVE, dict(OLD, linked=True))
check("negative: linked sites: refused", err and "linked sites" in err, err)
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
