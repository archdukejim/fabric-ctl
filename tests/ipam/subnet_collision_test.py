#!/usr/bin/env python3
"""A new LAN subnet's collisions (ipam/subnet_collision; manual 1.3.7.7, decision 2.1.1.107): pure logic.

    python3 tests/ipam/subnet_collision_test.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from fabriclib.ipam.subnet_collision import subnet_collision  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


KEPT = [{"name": "lan", "cidr": "10.77.0.0/24"}, {"name": "iot", "cidr": "10.78.0.0/24"},
        {"name": "another site's subnet", "cidr": "10.90.0.0/24"}]
FS = "10.255.0.0/24"
check("positive: a free subnet collides with nothing", subnet_collision("10.79.0.0/24", FS, KEPT, "10.77.0.0/24") == "")
check("positive: the old LAN's own subnet moves with it, so a new LAN overlapping only it is free",
      subnet_collision("10.77.0.0/23", FS, KEPT, "10.77.0.0/24") == "")
err = subnet_collision("10.78.0.0/24", FS, KEPT, "10.77.0.0/24")
check("negative: another subnet of the site's plan: named, with its network", "10.78.0.0/24 (iot)" in err, err)
err = subnet_collision("10.90.0.128/25", FS, KEPT, "10.77.0.0/24")
check("negative: another site's subnet: refused too", "another site's subnet" in err, err)
err = subnet_collision("10.255.0.0/16", FS, KEPT, "10.77.0.0/24")
check("negative: fabric's container network: named as fabric_subnet", "fabric_subnet" in err and FS in err, err)
check("not known (a bundle without them): nothing to check", subnet_collision("10.255.0.0/24", None, None) == "")
check("without a move, the old LAN counts like any other subnet",
      "(lan)" in subnet_collision("10.77.0.0/24", FS, KEPT))
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
