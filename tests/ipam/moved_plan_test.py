#!/usr/bin/env python3
"""The plan's LAN subnet moved to the new subnet after a restore (ipam/moved_plan; manual 1.3.7.7): pure logic.

    python3 tests/ipam/moved_plan_test.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from fabriclib.ipam.moved_plan import moved_plan  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


PLAN = {"site": "hq", "subnets": [
    {"name": "lan", "cidr": "10.77.0.0/24", "vlan": 1, "gateway": "10.77.0.1", "dhcp": True,
     "ranges": [{"kind": "dhcp", "first": "10.77.0.200", "last": "10.77.0.220"}],
     "addresses": [{"ip": "10.77.0.40", "kind": "static", "name": "nas", "dns": True},
                   {"ip": "10.77.0.250", "kind": "reservation", "name": "ap", "mac": "aa:bb:cc:dd:ee:ff"}]},
    {"name": "iot", "cidr": "10.78.0.0/24", "vlan": 20, "gateway": "10.78.0.1", "dhcp": True, "ranges": [],
     "addresses": [{"ip": "10.78.0.5", "kind": "static"}]}]}

out, warnings = moved_plan(PLAN, "10.77.0.0/24", "10.79.0.0/24")
lan = out["subnets"][0]
check("positive: the LAN's subnet moves: network, gateway, ranges and addresses keep their host numbers",
      lan["cidr"] == "10.79.0.0/24" and lan["gateway"] == "10.79.0.1"
      and lan["ranges"] == [{"kind": "dhcp", "first": "10.79.0.200", "last": "10.79.0.220"}]
      and [a["ip"] for a in lan["addresses"]] == ["10.79.0.40", "10.79.0.250"] and not warnings, (lan, warnings))
check("positive: its name, VLAN, names and MACs stay", lan["name"] == "lan" and lan["vlan"] == 1
      and lan["addresses"][1]["mac"] == "aa:bb:cc:dd:ee:ff")
check("positive: the other VLANs are left as they are", out["subnets"][1] == PLAN["subnets"][1])
check("positive: the plan given is not changed (a copy)", PLAN["subnets"][0]["cidr"] == "10.77.0.0/24")
small, warnings = moved_plan(PLAN, "10.77.0.0/24", "10.79.0.0/25")
check("negative: a smaller new subnet: what does not fit is left out, each named",
      small["subnets"][0]["ranges"] == [] and [a["ip"] for a in small["subnets"][0]["addresses"]] == ["10.79.0.40"]
      and len(warnings) == 2 and "10.77.0.200 - 10.77.0.220" in warnings[0], (small, warnings))
same, warnings = moved_plan(out, "10.77.0.0/24", "10.79.0.0/24")
check("positive: already moved (no subnet is the old LAN's): the plan itself, nothing to say",
      same is out and warnings == [])
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
