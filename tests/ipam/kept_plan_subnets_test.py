#!/usr/bin/env python3
"""The subnets a new LAN subnet is checked against (ipam/kept_plan_subnets; manual 1.3.7.7, decision 2.1.1.107):
this site's from the plan it last read, by name, and the other sites' it names: pure logic.

    python3 tests/ipam/kept_plan_subnets_test.py
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from fabriclib.ipam.kept_plan_subnets import kept_plan_subnets  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


PLAN = {"site": "hq", "subnets": [{"name": "lan", "cidr": "10.77.0.0/24"}, {"name": "iot", "cidr": "10.78.0.0/24"}],
        "fabric_networks": ["10.90.0.0/24", "10.77.0.0/24", "10.90.0.0/24"]}
KEPT = kept_plan_subnets(lambda: PLAN)
check("the kept plan: this site's subnets by name, each other site's once, none twice",
      KEPT == [{"name": "lan", "cidr": "10.77.0.0/24"}, {"name": "iot", "cidr": "10.78.0.0/24"},
               {"name": "another site's subnet", "cidr": "10.90.0.0/24"}], KEPT)
check("no plan kept: nothing to check against", kept_plan_subnets(lambda: None) == [])


def damaged():
    raise json.JSONDecodeError("bad", "", 0)


def unreadable():
    raise PermissionError("denied")


check("negative: a damaged copy is none (the plan's own check still refuses later)", kept_plan_subnets(damaged) == [])
check("negative: an unreadable copy is none", kept_plan_subnets(unreadable) == [])
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
