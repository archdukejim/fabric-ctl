#!/usr/bin/env python3
"""The upgrade step of 2.1.4.17 (setup/vlan_records_to_subnets, manual 1.4.1.12): a record 0.10.0 gave to one VLAN
answers that VLAN's subnets, keeping its reach; only on positive evidence (a `vlan` field): a fresh install, and every
record without one, left alone; a VLAN with no subnet known leaves the record answering no one, as before, and says
so; run by upgrade_vars. Pure logic; no container.

    python3 tests/setup/vlan_records_to_subnets_test.py
"""
import copy
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
import fabriclib.setup.vlan_records_to_subnets as vr  # noqa: E402
from fabriclib.setup.upgrade_vars import upgrade_vars  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


PLAN = {"vlans": [{"id": 20, "location": ""}, {"id": 30, "location": ""}],
        "subnets": [{"cidr": "10.1.21.0/24", "vlan": 20, "location": ""},
                    {"cidr": "10.1.20.0/24", "vlan": 20, "location": ""}]}
OLD = {"host_ip": "10.1.10.5", "lan_cidr": "10.1.10.0/24",
       "dns": {"dynamic_zone_var": {"A": [{"name": "nas", "ip": "192.168.1.10"},
                                          {"name": "nas", "ip": "10.1.20.10", "vlan": "20"},
                                          {"name": "cam", "ip": "10.1.30.9", "vlan": "30"},
                                          {"name": "old", "ip": "10.1.10.9", "vlan": ""}]},
               "iot.lan": {"TXT": [{"name": "hello", "text": "v=one", "vlan": "20"}]}}}

data = copy.deepcopy(OLD)
changes = vr.vlan_records_to_subnets(data, PLAN)
a = data["dns"]["dynamic_zone_var"]["A"]
check("positive: a record for VLAN 20 answers VLAN 20's subnets, sorted; its vlan field gone",
      a[1] == {"name": "nas", "ip": "10.1.20.10", "subnets": ["10.1.20.0/24", "10.1.21.0/24"]}, a[1])
check("...in every zone", data["dns"]["iot.lan"]["TXT"][0].get("subnets") == ["10.1.20.0/24", "10.1.21.0/24"])
check("positive: a VLAN with no subnet in the plan: no subnet (it answered no one, and still does), said so",
      a[2] == {"name": "cam", "ip": "10.1.30.9", "subnets": []} and any("VLAN 30 has none" in c for c in changes), a[2])
check("positive: an empty vlan answered everyone: the field goes, every subnet still", a[3] == {"name": "old",
                                                                                               "ip": "10.1.10.9"})
check("negative: a record without vlan is left as it is (it answers every subnet)", a[0] == OLD["dns"][
      "dynamic_zone_var"]["A"][0])
check("each record moved is said once", len(changes) == 3 and all("2.1.4.17" in c for c in changes), changes)
again = copy.deepcopy(data)
check("negative: run again: nothing changes (no vlan field is left)", vr.vlan_records_to_subnets(again, PLAN) == []
      and again == data)
fresh = {"lan_cidr": "10.1.10.0/24", "dns": {"dynamic_zone_var": {"A": [{"name": "nas", "ip": "192.168.1.10"}]}}}
before = copy.deepcopy(fresh)
vr.load_plan_cache = lambda: (_ for _ in ()).throw(AssertionError("the plan read without evidence"))
check("negative: a fresh install (no record names a VLAN): nothing changes, the plan not even read",
      vr.vlan_records_to_subnets(fresh) == [] and fresh == before and vr.vlan_records_to_subnets({}) == [])
vr.load_plan_cache = lambda: None
nothing = copy.deepcopy(OLD)
vr.vlan_records_to_subnets(nothing)
check("no plan copy kept: the VLANs' subnets unknown, so those records answer no one (as they did)",
      nothing["dns"]["dynamic_zone_var"]["A"][1]["subnets"] == [])
vr.load_plan_cache = lambda: PLAN
up = copy.deepcopy(OLD)
done = upgrade_vars(up, set())
check("upgrade_vars runs it and lists its changes", any("nas in dynamic_zone_var" in c for c in done)
      and up["dns"]["dynamic_zone_var"]["A"][1]["subnets"] == ["10.1.20.0/24", "10.1.21.0/24"], done)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
