#!/usr/bin/env python3
"""The upgrade step of 2.1.4.18 (setup/vlan_records_to_splits, manual 1.4.1.13): the records 0.10.0 gave to a VLAN
become a split of their zone for that VLAN's subnets, holding the zone's other records with the VLAN's in place of
theirs for the same names (fabric's own names left out); only on positive evidence (a `vlan` field): a fresh install,
and every record without one, left alone; a VLAN with no subnet known answered no one, so its records are dropped,
said so; run by upgrade_vars. Pure logic; no container.

    python3 tests/setup/vlan_records_to_splits_test.py
"""
import copy
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
import fabriclib.setup.vlan_records_to_splits as vr  # noqa: E402
from fabriclib.setup.upgrade_vars import upgrade_vars  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


PLAN = {"vlans": [{"id": 20, "location": ""}, {"id": 30, "location": ""}],
        "subnets": [{"cidr": "10.1.21.0/24", "vlan": 20, "location": ""},
                    {"cidr": "10.1.20.0/24", "vlan": 20, "location": ""}]}
OLD = {"host_ip": "10.1.10.5", "lan_cidr": "10.1.10.0/24", "domain": "home.lan", "hostname": "core",
       "dns": {"dynamic_zone_var": {"A": [{"name": "nas", "ip": "192.168.1.10"},
                                          {"name": "web", "ip": "192.168.1.11"},
                                          {"name": "nas", "ip": "10.1.20.10", "vlan": "20"},
                                          {"name": "cam", "ip": "10.1.30.9", "vlan": "30"},
                                          {"name": "old", "ip": "10.1.10.9", "vlan": ""},
                                          {"name": "core", "ip": "10.1.10.5"}],
                                    "CNAME": [{"name": "ca", "canonical": "core"}]},
               "iot.lan": {"TXT": [{"name": "hello", "text": "v=one", "vlan": "20"}]}}}

data = copy.deepcopy(OLD)
changes = vr.vlan_records_to_splits(data, PLAN)
zone = data["dns"]["dynamic_zone_var"]
check("positive: the All networks tab keeps the records without a VLAN (an empty vlan is every network), no vlan field",
      zone["A"] == [{"name": "nas", "ip": "192.168.1.10"}, {"name": "web", "ip": "192.168.1.11"},
                    {"name": "old", "ip": "10.1.10.9"}, {"name": "core", "ip": "10.1.10.5"}], zone["A"])
split = (zone.get("splits") or [{}])[0]
check("positive: VLAN 20 becomes a split for its subnets, sorted", split.get("subnets") == ["10.1.20.0/24",
                                                                                           "10.1.21.0/24"], split)
check("positive: ...holding the other records, the VLAN's nas in place of everyone's, fabric's own names left out",
      split.get("A") == [{"name": "web", "ip": "192.168.1.11"}, {"name": "old", "ip": "10.1.10.9"},
                         {"name": "nas", "ip": "10.1.20.10"}] and "CNAME" not in split, split)
check("positive: in every zone: iot.lan's TXT for VLAN 20 is its split's, the zone left with none",
      data["dns"]["iot.lan"] == {"splits": [{"subnets": ["10.1.20.0/24", "10.1.21.0/24"],
                                             "TXT": [{"name": "hello", "text": "v=one"}]}]}, data["dns"]["iot.lan"])
check("positive: a VLAN with no subnet in the plan: its records dropped (they answered no one), said so",
      len(zone["splits"]) == 1 and any("VLAN 30" in c and "dropped" in c for c in changes), changes)
check("each split made and each VLAN dropped is said once", len(changes) == 3 and all("2.1.4.18" in c for c in changes),
      changes)
again = copy.deepcopy(data)
check("negative: run again: nothing changes (no vlan field is left)", vr.vlan_records_to_splits(again, PLAN) == []
      and again == data)
fresh = {"lan_cidr": "10.1.10.0/24", "dns": {"dynamic_zone_var": {"A": [{"name": "nas", "ip": "192.168.1.10"}]}}}
before = copy.deepcopy(fresh)
vr.load_plan_cache = lambda: (_ for _ in ()).throw(AssertionError("the plan read without evidence"))
check("negative: a fresh install (no record names a VLAN): nothing changes, the plan not even read",
      vr.vlan_records_to_splits(fresh) == [] and fresh == before and vr.vlan_records_to_splits({}) == [])
vr.load_plan_cache = lambda: None
nothing = copy.deepcopy(OLD)
vr.vlan_records_to_splits(nothing)
check("no plan copy kept: the VLANs' subnets unknown, so their records are dropped (they answered no one)",
      "splits" not in nothing["dns"]["dynamic_zone_var"] and nothing["dns"]["iot.lan"] == {})
vr.load_plan_cache = lambda: PLAN
up = copy.deepcopy(OLD)
done = upgrade_vars(up, set())
check("upgrade_vars runs it and lists its changes", any("dynamic_zone_var: VLAN 20" in c for c in done)
      and up["dns"]["dynamic_zone_var"]["splits"][0]["subnets"] == ["10.1.20.0/24", "10.1.21.0/24"], done)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
