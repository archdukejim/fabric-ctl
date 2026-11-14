#!/usr/bin/env python3
"""A record's VLAN, as typed (decision 2.1.4.16, manual 1.4.1.11): a VLAN of the site's plan, kept as its reference;
refused, saying why: not a VLAN, a VLAN the plan has not, a reverse zone, a CNAME beside another record of the same
name for the same VLAN (both ways); a record for everyone and one for a VLAN may share a name. Pure logic; no
container.

    python3 tests/dns/split/record_vlan_test.py
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.dns.split.record_vlan import record_vlan  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def refused(fn, words):
    try:
        fn()
    except ValidationError as e:
        return words in str(e) or str(e)
    return "not refused"


PLAN = {"vlans": [{"id": 10, "location": ""}, {"id": 20, "location": ""}, {"id": 20, "location": "branch"}]}
ZONE = {"A": [{"name": "nas", "ip": "192.168.1.10"}, {"name": "nas", "ip": "10.1.20.10", "vlan": "20"}],
        "CNAME": [{"name": "files", "canonical": "nas", "vlan": "20"}]}
A = {"name": "web", "ip": "10.1.20.11"}

check("positive: no VLAN given: the record answers everyone, unchanged",
      record_vlan("dynamic_zone_var", "A", A, {}, ZONE, plan=PLAN) == A)
check("positive: a VLAN of the plan: kept as its reference",
      record_vlan("dynamic_zone_var", "A", A, {"vlan": " 20 "}, ZONE, plan=PLAN) == {**A, "vlan": "20"})
check("positive: a VLAN at a location", record_vlan("iot.lan", "A", A, {"vlan": "20@Branch"}, ZONE, plan=PLAN)
      == {**A, "vlan": "20@branch"})
check("positive: a name everyone has may have a VLAN's own record too (that is the split)",
      record_vlan("dynamic_zone_var", "A", {"name": "nas", "ip": "10.1.10.10"}, {"vlan": "10"}, ZONE, plan=PLAN)
      ["vlan"] == "10")
check("positive: replacing a VLAN's CNAME with itself is no clash (its own place is left out)",
      record_vlan("dynamic_zone_var", "CNAME", {"name": "files", "canonical": "nas2"}, {"vlan": "20"}, ZONE, index=0,
                  plan=PLAN)["vlan"] == "20")
for name, fn, words in (
        ("not a VLAN", lambda: record_vlan("dynamic_zone_var", "A", A, {"vlan": "lab"}, ZONE, plan=PLAN), "VLAN"),
        ("a VLAN the plan has not", lambda: record_vlan("dynamic_zone_var", "A", A, {"vlan": "30"}, ZONE, plan=PLAN),
         "VLAN 30 is not in the site's plan (it has 10, 20, 20@branch)"),
        ("no plan read yet", lambda: record_vlan("dynamic_zone_var", "A", A, {"vlan": "20"}, ZONE, plan={}),
         "none yet"),
        ("a reverse zone", lambda: record_vlan("20.1.10.in-addr.arpa", "A", A, {"vlan": "20"}, ZONE, plan=PLAN),
         "reverse zone answers everyone"),
        ("a CNAME beside the VLAN's own A of that name",
         lambda: record_vlan("dynamic_zone_var", "CNAME", {"name": "nas", "canonical": "x"}, {"vlan": "20"}, ZONE,
                             plan=PLAN), "a CNAME cannot sit beside"),
        ("another record beside the VLAN's CNAME of that name",
         lambda: record_vlan("dynamic_zone_var", "TXT", {"name": "files", "text": "t"}, {"vlan": "20"}, ZONE,
                             plan=PLAN), "a CNAME cannot sit beside")):
    check(f"negative: refused, saying why: {name}", refused(fn, words) is True, refused(fn, words))
check("positive: the same CNAME name for another VLAN is no clash",
      record_vlan("dynamic_zone_var", "CNAME", {"name": "files", "canonical": "nas"}, {"vlan": "10"}, ZONE,
                  plan=PLAN)["vlan"] == "10")

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
