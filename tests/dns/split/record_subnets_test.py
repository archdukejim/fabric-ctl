#!/usr/bin/env python3
"""A record's subnets, as typed (decision 2.1.4.17, manual 1.4.1.12): a new record starts on the host's LAN alone; with
the DNS filter off a new record in a forward zone is refused (2.1.4.17.3), an existing one may still be changed for
every subnet; every subnet is a choice, never the default; several subnets
of the host's LAN and the plan are kept sorted; an edit that leaves them out keeps the record's own; refused, saying
why: none picked, every subnet beside a subnet, not a subnet, one neither the host's LAN nor in the plan, a reverse
zone, the DNS filter off, a CNAME beside another record of the same name for a subnet in common (both ways); a record
for every subnet and one for some subnets may share a name. The subnets offered (offered_subnets) and what a record
reaches (reach). Pure logic; no container.

    python3 tests/dns/split/record_subnets_test.py
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.dns.split.offered_subnets import offered_subnets  # noqa: E402
from fabriclib.dns.split.reach import reach  # noqa: E402
from fabriclib.dns.split.record_subnets import default_reach, record_subnets  # noqa: E402

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


LAN, IOT, IOT2 = "10.1.10.0/24", "10.1.20.0/24", "10.1.21.0/24"
PLAN = {"subnets": [{"name": "lan", "cidr": LAN}, {"name": "iot", "cidr": IOT}, {"name": "iot-2", "cidr": IOT2}]}
V = {"lan_cidr": LAN}
OFF = {"lan_cidr": LAN, "dns_filter": "none"}
ZONE = {"A": [{"name": "nas", "ip": "192.168.1.10"}, {"name": "nas", "ip": "10.1.20.10", "subnets": [IOT]}],
        "CNAME": [{"name": "files", "canonical": "nas", "subnets": [IOT, IOT2]}]}
A = {"name": "web", "ip": "10.1.20.11"}


def rs(form, key="dynamic_zone_var", rtype="A", rec=A, v=V, **kw):
    return record_subnets(key, rtype, rec, form, ZONE, v, plan=PLAN, **kw)


print("--- offered_subnets and reach")
check("offered: the host's LAN first, then the plan's subnets, each once (the plan's own LAN not twice)",
      offered_subnets(V, PLAN) == [{"cidr": LAN, "label": f"{LAN} (host's LAN)"},
                                   {"cidr": IOT, "label": f"{IOT} (iot)"}, {"cidr": IOT2, "label": f"{IOT2} (iot-2)"}],
      offered_subnets(V, PLAN))
check("offered: no plan read yet: the host's LAN alone", [o["cidr"] for o in offered_subnets(V, {})] == [LAN])
check("reach: a record with no subnets (every record before 0.10.2) answers every subnet",
      reach({"name": "x"}) == "all" and reach({"subnets": [IOT2, IOT]}) == [IOT, IOT2] and reach({"subnets": []}) == [])

print("--- the default")
check("positive: a new record with no subnets given starts on the host's LAN alone", rs({}) == {**A, "subnets": [LAN]})
check("positive: ...the default the console's add row shows", default_reach(V, offered_subnets(V, PLAN)) == [LAN])
check("positive: every subnet, picked: the record answers every subnet (no `subnets` kept)", rs({"subnets": "all"}) == A)
# the DNS filter off (2.1.4.17.3, the owner 2026-11-24: "Refuse new records")
for form in ({}, {"subnets": "all"}, {"subnets": LAN}):
    check(f"negative: the DNS filter off: a new record ({form or 'the default'}) refused, saying to turn it on",
          refused(lambda: rs(form, v=OFF), "a new record needs the DNS filter on") is True,
          refused(lambda: rs(form, v=OFF), ""))
check("positive: the DNS filter off: an existing record changed, every subnet kept",
      rs({}, rec={"name": "nas", "ip": "192.168.1.11"}, v=OFF, index=0, old=ZONE["A"][0]) == {"name": "nas",
                                                                                              "ip": "192.168.1.11"}
      and rs({"subnets": "all"}, rec={"name": "nas", "ip": "10.1.20.12"}, v=OFF, index=1, old=ZONE["A"][1])
      == {"name": "nas", "ip": "10.1.20.12"})
check("negative: the DNS filter off: an existing record given some subnets: refused",
      refused(lambda: rs({"subnets": LAN}, v=OFF, index=0, old=ZONE["A"][0]), "needs the DNS filter on") is True)
check("positive: the DNS filter off: a new record in a reverse zone (it answers every subnet) is not refused",
      rs({}, key="20.1.10.in-addr.arpa", v=OFF) == A)
check("positive: a new record in a reverse zone with no subnets given answers every subnet (never the host's LAN)",
      rs({}, key="20.1.10.in-addr.arpa") == A)

print("--- picked subnets")
check("positive: several, comma or space separated, written loosely: kept as networks, sorted, once",
      rs({"subnets": f"{IOT2}, 10.1.20.7/24 {IOT2}"}) == {**A, "subnets": [IOT, IOT2]})
check("positive: a name every subnet has may have a subnet's own record too (that is the split)",
      rs({"subnets": LAN}, rec={"name": "nas", "ip": "10.1.10.10"})["subnets"] == [LAN])
check("positive: an edit that leaves the subnets out keeps the record's own",
      rs({}, rec={"name": "nas", "ip": "10.1.20.12"}, index=1, old=ZONE["A"][1])["subnets"] == [IOT])
check("positive: an edit of a record for every subnet that leaves them out keeps every subnet",
      rs({}, rec={"name": "nas", "ip": "192.168.1.11"}, index=0, old=ZONE["A"][0]) == {"name": "nas",
                                                                                     "ip": "192.168.1.11"})
check("positive: replacing a subnet's CNAME with itself is no clash (its own place is left out)",
      rs({"subnets": IOT}, rtype="CNAME", rec={"name": "files", "canonical": "nas2"}, index=0)["subnets"] == [IOT])
check("positive: a CNAME beside a record of the same name for every subnet is no clash (the subnet's view answers it)",
      rs({"subnets": LAN}, rtype="CNAME", rec={"name": "nas", "canonical": "x"})["subnets"] == [LAN])
check("positive: 0.10.0's vlan field is dropped (the subnets say it now)",
      "vlan" not in rs({"subnets": IOT}, rec={**A, "vlan": "20"}))
for name, fn, words in (
        ("none picked", lambda: rs({"subnets": " "}), "pick at least one subnet"),
        ("every subnet beside a subnet", lambda: rs({"subnets": f"all,{IOT}"}), "pick it alone"),
        ("not a subnet", lambda: rs({"subnets": "lab"}), "lab is not a subnet"),
        ("a subnet neither the host's LAN nor in the plan", lambda: rs({"subnets": "10.9.0.0/24"}),
         "10.9.0.0/24 is neither the host's LAN nor a subnet of the site's plan"),
        ("a reverse zone", lambda: rs({"subnets": IOT}, key="20.1.10.in-addr.arpa"), "reverse zone answers every"),
        ("a CNAME beside a subnet's own A of that name, for a subnet in common",
         lambda: rs({"subnets": f"{IOT},{LAN}"}, rtype="CNAME", rec={"name": "nas", "canonical": "x"}),
         "a CNAME cannot sit beside"),
        ("another record beside a subnet's CNAME of that name",
         lambda: rs({"subnets": IOT2}, rec={"name": "files", "ip": "10.1.21.5"}), "a CNAME cannot sit beside")):
    check(f"negative: {name}: refused, saying why", refused(fn, words) is True, refused(fn, words))

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
