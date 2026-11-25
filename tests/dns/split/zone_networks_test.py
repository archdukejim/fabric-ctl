#!/usr/bin/env python3
"""A zone's networks and its splits, changed (decision 2.1.4.18, manual 1.4.1.13): set_zone_networks, add_split,
update_split, remove_split and a record added, changed or removed in a split's tab, each against settings held in
memory (the settings file, its lock and the audit stood in for). Positive: a zone mapped to some networks and back to
every network; a split copied from the All networks tab less fabric's own names; its networks changed; a record in
its tab changed there alone; the split removed. Negative, each refused saying why and changing nothing: none picked;
every network beside a network; every network for a split; not a subnet; one not offered; a reverse zone; the site's
own domain mapped; a zone holding another mapped; the DNS filter off; a split's network left out of the zone's; a
network already in another split, or not the zone's; a stale split; one of fabric's own names in a split; nothing to
change. Pure logic; no container.

    python3 tests/dns/split/zone_networks_test.py
"""
import contextlib
import copy
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REPO, "src"))
import fabriclib.dns.add_record as add_mod  # noqa: E402
import fabriclib.dns.remove_record as remove_mod  # noqa: E402
import fabriclib.dns.split.add_split as add_split_mod  # noqa: E402
import fabriclib.dns.split.remove_split as remove_split_mod  # noqa: E402
import fabriclib.dns.split.set_zone_networks as nets_mod  # noqa: E402
import fabriclib.dns.split.update_split as update_split_mod  # noqa: E402
import fabriclib.dns.update_record as update_mod  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


LAN, IOT, IOT2 = "10.1.10.0/24", "10.1.20.0/24", "10.1.21.0/24"
PLAN = {"subnets": [{"name": "iot", "cidr": IOT}, {"name": "iot-2", "cidr": IOT2}]}
START = {"domain": "home.arpa", "hostname": "core", "host_ip": "10.1.10.5", "lan_cidr": LAN,
         "dns": {"dynamic_zone_var": {"A": [{"name": "nas", "ip": "192.168.1.10"}, {"name": "core", "ip": "10.1.10.5"}],
                                      "CNAME": [{"name": "ca", "canonical": "core"}]},
                 "iot.lan": {"A": [{"name": "hello", "ip": "10.1.20.5"}]},
                 "lan": {"A": []},
                 "20.1.10.in-addr.arpa": {}}}
state = {}
audit = []
for mod in (nets_mod, add_split_mod, update_split_mod, remove_split_mod, add_mod, update_mod, remove_mod):
    mod.load_vars = lambda: copy.deepcopy(state["v"])
    mod.save_vars = lambda d: state.__setitem__("v", copy.deepcopy(d))
    mod.vars_lock = contextlib.nullcontext
    mod.write_audit = lambda *a, **k: audit.append(a[1])
for mod in (nets_mod, add_split_mod, update_split_mod):
    mod.offered_subnets = (lambda real: lambda v, plan=None: real(v, PLAN))(mod.offered_subnets)


def reset(**extra):
    state["v"] = copy.deepcopy({**START, **extra})


def zone(key="dynamic_zone_var"):
    return state["v"]["dns"][key]


def refused(fn, words):
    before = copy.deepcopy(state["v"])
    try:
        fn()
    except ValidationError as e:
        return (words in str(e) and state["v"] == before) or f"{e} (changed: {state['v'] != before})"
    return "not refused"


reset()
print("--- a zone's networks")
# the agent's routes are what the console posts: their entry points are covered in tests/webui/test_devserver.py
check("positive: a zone mapped to one network, kept sorted, audited",
      nets_mod.set_zone_networks("t", "iot.lan", f"{IOT2}, {IOT}") == {"old": "all", "new": [IOT, IOT2]}
      and zone("iot.lan")["networks"] == [IOT, IOT2] and audit[-1] == "DNS_NETWORKS")
check("positive: back to every network: the field gone", nets_mod.set_zone_networks("t", "iot.lan", "all")["new"]
      == "all" and "networks" not in zone("iot.lan"))
for name, fn, words in (
        ("none picked", lambda: nets_mod.set_zone_networks("t", "iot.lan", " "), "pick at least one network"),
        ("every network beside a network", lambda: nets_mod.set_zone_networks("t", "iot.lan", f"all {IOT}"),
         "pick it alone"),
        ("not a subnet", lambda: nets_mod.set_zone_networks("t", "iot.lan", "lab"), "lab is not a subnet"),
        ("an address, not a subnet", lambda: nets_mod.set_zone_networks("t", "iot.lan", "10.1.20.7"),
         "is not a subnet"),
        ("a network not offered", lambda: nets_mod.set_zone_networks("t", "iot.lan", "10.9.0.0/24"),
         "10.9.0.0/24 is neither the host's LAN nor a subnet of the site's plan"),
        ("a reverse zone", lambda: nets_mod.set_zone_networks("t", "20.1.10.in-addr.arpa", IOT),
         "a reverse zone is never split or mapped"),
        ("the site's own domain", lambda: nets_mod.set_zone_networks("t", "dynamic_zone_var", IOT),
         "the site's own domain is never mapped"),
        ("a zone holding another fabric serves", lambda: nets_mod.set_zone_networks("t", "lan", IOT),
         "lan holds the zone iot.lan"),
        ("nothing to change", lambda: nets_mod.set_zone_networks("t", "iot.lan", "all"), "nothing to change"),
        ("unknown zone", lambda: nets_mod.set_zone_networks("t", "nosuch.lan", IOT), "unknown zone")):
    check(f"negative: {name}: refused, saying why, nothing changed", refused(fn, words) is True, refused(fn, words))
reset(dns_filter="none")
check("negative: the DNS filter off: mapping refused, saying to turn it on",
      refused(lambda: nets_mod.set_zone_networks("t", "iot.lan", IOT), "needs the DNS filter on") is True)

print("--- splits")
reset()
got = add_split_mod.add_split("t", "dynamic_zone_var", IOT)
check("positive: a split added, a copy of All networks less fabric's own names (core, ca)",
      got == {"index": 0, "subnets": [IOT]} and zone()["splits"] == [{"subnets": [IOT], "A": [
          {"name": "nas", "ip": "192.168.1.10"}]}] and audit[-1] == "DNS_SPLIT_ADD", zone().get("splits"))
nets_mod.set_zone_networks("t", "iot.lan", IOT)
check("positive: a split in a mapped zone, of one of its networks", add_split_mod.add_split("t", "iot.lan", IOT)
      == {"index": 0, "subnets": [IOT]} and zone("iot.lan")["splits"][0]["A"] == [{"name": "hello", "ip": "10.1.20.5"}])
for name, fn, words in (
        ("every network for a split", lambda: add_split_mod.add_split("t", "dynamic_zone_var", "all"),
         "a split names networks, never every network"),
        ("a network already in another split", lambda: add_split_mod.add_split("t", "dynamic_zone_var", IOT),
         f"{IOT} is already in another split of this zone"),
        ("a network not the zone's", lambda: add_split_mod.add_split("t", "iot.lan", IOT2),
         f"{IOT2} is not one of the zone's networks"),
        ("a reverse zone", lambda: add_split_mod.add_split("t", "20.1.10.in-addr.arpa", IOT), "a reverse zone"),
        ("the zone mapped away from its split's network", lambda: nets_mod.set_zone_networks("t", "iot.lan", IOT2),
         f"{IOT} is in a split of this zone")):
    check(f"negative: {name}: refused, saying why, nothing changed", refused(fn, words) is True, refused(fn, words))
check("positive: a split's networks changed, its records kept",
      update_split_mod.update_split("t", "dynamic_zone_var", 0, IOT, f"{IOT},{IOT2}") == {"old": [IOT],
                                                                                         "new": [IOT, IOT2]}
      and zone()["splits"][0]["A"] == [{"name": "nas", "ip": "192.168.1.10"}])
for name, fn, words in (
        ("a stale split (its networks changed since shown)",
         lambda: update_split_mod.update_split("t", "dynamic_zone_var", 0, IOT, IOT2), "the split changed"),
        ("no such split", lambda: remove_split_mod.remove_split("t", "dynamic_zone_var", 3, IOT), "the split changed"),
        ("nothing to change", lambda: update_split_mod.update_split("t", "dynamic_zone_var", 0, f"{IOT},{IOT2}",
                                                                    f"{IOT2} {IOT}"), "nothing to change")):
    check(f"negative: {name}: refused, saying why, nothing changed", refused(fn, words) is True, refused(fn, words))

print("--- a split's records")
rec = add_mod.add_record("t", "dynamic_zone_var", "A", {"name": "cam", "ip": "10.1.20.30"}, split=0)
check("positive: a record added in the split's tab: there alone", rec == {"name": "cam", "ip": "10.1.20.30"}
      and {"name": "cam", "ip": "10.1.20.30"} in zone()["splits"][0]["A"]
      and all(r["name"] != "cam" for r in zone()["A"]), zone())
update_mod.update_record("t", "dynamic_zone_var", "A", 0, "nas", {"name": "nas", "ip": "10.1.20.10"}, split=0)
check("positive: a record changed in the split's tab: the All networks one untouched",
      zone()["splits"][0]["A"][0] == {"name": "nas", "ip": "10.1.20.10"} and zone()["A"][0]["ip"] == "192.168.1.10")
for name, fn, words in (
        ("one of fabric's own names in a split", lambda: add_mod.add_record(
            "t", "dynamic_zone_var", "CNAME", {"name": "ca", "target": "elsewhere"}, split=0), "answers in every tab"),
        ("a stale split's tab", lambda: add_mod.add_record("t", "dynamic_zone_var", "A",
                                                           {"name": "x", "ip": "10.1.20.31"}, split=5),
         "the split changed"),
        ("a record changed since shown, in the split", lambda: remove_mod.remove_record(
            "t", "dynamic_zone_var", "A", 0, "other", split=0), "record changed since it was shown")):
    check(f"negative: {name}: refused, saying why, nothing changed", refused(fn, words) is True, refused(fn, words))
remove_mod.remove_record("t", "dynamic_zone_var", "A", 1, "cam", split=0)
check("positive: a record removed from the split's tab", [r["name"] for r in zone()["splits"][0]["A"]] == ["nas"])
gone = remove_split_mod.remove_split("t", "dynamic_zone_var", 0, f"{IOT},{IOT2}")
check("positive: the split removed with its records; the zone has no splits left", gone["subnets"] == [IOT, IOT2]
      and "splits" not in zone() and audit[-1] == "DNS_SPLIT_DELETE", zone())
reset(dns_filter="none")
check("negative: the DNS filter off: a split refused, saying to turn it on",
      refused(lambda: add_split_mod.add_split("t", "dynamic_zone_var", IOT), "needs the DNS filter on") is True)
check("positive: the DNS filter off: an All networks record still added (as before 0.10.2)",
      add_mod.add_record("t", "dynamic_zone_var", "A", {"name": "web", "ip": "192.168.1.11"})["name"] == "web")

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
