#!/usr/bin/env python3
"""The `ipam` suite (manual 1.10.4.3, 1.10.4.41): the address manager's model with no container. Its rules: one
claim per address, ranges inside their subnet and apart, only reservations in a dhcp range, and overlaps refused
unless a reason is given. Also its suggestions, the site's number, several subnets on one VLAN (2.1.10.16, 2.1.10.18),
the changes that add or change a subnet, and one site's plan out of read_plan's answer on 0.8.0's directory
(1.10.4.32); the address table, find, export and show; one change made the way every command makes it (the grant
checked first, the writable DC, nothing written on a refusal: 1.10.4.34), with the domain stood in for; and
`fabricctl ipam`'s refusals that need no domain. Area 5 (Kea and DNS from the plan): plan_to_dhcp, a name set by
hand winning over DHCP's (2.1.10.20), the plan rendered for Kea and DNS (1.10.4.14). The options:
tests/ipam/options.py. Area 6 adds its sections here. The plan in a real domain: tests/samba/ipam.py.

    python3 tests/ipam/run.py
"""
import copy
import io
import ipaddress
import json
import os
import sys
from contextlib import redirect_stderr, redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
import fabriclib.ipam.common.edit_plan as m_edit  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.dhcp.dhcp_reverse_zones import dhcp_reverse_zones  # noqa: E402
from fabriclib.dhcp.normalize_dhcp import normalize_dhcp  # noqa: E402
from fabriclib.dns.reverse_by_hand import reverse_by_hand  # noqa: E402
from fabriclib.ipam.check_address import check_address  # noqa: E402
from fabriclib.ipam.check_block import check_block  # noqa: E402
from fabriclib.ipam.check_range import check_range  # noqa: E402
from fabriclib.ipam.check_subnet import check_subnet  # noqa: E402
from fabriclib.ipam.check_vlan import check_vlan  # noqa: E402
from fabriclib.ipam.common.change_subnet import change_subnet  # noqa: E402
from fabriclib.ipam.common.fields import find_address, find_subnet, find_vlan, subnet_holding  # noqa: E402
from fabriclib.ipam.common.new_subnet import new_subnet  # noqa: E402
from fabriclib.ipam.common.option_codes import CATALOGUE, CODES, FABRIC_PROVIDED  # noqa: E402
from fabriclib.ipam.common.pool_text import pool_text  # noqa: E402
from fabriclib.ipam.common.scan_busy import ScanBusy  # noqa: E402
from fabriclib.ipam.common.site_plan import site_plan  # noqa: E402
from fabriclib.ipam.add_subnet import add_subnet  # noqa: E402
from fabriclib.ipam.add_vlan import add_vlan  # noqa: E402
from fabriclib.ipam.export_plan import export_plan  # noqa: E402
from fabriclib.ipam.find_in_plan import find_in_plan  # noqa: E402
from fabriclib.ipam.plan_rows import plan_rows  # noqa: E402
from fabriclib.ipam.plan_to_dhcp import plan_to_dhcp  # noqa: E402
from fabriclib.ipam.run_ipam_command import run_ipam_command  # noqa: E402
from fabriclib.ipam.show_plan import show_plan  # noqa: E402
from fabriclib.ipam.suggestions import suggest_block, suggest_split, suggest_subnet  # noqa: E402


FAILED = 0


def check(name, ok, detail=""):
    global FAILED
    FAILED += not ok
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:400]}"))


def refused(fn, words):
    try:
        fn()
    except ValidationError as e:
        return words in str(e) or str(e)
    return "not refused"


def is_refused(fn, words):
    return refused(fn, words) is True


SUB = {"name": "iot", "cidr": "10.1.20.0/24", "vlan": 20, "gateway": "10.1.20.1", "dhcp": True, "id": 3, "relay": "",
       "notes": "", "allow_overlap": "", "options": [],
       "ranges": [{"kind": "gateway", "first": "10.1.20.1", "last": "10.1.20.1", "notes": ""},
                  {"kind": "static", "first": "10.1.20.2", "last": "10.1.20.99", "notes": ""},
                  {"kind": "dhcp", "first": "10.1.20.100", "last": "10.1.20.249", "notes": ""},
                  {"kind": "reserved", "first": "10.1.20.250", "last": "10.1.20.254", "notes": ""}],
       "addresses": [{"ip": "10.1.20.10", "kind": "static", "name": "nas", "mac": "", "owner": "office", "notes": "",
                      "dns": True, "options": []},
                     {"ip": "10.1.20.150", "kind": "reservation", "name": "cam1", "mac": "aa:bb:cc:dd:ee:01",
                      "owner": "", "notes": "", "dns": False,
                      "options": [{"name": "boot-file-name", "data": "cam.bin"}]}]}
PLAN = {"site": "lan", "block": 1,
        "vlans": [{"id": 20, "name": "iot", "purpose": "cameras", "access": "full", "notes": ""},
                  {"id": 30, "name": "guest", "purpose": "", "access": "guest", "notes": ""}],
        "subnets": [SUB, {"name": "guest", "cidr": "10.1.30.0/24", "vlan": 30, "gateway": "10.1.30.1", "dhcp": True,
                          "id": 4, "relay": "", "notes": "", "allow_overlap": "", "options": [],
                          "ranges": [{"kind": "dhcp", "first": "10.1.30.100", "last": "10.1.30.200", "notes": ""}],
                          "addresses": []}],
        "networks": [{"name": "lan", "cidr": "192.168.4.0/24", "kind": "lan", "vlan": None, "notes": "",
                      "allow_overlap": ""}]}
NETS = [{"site": "lan", "name": "lan", "cidr": "192.168.4.0/24", "kind": "lan", "allow_overlap": ""},
        {"site": "lan", "name": "iot", "cidr": "10.1.20.0/24", "kind": "dhcp", "allow_overlap": ""},
        {"site": "house2", "name": "mgmt", "cidr": "10.2.10.0/24", "kind": "dhcp", "allow_overlap": ""}]

print("--- the VLAN (1.10.4.3)")
v = check_vlan({"id": 40, "name": "Printers", "purpose": "print", "access": "full", "notes": ""}, PLAN)
check("a VLAN with a free ID and name is accepted, its name lower-case", v["name"] == "printers" and v["id"] == 40)
check("refused: a VLAN ID the site has, naming its VLAN",
      is_refused(lambda: check_vlan({"id": 20, "name": "x"}, PLAN), "already in this site's plan (iot)"))
check("refused: a name another VLAN of the site has",
      is_refused(lambda: check_vlan({"id": 41, "name": "iot"}, PLAN), "already VLAN 20's"))
check("refused: VLAN 0 and 4095", is_refused(lambda: check_vlan({"id": 0, "name": "a"}, PLAN), "1 to 4094")
      and is_refused(lambda: check_vlan({"id": 4095, "name": "a"}, PLAN), "1 to 4094"))
check("refused: a name that is not one DNS label", is_refused(lambda: check_vlan({"id": 41, "name": "a b"}, PLAN),
                                                                "one DNS label"))
check("refused: an access other than full or guest",
      is_refused(lambda: check_vlan({"id": 41, "name": "a", "access": "open"}, PLAN), "full"))
check("a VLAN being changed keeps its own ID and name", check_vlan({"id": 20, "name": "iot"}, PLAN, current=20)["id"] == 20)

print("--- the subnet: overlaps across the organisation (1.10.2.6, 1.10.4.3.2)")
ok = check_subnet({"name": "cams", "cidr": "10.1.21.0/24", "gateway": "10.1.21.1", "dhcp": True}, PLAN, "lan", NETS)
check("a subnet overlapping nothing is accepted with its gateway", ok["cidr"] == "10.1.21.0/24"
      and ok["gateway"] == "10.1.21.1")
check("refused: a subnet overlapping another site's network, naming it and its site",
      is_refused(lambda: check_subnet({"name": "x", "cidr": "10.2.0.0/16"}, PLAN, "lan", NETS),
                 "overlaps 10.2.10.0/24 (mgmt) of site house2"))
check("refused: a subnet overlapping one of the same site",
      is_refused(lambda: check_subnet({"name": "x", "cidr": "10.1.20.128/25"}, PLAN, "lan", NETS), "(iot) of site lan"))
check("accepted with a reason (--allow-overlap)",
      check_subnet({"name": "x", "cidr": "10.2.0.0/16", "allow_overlap": "NAT"}, PLAN, "lan", NETS)["allow_overlap"]
      == "NAT")
check("the site's own LAN, served as a VLAN, is no overlap",
      check_subnet({"name": "lanv", "cidr": "192.168.4.0/24"}, PLAN, "lan", NETS)["cidr"] == "192.168.4.0/24")
check("refused: fabric's own container network",
      is_refused(lambda: check_subnet({"name": "x", "cidr": "10.255.0.0/16"}, PLAN, "lan", []), "fabric_subnet"))
check("refused: host bits set, IPv6, or smaller than /30",
      is_refused(lambda: check_subnet({"name": "x", "cidr": "10.1.21.1/24"}, PLAN, "lan", []), "host bits zero")
      and is_refused(lambda: check_subnet({"name": "x", "cidr": "fd00::/64"}, PLAN, "lan", []), "IPv4")
      and is_refused(lambda: check_subnet({"name": "x", "cidr": "10.1.21.0/31"}, PLAN, "lan", []), "/30"))
check("refused: a gateway outside the subnet, or its network address",
      is_refused(lambda: check_subnet({"name": "x", "cidr": "10.1.21.0/24", "gateway": "10.1.22.1"}, PLAN, "lan", []),
                 "outside the subnet")
      and is_refused(lambda: check_subnet({"name": "x", "cidr": "10.1.21.0/24", "gateway": "10.1.21.0"}, PLAN, "lan",
                                          []), "network's own"))
check("refused: a subnet name the site uses",
      is_refused(lambda: check_subnet({"name": "guest", "cidr": "10.1.21.0/24"}, PLAN, "lan", []), "already used"))
check("a subnet being changed is no overlap with itself",
      check_subnet({**SUB}, PLAN, "lan", NETS, current="iot")["name"] == "iot")

print("--- ranges (1.10.4.3)")
bare = {**SUB, "ranges": [], "addresses": []}
check("a range inside its subnet is accepted", check_range({"kind": "dhcp", "first": "10.1.20.100",
                                                           "last": "10.1.20.200"}, bare)["kind"] == "dhcp")
check("refused: a range overlapping another, naming it",
      is_refused(lambda: check_range({"kind": "static", "first": "10.1.20.90", "last": "10.1.20.110"}, SUB),
                 "overlaps the static range 10.1.20.2 - 10.1.20.99"))
check("refused: a range outside its subnet", is_refused(lambda: check_range({"kind": "static", "first": "10.1.21.2",
                                                                            "last": "10.1.21.9"}, bare), "outside"))
check("refused: first after last", is_refused(lambda: check_range({"kind": "static", "first": "10.1.20.9",
                                                                  "last": "10.1.20.2"}, bare), "comes before"))
check("refused: an unknown kind", is_refused(lambda: check_range({"kind": "pool", "first": "10.1.20.2",
                                                                 "last": "10.1.20.9"}, bare), "one of gateway"))
with_static = {**SUB, "ranges": []}
check("refused: a dhcp range over a static address (only reservations may be there)",
      is_refused(lambda: check_range({"kind": "dhcp", "first": "10.1.20.5", "last": "10.1.20.20"}, with_static),
                 "may hold only reservations"))
check("a dhcp range over a reservation is accepted",
      check_range({"kind": "dhcp", "first": "10.1.20.140", "last": "10.1.20.160"}, with_static)["first"]
      == "10.1.20.140")
check("refused: a dhcp range over the gateway",
      is_refused(lambda: check_range({"kind": "dhcp", "first": "10.1.20.1", "last": "10.1.20.5"},
                                     {**bare, "gateway": "10.1.20.1"}), "Kea would hand it out"))

print("--- addresses: one claim each (1.10.4.3.2)")
a, w = check_address({"ip": "10.1.20.20", "kind": "static", "name": "Printer", "dns": True}, SUB, PLAN)
check("a static address in the static range: accepted, no warning, its name lower-case", a["name"] == "printer"
      and w == [])
check("refused: a second claim, naming the first",
      is_refused(lambda: check_address({"ip": "10.1.20.10", "kind": "static"}, SUB, PLAN),
                 "already claimed: a static address (nas)"))
check("refused: the gateway's address", is_refused(lambda: check_address({"ip": "10.1.20.1", "kind": "static"}, SUB,
                                                                         PLAN), "the gateway"))
check("refused: a static address in the DHCP range",
      is_refused(lambda: check_address({"ip": "10.1.20.120", "kind": "static"}, SUB, PLAN), "only a reservation"))
r, w = check_address({"ip": "10.1.20.120", "kind": "reservation", "mac": "AA-BB-CC-DD-EE-02"}, SUB, PLAN)
check("a reservation in the DHCP range is accepted, its MAC normalized", r["mac"] == "aa:bb:cc:dd:ee:02" and w == [])
_, w = check_address({"ip": "10.1.20.251", "kind": "static"}, SUB, PLAN)
check("a static address outside the static ranges is warned about, never refused",
      w and "outside the subnet's static ranges" in w[0], w)
check("refused: a reservation without a MAC", is_refused(lambda: check_address({"ip": "10.1.20.121",
                                                                               "kind": "reservation"}, SUB, PLAN),
                                                         "needs the device's MAC"))
check("refused: a MAC that already has a reservation",
      is_refused(lambda: check_address({"ip": "10.1.20.121", "kind": "reservation", "mac": "aa:bb:cc:dd:ee:01"}, SUB,
                                       PLAN), "already has a reservation: 10.1.20.150"))
r, w = check_address({"ip": "10.1.20.121", "kind": "reservation", "mac": "aa:bb:cc:dd:ee:03", "name": "cam9",
                      "dns": True}, SUB, PLAN)
check("a reservation may be published in DNS too, beside DHCP's own name (2.1.10.17)", r["dns"] and w == [], (r, w))
check("refused: a reservation published under a name another address publishes",
      is_refused(lambda: check_address({"ip": "10.1.20.121", "kind": "reservation", "mac": "aa:bb:cc:dd:ee:03",
                                        "name": "nas", "dns": True}, SUB, PLAN), "already published"))
check("refused: DNS without a name, and a name another address publishes",
      is_refused(lambda: check_address({"ip": "10.1.20.21", "kind": "static", "dns": True}, SUB, PLAN), "needs a name")
      and is_refused(lambda: check_address({"ip": "10.1.20.21", "kind": "static", "name": "nas", "dns": True}, SUB,
                                           PLAN), "already published"))
check("refused: outside the subnet, a bad MAC, an unknown kind",
      is_refused(lambda: check_address({"ip": "10.1.21.5", "kind": "static"}, SUB, PLAN), "outside the subnet")
      and is_refused(lambda: check_address({"ip": "10.1.20.22", "kind": "static", "mac": "zz"}, SUB, PLAN), "MAC")
      and is_refused(lambda: check_address({"ip": "10.1.20.22", "kind": "dynamic"}, SUB, PLAN), "one of static"))
_, w = check_address({"ip": "10.1.20.10", "kind": "static", "name": "nas", "dns": True}, SUB, PLAN, current="10.1.20.10")
check("an address being changed is not a second claim on itself", w == [])
_, w = check_address({"ip": "10.1.20.30", "kind": "reservation", "mac": "aa:bb:cc:dd:ee:04"}, {**SUB, "dhcp": False},
                     PLAN)
check("a reservation in a subnet DHCP does not serve is warned about", any("not served by DHCP" in x for x in w), w)

print("--- what fabric suggests (1.10.4.3.3)")
check("VLAN 10 at site 1: 10.1.10.0/24; VLAN 255: 10.1.255.0/24", suggest_subnet(1, 10) == "10.1.10.0/24"
      and suggest_subnet(1, 255) == "10.1.255.0/24")
check("no suggestion above VLAN 255 or without a site number", suggest_subnet(1, 300) is None
      and suggest_subnet(None, 10) is None)
split = suggest_split("10.1.20.0/24")
check("a /24's split: gateway .1, static .2-.99, DHCP .100-.249, reserved .250-.254",
      split["gateway"] == "10.1.20.1" and [(r["kind"], r["first"], r["last"]) for r in split["ranges"]] == [
          ("gateway", "10.1.20.1", "10.1.20.1"), ("static", "10.1.20.2", "10.1.20.99"),
          ("dhcp", "10.1.20.100", "10.1.20.249"), ("reserved", "10.1.20.250", "10.1.20.254")])
check("another size: only the gateway, its first host", suggest_split("10.1.64.0/22") == {"gateway": "10.1.64.1",
                                                                                            "ranges": []})
sites = [{"name": "lan", "created": "1", "block": 1}, {"name": "house2", "created": "2", "block": None},
         {"name": "house3", "created": "3", "block": 3}]
check("a site's number: its order in the organisation", suggest_block(sites, "house2") == 2)
check("a taken number gives the next free one", suggest_block([*sites[:2], {"name": "x", "created": "0", "block": 2}],
                                                              "house2") == 3)

print("--- the site's number (2.1.10.16)")
check("a free number from 1 to 255 is accepted, as typed or as an int", check_block("2", sites, "house2") == 2
      and check_block(255, sites, "house2") == 255)
check("a site keeps its own number", check_block(3, sites, "house3") == 3)
check("refused: 0, 256, text and a boolean", is_refused(lambda: check_block("0", sites, "house2"), "1 to 255")
      and is_refused(lambda: check_block(256, sites, "house2"), "1 to 255")
      and is_refused(lambda: check_block("two", sites, "house2"), "1 to 255")
      and is_refused(lambda: check_block(True, sites, "house2"), "1 to 255"))
check("refused: another site's number, naming it", is_refused(lambda: check_block(3, sites, "house2"),
                                                              "already house3's"))

print("--- more than one subnet per VLAN (2.1.10.18)")
SECOND = {"name": "iot-2", "cidr": "10.1.21.0/24", "vlan": 20, "gateway": "10.1.21.1", "dhcp": True, "id": 5,
          "relay": "", "notes": "renumbering", "allow_overlap": "", "options": [],
          "ranges": [{"kind": "dhcp", "first": "10.1.21.100", "last": "10.1.21.200", "notes": ""}],
          "addresses": [{"ip": "10.1.21.150", "kind": "reservation", "name": "cam5", "mac": "aa:bb:cc:dd:ee:05",
                         "owner": "", "notes": "", "dns": True, "options": []}]}
TWO = {**PLAN, "subnets": [SUB, PLAN["subnets"][1], SECOND]}
vlan20, subs20 = find_vlan(TWO, 20)
check("a VLAN's subnets, in the plan's order", [s["name"] for s in subs20] == ["iot", "iot-2"])
check("an address goes in the VLAN's subnet holding it",
      subnet_holding(vlan20, subs20, ipaddress.ip_address("10.1.21.7"), "address")["name"] == "iot-2")
check("refused: an address in none of the VLAN's subnets, naming them",
      is_refused(lambda: subnet_holding(vlan20, subs20, ipaddress.ip_address("10.1.22.7"), "address"),
                 "none of VLAN 20's subnets (10.1.20.0/24, 10.1.21.0/24)"))
check("refused: a VLAN with no subnet", is_refused(lambda: subnet_holding({"id": 40}, [], None, "address"),
                                                   "has no subnet"))
check("a subnet by its name or its network", find_subnet(TWO, "IOT-2")["cidr"] == "10.1.21.0/24"
      and find_subnet(TWO, "10.1.21.0/24")["name"] == "iot-2")
check("refused: a subnet the plan does not have", is_refused(lambda: find_subnet(TWO, "10.9.0.0/24"),
                                                             "is not a subnet of lan's plan"))
two = plan_to_dhcp(TWO)
check("both subnets of the VLAN are Kea's, with the VLAN; the reservation's name is an A record of the site's zone",
      [(s["name"], s.get("vlan")) for s in two["subnets"]] == [("iot", 20), ("guest", 30), ("iot-2", 20)]
      and {"name": "cam5", "ip": "10.1.21.150"} in two["records"], two)
VT = {"install_kea": True, "domain": "lan.test", "host_ip": "192.168.4.2",
      "dns": {"dynamic_zone_var": {"A": two["records"]}}, "dhcp": {"interfaces": ["eth0"], "subnets": two["subnets"]}}
try:
    check("fabric's DHCP checks accept two subnets on one VLAN and a reservation's A record inside its pool",
          len(normalize_dhcp(VT)["subnets"]) == 3)
except ValidationError as e:
    check("fabric's DHCP checks accept two subnets on one VLAN and a reservation's A record inside its pool", False, e)
check("refused still: a static A record inside a pool that is no reservation's",
      is_refused(lambda: normalize_dhcp({**VT, "dns": {"dynamic_zone_var": {"A": [{"name": "x",
                                                                                     "ip": "10.1.21.160"}]}}}),
                 "inside a DHCP pool"))

print("--- a name set by hand wins over DHCP's (2.1.10.20)")
cam5 = next(r for s in two["subnets"] for r in s["reservations"] if r["ip"] == "10.1.21.150")
cam1 = next(r for s in two["subnets"] for r in s["reservations"] if r["ip"] == "10.1.20.150")
check("a reservation published in the site's zone is one DHCP never registers; one that is not, DHCP's",
      cam5.get("ddns") is False and "ddns" not in cam1, (cam5, cam1))
bare_plan = {**TWO, "subnets": [{**SECOND, "addresses": [{**SECOND["addresses"][0], "dns": False}]}]}
by_hand = normalize_dhcp({**VT, "dns": {"dynamic_zone_var": {"A": [{"name": "cam5", "ip": "10.1.21.150"}]}},
                          "dhcp": {"interfaces": ["eth0"], "subnets": plan_to_dhcp(bare_plan)["subnets"]}})
check("any record set by hand on a reservation's address (the settings' dns:) takes it away from DHCP's updates",
      by_hand["subnets"][0]["reservations"][0].get("ddns") is False, by_hand["subnets"][0])
plain = normalize_dhcp({**VT, "dns": {}, "dhcp": {"interfaces": ["eth0"],
                                                 "subnets": plan_to_dhcp(bare_plan)["subnets"]}})
check("without one, DHCP registers the reservation as before", "ddns" not in plain["subnets"][0]["reservations"][0])
check("refused: a reservation's ddns that is not true or false",
      is_refused(lambda: normalize_dhcp({**VT, "dns": {}, "dhcp": {"interfaces": ["eth0"], "subnets": [
          {"subnet": "10.1.21.0/24", "pools": ["10.1.21.100 - 10.1.21.200"],
           "reservations": [{"mac": "aa:bb:cc:dd:ee:05", "ip": "10.1.21.150", "ddns": "no"}]}]}}),
                 "ddns is true"))
check("Kea's reverse zones leave out a reservation whose names are set by hand",
      dhcp_reverse_zones({"install_kea": True, "dhcp": {"subnets": [
          {"pools": [], "reservations": [{"ip": "10.7.7.7", "ddns": False}, {"ip": "10.7.8.8"}]}]}})
      == ["8.7.10.in-addr.arpa"])
check("every PTR fabric generates is one DHCP's key is denied in BIND",
      reverse_by_hand({"zones": {"20.1.10.in-addr.arpa": [{"label": "10"}, {"label": "150"}], "x.arpa": []}})
      == {"20.1.10.in-addr.arpa": ["10", "150"]})
text = show_plan({"sites": [{"name": "lan", "created": "1", "block": 1}], "plans": {"lan": TWO}}, "lan")
check("show: each of a VLAN's subnets under it, a second one by its name",
      "VLAN 20    iot              10.1.20.0/24" in text and "10.1.21.0/24" in text and "subnet iot-2" in text
      and "  10.1.21.150" in text, text)

print("--- the plan rendered for Kea and DNS (1.10.4.14)")
out = plan_to_dhcp(PLAN)
iot = out["subnets"][0]
check("a served subnet: its id, name, VLAN, router, dhcp ranges as pools, reservations with names and options",
      iot["id"] == 3 and iot["name"] == "iot" and iot["vlan"] == 20 and iot["routers"] == "10.1.20.1"
      and iot["pools"] == ["10.1.20.100 - 10.1.20.249"]
      and iot["reservations"] == [{"mac": "aa:bb:cc:dd:ee:01", "ip": "10.1.20.150", "hostname": "cam1",
                                   "options": [{"name": "boot-file-name", "data": "cam.bin"}]}], iot)
check("a guest VLAN's subnet is rendered guest", out["subnets"][1].get("access") == "guest")
check("a static address with DNS on is an A record", out["records"] == [{"name": "nas", "ip": "10.1.20.10"}])
off = plan_to_dhcp({**PLAN, "subnets": [{**SUB, "dhcp": False}]})
check("a subnet DHCP does not serve is not Kea's, its published names still are", off["subnets"] == []
      and off["records"] == [{"name": "nas", "ip": "10.1.20.10"}])
V = {"install_kea": True, "domain": "lan.test", "host_ip": "192.168.4.2", "ip_kea_ddns": "10.255.0.40",
     "dns": {"dynamic_zone_var": {"A": out["records"]}},
     "dhcp": {"interfaces": ["eth0"], "subnets": out["subnets"]}}
try:
    norm = normalize_dhcp(V)
    check("fabric's own DHCP checks accept the rendered plan (a reservation inside a DHCP range included)",
          norm["subnets"][0]["reservations"][0]["ip"] == "10.1.20.150")
    text = jinja_env(os.path.join(REPO, "templates")).get_template("kea/kea-dhcp4.conf.j2").render(**{**V, "dhcp": norm})
    conf = json.loads("\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("//")))
    s4 = conf["Dhcp4"]["subnet4"]
    check("Kea's configuration from the plan: ids, pools, reservations, routers",
          [s["id"] for s in s4] == [3, 4] and s4[0]["pools"] == [{"pool": "10.1.20.100 - 10.1.20.249"}]
          and s4[0]["reservations"][0]["ip-address"] == "10.1.20.150"
          and {"name": "routers", "data": "10.1.20.1"} in s4[0]["option-data"], s4)
except ValidationError as e:
    check("fabric's own DHCP checks accept the rendered plan", False, e)


print("--- an address by its IP (1.10.4.16)")
found, where = find_address(TWO, "10.1.21.150")
check("an address recorded in the plan, with its subnet", found["name"] == "cam5" and where["name"] == "iot-2")
check("refused: an address nobody recorded, and text that is no address",
      is_refused(lambda: find_address(TWO, "10.1.21.151"), "is not recorded in lan's plan")
      and is_refused(lambda: find_address(TWO, "cam5"), "is not an IPv4 address"))
check("refused: a VLAN the plan does not have, and one that is not a number",
      is_refused(lambda: find_vlan(TWO, 99), "VLAN 99 is not in lan's plan")
      and is_refused(lambda: find_vlan(TWO, "x"), "a VLAN ID, 1 to 4094"))

print("--- adding and changing a subnet (1.10.4.16, 2.1.10.18)")
V = {"fabric_subnet": "10.255.0.0/24"}
changes, sub, ranges = new_subnet(V, TWO, NETS, PLAN["vlans"][0], "10.1.22.0/24", "IoT-3")
check("a /24 added: the subnet, then the suggested split, its gateway .1 and the next Kea id",
      [c["what"] for c in changes] == ["subnet", "range", "range", "range", "range"]
      and changes[0]["do"] == "add" and sub["name"] == "iot-3" and sub["gateway"] == "10.1.22.1"
      and sub["id"] == 6 and sub["kind"] == "dhcp" and [r["kind"] for r in ranges]
      == ["gateway", "static", "dhcp", "reserved"] and changes[1]["key"] == "gateway-10.1.22.1", changes)
changes, sub, ranges = new_subnet(V, TWO, NETS, PLAN["vlans"][0], "10.1.22.0/24", "iot-3", gateway="10.1.22.254",
                                  dhcp=False, split=True)
check("a gateway elsewhere: no .1 gateway range; DHCP off makes the subnet's kind `subnet`",
      sub["kind"] == "subnet" and "gateway" not in [r["kind"] for r in ranges], ranges)
changes, sub, ranges = new_subnet(V, TWO, NETS, PLAN["vlans"][0], "10.1.22.0/24", "iot-3", split=False)
check("split off: the subnet alone", len(changes) == 1 and ranges == [])
changes, sub, _ = new_subnet(V, TWO, NETS, PLAN["vlans"][0], "192.168.4.0/24", "lan", split=False)
check("the site's LAN by its own name becomes the subnet (a set, not an add)", changes[0]["do"] == "set", changes)
check("refused: the LAN's name with another network",
      is_refused(lambda: new_subnet(V, TWO, NETS, PLAN["vlans"][0], "10.1.23.0/24", "lan"),
                 "is the site's network 192.168.4.0/24"))
check("refused: a new subnet overlapping another site's network",
      is_refused(lambda: new_subnet(V, TWO, NETS, PLAN["vlans"][0], "10.2.0.0/16", "wide"), "of site house2"))
change, after = change_subnet(V, TWO, NETS, SUB, {"notes": "cameras", "dhcp": False})
check("a subnet's settings changed: only the fields given, its kind from DHCP on or off",
      change == {"do": "set", "what": "subnet", "site": "lan", "key": "iot",
                 "fields": {"notes": "cameras", "dhcp": False, "kind": "subnet"}} and after["notes"] == "cameras",
      change)
check("refused: a gateway an address claims, naming it",
      is_refused(lambda: change_subnet(V, TWO, NETS, SUB, {"gateway": "10.1.20.10"}),
                 "already claimed: a static address (nas)"))
check("refused: a gateway in the DHCP range",
      is_refused(lambda: change_subnet(V, TWO, NETS, SUB, {"gateway": "10.1.20.120"}), "lies in the DHCP range"))

print("--- the small parts (1.10.4.6, 1.10.4.24)")
check("a 0.7 pool as typed", pool_text(" 10.1.20.100 - 10.1.20.249 ") == ("10.1.20.100", "10.1.20.249"))
check("refused: a pool that is not two addresses", is_refused(lambda: pool_text("10.1.20.100"), "two addresses")
      and is_refused(lambda: pool_text("a-b-c"), "two addresses"))
check("the option list: names and codes both ways; fabric's own (DNS servers, domain name, NTP, search)",
      CATALOGUE[66] == "tftp-server-name" and CODES["boot-file-name"] == 67
      and FABRIC_PROVIDED == {6, 15, 42, 119})
check("ScanBusy is a refusal (a ValidationError)", issubclass(ScanBusy, ValidationError))

print("--- one site's plan out of read_plan's answer on 0.8.0's directory (1.10.4.32)")
READ = {"sites": [{"name": "lan", "created": "20261023", "block": 1},
                  {"name": "lab", "created": "20261024", "block": None}],
        "plans": {"lan": {"vlans": PLAN["vlans"], "subnets": PLAN["subnets"], "networks": PLAN["networks"]}},
        "option_sets": {"domain": {"options": [{"name": "ntp-servers", "data": "10.1.0.1"}], "option_defs": [],
                                   "client_classes": []},
                        "lan": {"options": [{"code": 66, "data": "boot.lan"}], "option_defs": [],
                                "client_classes": []}},
        "options": [{"name": "ntp-servers", "data": "10.1.0.1"}]}
p = site_plan(READ, "lan")
check("the site's number, VLANs, subnets, networks, and the domain's and the site's option sets",
      p["site"] == "lan" and p["block"] == 1 and p["vlans"] == PLAN["vlans"] and len(p["subnets"]) == 2
      and p["domain_options"]["options"][0]["name"] == "ntp-servers"
      and p["site_options"]["options"] == [{"code": 66, "data": "boot.lan"}] and p["read"], p)
check("no 0.7-era editors or scan setting on it: the grants say who may change it (1.6.13.12)",
      "org_editors" not in p and "local_scan" not in p and "org_options" not in p, sorted(p))
q = site_plan({"sites": READ["sites"], "plans": {}, "option_sets": {"domain": None}}, "lab")
check("a site with nothing in its plan, before the domain's set exists",
      q["block"] is None and q["vlans"] == [] and q["subnets"] == [] and q["domain_options"] is None
      and q["site_options"] == {"options": [], "option_defs": [], "client_classes": []}, q)


print("--- the address table, find and export (1.10.4.9)")
rows = plan_rows(PLAN, [{"ip": "10.1.20.150", "mac": "aa:bb:cc:dd:ee:01", "hostname": "cam1", "state": "active",
                         "expires": "2026-10-13 10:00"},
                        {"ip": "10.1.20.177", "mac": "aa:bb:cc:dd:ee:09", "hostname": "phone", "state": "active",
                         "expires": "2026-10-13 11:00"}])
kinds = [(r["ip"], r["kind"], r["range"]) for r in rows if r["subnet"] == "10.1.20.0/24"]
check("rows: the gateway, the recorded addresses with their range, a lease nobody recorded",
      kinds == [("10.1.20.1", "gateway", "gateway"), ("10.1.20.10", "static", "static"),
                ("10.1.20.150", "reservation", "dhcp"), ("10.1.20.177", "lease", "dhcp")], kinds)
check("a lease on a recorded address fills its lease column",
      next(r for r in rows if r["ip"] == "10.1.20.150")["lease"] == "active until 2026-10-13 10:00")
read = {"sites": [{"name": "lan", "created": "1", "block": 1}], "plans": {"lan": PLAN}}
check("find by address, MAC and name", [r["name"] for r in find_in_plan(read, "10.1.20.10")] == ["nas"]
      and [r["ip"] for r in find_in_plan(read, "AA-BB-CC-DD-EE-01")] == ["10.1.20.150"]
      and [r["kind"] for r in find_in_plan(read, "iot")] == ["vlan"])
un = find_in_plan(read, "10.1.20.60")
check("find an address nobody recorded: its subnet and range", [(r["kind"], r["range"], r["subnet"]) for r in un]
      == [("unrecorded", "static", "10.1.20.0/24")], un)
check("find nothing: an empty answer", find_in_plan(read, "10.9.9.9") == [] and find_in_plan(read, "nobody") == [])
evil = copy.deepcopy(read)
evil["plans"]["lan"]["subnets"][0]["addresses"][0]["notes"] = "=HYPERLINK(\"http://x\")"
csv_text = export_plan(evil, "lan")
check("export: a header and one row per address; a formula-like cell defused",
      csv_text.splitlines()[0].startswith("site,vlan,vlan_name,subnet,ip,kind")
      and "'=HYPERLINK" in csv_text and len(csv_text.splitlines()) == 5, csv_text)
shown = show_plan(read, "lan")
check("show: the site's number, each VLAN with its subnet, ranges and addresses, the site's LAN",
      shown.startswith("site lan  number 1") and "VLAN 20" in shown and "10.1.20.10" in shown
      and "network lan  192.168.4.0/24  (lan)" in shown, shown)
check("show of a site without a number gives the suggestion",
      show_plan({"sites": [{"name": "lab", "created": "1", "block": None}], "plans": {}}, "lab").startswith(
          "site lab  number none (suggested 1)"))

print("--- one change, the way every command makes it (common/edit_plan, 1.10.4.34)")
calls = []
m_edit.check_access = lambda v, caller, action, target, container: calls.append(("check", caller, action, target)) or {
    "tier": "delegated", "by": "grant net-ops"}
m_edit.read_plan = lambda v, secrets, of, container, server=None: calls.append(("read", of)) or {**READ, "plans": {
    "lan": READ["plans"]["lan"], "lab": {"vlans": [], "subnets": [], "networks": []}}}
m_edit.read_address_plan = lambda v, secrets, container: calls.append(("org",)) or NETS
m_edit.write_plan = lambda v, secrets, changes, container, server: calls.append(("write", server, changes)) or [
    "done"]
m_edit.save_plan_cache = lambda plan: calls.append(("keep", plan["site"]))
m_edit.write_audit = lambda actor, event, detail, source: calls.append(("audit", event, detail, source))
SEC = {"ad_agent_password": "x"}
LAN = {"site_name": "lan", "dc_name": "dc-0001", "fabric_subnet": "10.255.0.0/24"}
out = add_vlan(LAN, "root", 40, "printers", no_subnet=True, secrets=SEC)
check("a change: checked first (root, networks:plan at the site), read, written at this DC, kept, audited with "
      "this DC, the site and what allowed it (1.10.4.34)",
      [c[0] for c in calls] == ["check", "read", "write", "read", "keep", "audit"]
      and calls[0] == ("check", None, "networks:plan", {"site": "lan"}) and calls[2][1] is None
      and calls[5][1] == "IPAM_VLAN_ADD" and calls[5][2].startswith("from=dc-0001 site=lan by=grant net-ops ")
      and out["site"] == "lan", calls)
calls.clear()
out = add_vlan(LAN, "nina", 41, "lab-vlan", site="lab", no_subnet=True, secrets=SEC, source="web", caller="nina")
check("another site's plan: the caller's grant checked at that site; not kept here; audited from the web",
      calls[0] == ("check", "nina", "networks:plan", {"site": "lab"}) and "keep" not in [c[0] for c in calls]
      and calls[-1][3] == "web" and "site=lab" in calls[-1][2], calls)
calls.clear()
add_subnet(LAN, "root", 20, "10.1.22.0/24", secrets=SEC)
check("a subnet's change reads every site's networks for the overlap rule", ("org",) in calls, calls)


def refuse_grant(v, caller, action, target, container):
    raise ValidationError(f"no grant gives you networks plan at {target['site']} (manual 1.6.13.12)")


calls.clear()
m_edit.check_access = refuse_grant
check("negative: no grant: refused before the plan is read, nothing written",
      is_refused(lambda: add_vlan(LAN, "pete", 42, "x", no_subnet=True, secrets=SEC, caller="pete"),
                 "no grant gives you networks plan at lan") and calls == [], calls)
m_edit.check_access = lambda v, caller, action, target, container: calls.append(("check",)) or {"by": "tier"}
RODC = {**LAN, "ad_dc_type": "rodc", "ad_join_server": "10.0.0.2"}
add_vlan(RODC, "root", 43, "ro", no_subnet=True, secrets=SEC)
check("a site with a read-only DC writes at its writable DC (2.1.6.52)",
      next(c for c in calls if c[0] == "write")[1] == "10.0.0.2", calls)
calls.clear()
check("negative: a read-only DC with no writable DC known: refused before anything is read or written",
      is_refused(lambda: add_vlan({**LAN, "ad_dc_type": "rodc"}, "root", 44, "ro2", no_subnet=True, secrets=SEC),
                 "no writable domain controller is known") and [c[0] for c in calls] == ["check"], calls)
calls.clear()
check("negative: a rule refused (a VLAN ID the site has): nothing written, nothing audited",
      is_refused(lambda: add_vlan(LAN, "root", 20, "again", no_subnet=True, secrets=SEC), "already in this site's")
      and "write" not in [c[0] for c in calls] and "audit" not in [c[0] for c in calls], calls)
check("negative: no domain yet (no agent password): refused before the DC is asked",
      is_refused(lambda: add_vlan(LAN, "root", 45, "x", no_subnet=True, secrets={}), "ad_agent_password"))


def cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = run_ipam_command({"site_name": "lan"}, argv, secrets={}, container="no-such-dc")
    return code, out.getvalue() + err.getvalue()


print("--- fabricctl ipam: refusals that need no domain (1.10.4.16)")
# covers: cli:ipam +
code, text = cli(["--help"])
check("help prints the commands", code == 0 and "fabricctl ipam vlan add" in text, text)
# covers: cli:ipam -
code, text = cli(["frobnicate"])
check("an unknown command: usage, exit 2", code == 2 and "usage:" in text, text)
code, text = cli(["scan", "iot"])
check("a command of a later area (the scans, area 6): usage, exit 2", code == 2 and "usage:" in text, text)
# covers: cli:ipam.vlan -
code, text = cli(["vlan", "add", "20"])
check("vlan add without --name: usage, exit 2", code == 2 and "usage:" in text, text)
code, text = cli(["vlan", "add", "twenty", "--name", "iot"])
check("vlan add with an ID that is not a number: refused, exit 1", code == 1 and "1 to 4094" in text, text)
code, text = cli(["vlan", "add", "20", "--name", "iot", "--dhcp", "maybe"])
check("--dhcp other than on or off: refused, exit 1", code == 1 and "--dhcp is on or off" in text, text)
code, text = cli(["vlan", "add", "20", "--name", "iot", "--colour", "red"])
check("an unknown option: refused, exit 1", code == 1 and "unknown option --colour" in text, text)
code, text = cli(["vlan", "set", "20"])
check("vlan set with nothing to change: refused before the domain is asked", code == 1
      and "nothing to change" in text, text)
# covers: cli:ipam.range -
code, text = cli(["range", "add", "20", "dhcp", "10.1.20.100"])
check("range add without its last address: usage, exit 2", code == 2 and "usage:" in text, text)
code, text = cli(["range", "remove", "20", "not-an-ip"])
check("range remove with no address: refused, exit 1", code == 1 and "not an IPv4 address" in text, text)
# covers: cli:ipam.address -
code, text = cli(["address", "add", "10.1.20.5"])
check("address add without --kind: usage, exit 2", code == 2 and "usage:" in text, text)
code, text = cli(["address", "add", "10.1.20.x", "--kind", "static"])
check("address add with no address: refused, exit 1", code == 1 and "not an IPv4 address" in text, text)
code, text = cli(["address", "set", "10.1.20.5"])
check("address set with nothing to change: refused", code == 1 and "nothing to change" in text, text)
code, text = cli(["address", "add", "10.1.20.5", "--kind", "static", "--dns", "yes"])
check("--dns other than on or off: refused", code == 1 and "--dns is on or off" in text, text)
# covers: cli:ipam.show -
code, text = cli(["show", "a", "b"])
check("show with two sites: usage, exit 2", code == 2 and "usage:" in text, text)
# covers: cli:ipam.find -
code, text = cli(["find"])
check("find without what to find: usage, exit 2", code == 2 and "usage:" in text, text)
# covers: cli:ipam.export -
code, text = cli(["export", "a", "b"])
check("export with two sites: usage, exit 2", code == 2 and "usage:" in text, text)
# covers: cli:ipam.block -
code, text = cli(["block", "1", "2"])
check("block with two numbers: usage, exit 2", code == 2 and "usage:" in text, text)
code, text = cli(["block", "7"])
check("block without the domain's agent password: refused, saying why", code == 1 and "ad_agent_password" in text,
      text)
# covers: cli:ipam.subnet -
code, text = cli(["subnet", "add", "20"])
check("subnet add without its network: usage, exit 2", code == 2 and "usage:" in text, text)
code, text = cli(["subnet", "add", "20", "10.1.21.0/24", "--dhcp", "maybe"])
check("subnet add with --dhcp other than on or off: refused, exit 1", code == 1 and "--dhcp is on or off" in text,
      text)
code, text = cli(["subnet", "set", "iot-2"])
check("subnet set with nothing to change: refused before the domain is asked", code == 1
      and "nothing to change" in text, text)
code, text = cli(["subnet", "remove"])
check("subnet remove without a subnet: usage, exit 2", code == 2 and "usage:" in text, text)
code, text = cli(["show"])
check("show without the domain's agent password: refused, saying why", code == 1 and "ad_agent_password" in text,
      text)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
