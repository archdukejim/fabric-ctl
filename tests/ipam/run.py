#!/usr/bin/env python3
"""The `ipam` suite (manual 1.10.4.17): the address manager's model with no container: its rules (one claim per
address, ranges inside their subnet and apart, only reservations in a dhcp range, overlaps refused unless a reason is
given), its suggestions, the site's number, several subnets on one VLAN and a reservation published in DNS
(2.1.10.16-18), a plan rendered for Kea (and checked by fabric's normalize_dhcp and the Kea template), the
upgrade's changes from 0.7's subnets, the address table, find and export, and `fabricctl ipam`'s refusals that need
no domain. The plan in a real domain: tests/samba/ipam.py.

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
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.dhcp.normalize_dhcp import normalize_dhcp  # noqa: E402
from fabriclib.ipam.check_address import check_address  # noqa: E402
from fabriclib.ipam.check_block import check_block  # noqa: E402
from fabriclib.ipam.check_range import check_range  # noqa: E402
from fabriclib.ipam.check_subnet import check_subnet  # noqa: E402
from fabriclib.ipam.check_vlan import check_vlan  # noqa: E402
from fabriclib.ipam.common.fields import find_subnet, find_vlan, subnet_holding  # noqa: E402
from fabriclib.ipam.export_plan import export_plan  # noqa: E402
from fabriclib.ipam.find_in_plan import find_in_plan  # noqa: E402
from fabriclib.ipam.plan_rows import plan_rows  # noqa: E402
from fabriclib.ipam.plan_to_dhcp import plan_to_dhcp  # noqa: E402
from fabriclib.ipam.run_ipam_command import run_ipam_command  # noqa: E402
from fabriclib.ipam.show_plan import show_plan  # noqa: E402
from fabriclib.ipam.subnets_to_plan import subnets_to_plan  # noqa: E402
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

print("--- the upgrade from 0.7 (1.10.4.15)")
old = normalize_dhcp({"install_kea": True, "dhcp": {"interfaces": ["eth0"], "subnets": [
    {"subnet": "192.168.20.0/24", "name": "iot", "vlan": 20, "id": 2, "notes": "cams", "routers": "192.168.20.1",
     "pools": ["192.168.20.100 - 192.168.20.200"], "options": [{"name": "domain-name-servers", "data": "1.1.1.1"}],
     "reservations": [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.20.20", "hostname": "cam1"}]},
    {"subnet": "192.168.4.0/24", "pools": ["192.168.4.100 - 192.168.4.199"], "access": "guest", "custom-key": 1}]}})
moved = subnets_to_plan(old["subnets"], {"vlans": [{"id": 1, "name": "x"}], "subnets": [],
                                          "networks": [{"name": "iot", "cidr": "192.168.20.0/24"}]}, "lan")
kinds = [(c["do"], c["what"], c["key"]) for c in moved["changes"]]
check("each subnet a VLAN and its subnet; pools dhcp ranges; the router a gateway range; reservations kept",
      kinds == [("add", "vlan", "20"), ("set", "subnet", "iot"), ("add", "range", "dhcp-192.168.20.100"),
                ("add", "range", "gateway-192.168.20.1"), ("add", "address", "192.168.20.20"),
                ("add", "vlan", "2"), ("add", "subnet", "net-192-168-4-0-24"),
                ("add", "range", "dhcp-192.168.4.100")], kinds)
sub_fields = moved["changes"][1]["fields"]
check("the subnet keeps its Kea id, notes, options; the one convergence wrote is converted in place",
      sub_fields["id"] == 2 and sub_fields["notes"] == "cams" and sub_fields["gateway"] == "192.168.20.1"
      and sub_fields["options"] == [{"name": "domain-name-servers", "data": "1.1.1.1"}], sub_fields)
check("a subnet without a VLAN gets the lowest free ID, listed; without a name its network's; access kept",
      moved["assigned"] == [{"subnet": "192.168.4.0/24", "vlan": 2}]
      and moved["changes"][5]["fields"]["access"] == "guest", moved["assigned"])
check("a key the plan does not hold is listed as not carried", moved["not_carried"] == ["192.168.4.0/24: custom-key"])
again = subnets_to_plan(old["subnets"], {"vlans": [{"id": 20, "name": "iot"}, {"id": 2, "name": "net"}],
                                          "subnets": [{"name": "iot", "cidr": "192.168.20.0/24"},
                                                      {"name": "net-192-168-4-0-24", "cidr": "192.168.4.0/24"}],
                                          "networks": []}, "lan")
check("a second run changes nothing (idempotent)", again["changes"] == [] and len(again["kept"]) == 2, again)
plan_back = {"vlans": [{"id": 20, "name": "iot", "access": "full"}, {"id": 2, "name": "x", "access": "guest"}],
             "subnets": []}
for c in moved["changes"]:
    f = c["fields"]
    if c["what"] == "subnet":
        plan_back["subnets"].append({**f, "name": c["key"], "ranges": [], "addresses": []})
    elif c["what"] == "range":
        plan_back["subnets"][-1]["ranges"].append(f)
    elif c["what"] == "address":
        plan_back["subnets"][-1]["addresses"].append(f)
again_dhcp = normalize_dhcp({"install_kea": True, "dhcp": {"interfaces": ["eth0"],
                                                            "subnets": plan_to_dhcp(plan_back)["subnets"]}})


def served(d):
    return [(s["id"], s["subnet"], s["pools"], s.get("routers"), s["reservations"], s.get("options"),
             s.get("access")) for s in d["subnets"]]


check("nothing a running site serves changes: the plan renders the same subnets as the settings did",
      served(again_dhcp) == served(old), (served(again_dhcp), served(old)))

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
code, text = cli(["subnet", "rename", "iot-2"])
check("an unknown subnet command: usage, exit 2", code == 2 and "usage:" in text, text)
code, text = cli(["show"])
check("without the domain's agent password: refused, saying why", code == 1 and "ad_agent_password" in text, text)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
