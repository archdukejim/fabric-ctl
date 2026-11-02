#!/usr/bin/env python3
"""The upgrade's move into the address plan with no container (manual 1.10.4.15, 1.10.4.24.4, 1.10.4.37; decision
2.1.10.40; the port's area 4, 1.10.4.41): a site's `dhcp.subnets` as the plan's changes (each a VLAN and its subnet,
pools as dhcp ranges, the router a gateway range, reservations kept, a second run changing nothing), the move itself
with the domain stood in for (written, the site's number given, the record kept 0600, vars.yaml losing its subnets),
a move that cannot happen yet leaving the settings untouched, a site with a read-only DC moved through its writable
DC (2.1.10.43), and the settings' options moved into the site's set once the plan holds the subnets.
Nothing calls the move until Kea renders from the plan (area 5); that round trip is area 5's test.

    python3 tests/ipam/upgrade.py
"""
import ipaddress
import json
import os
import shutil
import stat
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
W = tempfile.mkdtemp(prefix="fabric-ipam-upgrade-")
os.environ["DEPLOY_BASE_DIR"] = W                # vars.yaml, the records and the plan's copy go under the test's folder
os.makedirs(os.path.join(W, "fabric", "config"))
import fabriclib.ipam.move_subnets_to_plan as m_move  # noqa: E402
import fabriclib.ipam.options.move_options_to_plan as m_opts  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.load_vars import load_vars  # noqa: E402
from fabriclib.common.save_vars import save_vars  # noqa: E402
from fabriclib.dhcp.normalize_dhcp import normalize_dhcp  # noqa: E402
from fabriclib.ipam.plan_to_dhcp import plan_to_dhcp  # noqa: E402
from fabriclib.ipam.subnets_to_plan import subnets_to_plan  # noqa: E402

FAILED = 0
VARS = os.path.join(W, "fabric", "config", "vars.yaml")


def check(name, ok, detail=""):
    global FAILED
    FAILED += not ok
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:500]}"))


print("--- a site's subnets as the plan's changes (1.10.4.15)")
OLD = {"interfaces": ["eth0"], "subnets": [
    {"subnet": "192.168.20.0/24", "name": "iot", "vlan": 20, "id": 2, "notes": "cams", "routers": "192.168.20.1",
     "pools": ["192.168.20.100 - 192.168.20.200"], "options": [{"name": "domain-name-servers", "data": "1.1.1.1"}],
     "reservations": [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.20.20", "hostname": "cam1"}]},
    {"subnet": "192.168.4.0/24", "pools": ["192.168.4.100 - 192.168.4.199"], "access": "guest", "custom-key": 1}]}
old = normalize_dhcp({"install_kea": True, "dhcp": OLD})
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


check("nothing a running site serves changes: the plan renders the same subnets as the settings did (area 5)",
      served(again_dhcp) == served(old), (served(again_dhcp), served(old)))

print("--- the move, with the domain stood in for (1.10.4.37)")
CALLS = []
PLAN_SETS = {"domain": {"options": [], "option_defs": [{"name": "ztp-url", "code": 239, "type": "string"}],
                        "client_classes": []},
             "lan": {"options": [{"name": "domain-name", "data": "kept.lan"}], "option_defs": [], "client_classes": []}}


def read_ok(v, secrets, of=None, container="samba", server=None):
    CALLS.append(("read", of, server))
    return {"sites": [{"name": "lan", "created": "1", "block": None}, {"name": "branch", "created": "2", "block": 1}],
            "plans": {"lan": {"vlans": [], "subnets": [], "networks": []}}, "option_sets": PLAN_SETS}


def read_down(v, secrets, of=None, container="samba", server=None):
    raise ValidationError("the domain controller did not answer")


for m in (m_move, m_opts):
    m.read_plan = read_ok
    m.write_plan = lambda v, secrets, changes, container="samba", server=None: CALLS.append(
        ("write", server, changes)) or ["done"]
    m.save_plan_cache = lambda plan: CALLS.append(("keep", plan["site"]))
V = {"site_name": "lan"}
SETTINGS = {"site_name": "lan", "dhcp": {**OLD, "options": [{"name": "ntp-servers", "data": "10.1.0.1"},
                                                            {"name": "domain-name", "data": "settings.lan"}]}}
save_vars(SETTINGS, VARS)
m_move.read_plan = read_down
lines = m_move.move_subnets_to_plan(V, {})
check("negative: the DC not answering: said, the settings untouched, nothing written",
      "stay in the settings for now" in lines[0] and load_vars(VARS) == SETTINGS
      and not any(c[0] == "write" for c in CALLS), lines)
lines = m_move.move_subnets_to_plan({**V, "ad_dc_type": "rodc"}, {})
check("negative: a read-only DC with no writable DC known: said, the settings untouched, nothing read (2.1.10.43)",
      "no writable domain controller" in lines[0] and load_vars(VARS) == SETTINGS and CALLS == [], lines)
m_move.read_plan = read_ok
RODC = {**V, "ad_dc_type": "rodc", "ad_join_server": "10.0.0.2"}
m_move.save_vars = lambda data, path=None: CALLS.append(("saved",))   # this run's settings stay for the next case
lines = m_move.move_subnets_to_plan(RODC, {})
check("a site with a read-only DC: read, written and read back at its writable DC (2.1.10.43)",
      [c[2] if c[0] == "read" else c[1] for c in CALLS if c[0] in ("read", "write")] == ["10.0.0.2"] * 3
      and ("saved",) in CALLS and "moved" in lines[0], (CALLS, lines))
m_move.save_vars = save_vars
for f in os.listdir(os.path.join(W, "fabric", "config")):
    if f.startswith("ipam-upgrade-"):
        os.remove(os.path.join(W, "fabric", "config", f))
del CALLS[:]
m_move.read_plan = read_down
m_move.read_plan = read_ok
lines = m_move.move_subnets_to_plan(V, {})
writes = [c for c in CALLS if c[0] == "write"]
record = next(f for f in os.listdir(os.path.join(W, "fabric", "config")) if f.startswith("ipam-upgrade-"))
rpath = os.path.join(W, "fabric", "config", record)
check("moved: written at this DC with the site's number given (the suggestion), kept, said with the record",
      len(writes) == 1 and writes[0][1] is None
      and {"do": "set", "what": "block", "site": "lan", "fields": {"block": 2}} in writes[0][2]
      and ("keep", "lan") in CALLS and "2 DHCP subnet(s) moved" in lines[0] and "site number 2" in lines[0]
      and any("VLAN 1 now" in x for x in lines), lines)
check("the record: 0600, what moved and the subnets as they were",
      stat.S_IMODE(os.stat(rpath).st_mode) == 0o600
      and json.load(open(rpath))["subnets_as_they_were"][0]["subnet"] == "192.168.20.0/24")
after = load_vars(VARS)
check("vars.yaml loses dhcp.subnets, keeping the interfaces and the options (they move later, once the plan holds "
      "the subnets)", "subnets" not in after["dhcp"] and after["dhcp"]["interfaces"] == ["eth0"]
      and after["dhcp"]["options"] == SETTINGS["dhcp"]["options"], after)
del CALLS[:]
check("a second run: nothing to move, nothing written", m_move.move_subnets_to_plan(V, {}) == [] and CALLS == [])

print("--- the settings' options into the site's set (1.10.4.24.4)")
m_opts.plan_holds_subnets = lambda data: False
check("not while the subnets are still the settings'", m_opts.move_options_to_plan(V, {}) == [] and CALLS == [])
m_opts.plan_holds_subnets = lambda data: True
m_opts.read_plan = read_down
lines = m_opts.move_options_to_plan(V, {})
check("negative: the DC not answering: said, the settings untouched", "stay in the settings for now" in lines[0]
      and load_vars(VARS) == after, lines)
m_opts.read_plan = read_ok
del CALLS[:]
lines = m_opts.move_options_to_plan(V, {})
write = next(c for c in CALLS if c[0] == "write")
opts = write[2][0]["fields"]["options"]
check("moved into the site's set under its own key; the set's domain-name kept, the settings' listed as not carried",
      write[2][0]["key"] == "lan" and {"name": "domain-name", "data": "kept.lan"} in opts
      and {"name": "ntp-servers", "data": "10.1.0.1"} in opts
      and any("not carried" in x and "domain-name" in x for x in lines), (write, lines))
check("vars.yaml loses the options; a second run moves nothing", "options" not in load_vars(VARS)["dhcp"]
      and m_opts.move_options_to_plan(V, {}) == [])
save_vars({**after, "dhcp": {**after["dhcp"], "options": [{"name": "no-such", "data": "x"}]}}, VARS)
lines = m_opts.move_options_to_plan(V, {})
check("negative: an option the checks refuse: said, the settings untouched", "stay in the settings" in lines[0]
      and load_vars(VARS)["dhcp"]["options"] == [{"name": "no-such", "data": "x"}], lines)
save_vars({**after, "dhcp": {**after["dhcp"], "options": [{"name": "ntp-servers", "data": "10.1.0.9"}]}}, VARS)
lines = m_opts.move_options_to_plan({**V, "ad_dc_type": "rodc"}, {})
check("negative: at a read-only DC's site with no writable DC known: said, the settings untouched",
      "no writable domain controller" in lines[0], lines)

print("--- between applies, the plan this site last read (area 5, 1.10.4.14)")
from fabriclib.dhcp.client_networks import client_networks  # noqa: E402
from fabriclib.dhcp.common.turn_dhcp_on import turn_dhcp_on  # noqa: E402
from fabriclib.dhcp.dhcp_overview import dhcp_overview  # noqa: E402
from fabriclib.ipam.common.plan_cache import save_plan_cache  # noqa: E402
from fabriclib.ipam.common.plan_holds_subnets import plan_holds_subnets  # noqa: E402
from fabriclib.ipam.planned_subnets import planned_subnets  # noqa: E402

KEPT = {"site": "lan", "block": 1, "vlans": [{"id": 20, "name": "iot", "access": "guest"}],
        "subnets": [{"name": "iot", "cidr": "192.168.20.0/24", "vlan": 20, "gateway": "192.168.20.1", "dhcp": True,
                     "id": 2, "relay": "", "notes": "", "allow_overlap": "", "options": [],
                     "ranges": [{"kind": "dhcp", "first": "192.168.20.100", "last": "192.168.20.200"}],
                     "addresses": []}], "networks": [], "domain_options": None, "site_options": None}
save_plan_cache(KEPT)
NOW = {"install_kea": True, "dhcp": {"interfaces": ["eth1"]}}
check("the plan holds the subnets: the settings carry none and a copy is kept", plan_holds_subnets(NOW)
      and not plan_holds_subnets({"dhcp": {"subnets": []}}))
check("the served subnets come from the copy kept; settings that still carry theirs win",
      [s["subnet"] for s in planned_subnets(NOW)] == ["192.168.20.0/24"]
      and planned_subnets({"dhcp": {"subnets": [{"subnet": "10.9.0.0/24"}]}}) == [{"subnet": "10.9.0.0/24"}])
check("the firewall and BIND's ACLs see the plan's guest subnet between applies",
      client_networks(NOW)["guest"] == ["192.168.20.0/24"], client_networks(NOW))
ov = dhcp_overview({**NOW, "install_kea": False}, networks={})
check("the Kea tab shows the plan's subnets and says they live in the plan", ov["in_plan"] is True
      and [s["subnet"] for s in ov["subnets"]] == ["192.168.20.0/24"] and ov["has_settings"], ov)
NETS = {"eth1": [ipaddress.ip_interface("192.168.20.2/24")]}
on = turn_dhcp_on({"dhcp": {"interfaces": ["eth0"]}, "host_ip": "192.168.20.2"}, "eth1", "", "", "", NETS)
check("DHCP turned on with the plan's subnets: only the interface saved, checked against the plan",
      on == {"interfaces": ["eth1"]}, on)
save_plan_cache({**KEPT, "subnets": [{**KEPT["subnets"][0], "dhcp": False}]})
try:
    turn_dhcp_on({"dhcp": {"interfaces": ["eth0"]}}, "eth1", "", "", "", NETS)
    check("refused: DHCP on with no subnet of the plan served by DHCP", False)
except ValidationError as e:
    check("refused: DHCP on with no subnet of the plan served by DHCP, saying how to add one",
          "fabricctl ipam vlan add" in str(e), e)

shutil.rmtree(W, ignore_errors=True)
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
