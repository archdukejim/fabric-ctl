#!/usr/bin/env python3
"""Locations inside a site (decision 2.1.10.49, manual 1.10.4.46): a location without a DC is labelled inside the DC
site that serves it. Two VLAN 10s at one site, the names their subnets take, a VLAN named `<id>@<location>`, a move
to another location, and where the label shows (show, the address table, Kea's access, the console's view), each both
ways. Pure: the domain is stood in for (common/edit_plan's reads and write). The label in a real domain:
tests/samba/ipam.py.
    python3 tests/ipam/locations_test.py
"""
import copy
import io
import os
import sys
from contextlib import redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
import fabriclib.ipam.common.edit_plan as m_edit  # noqa: E402
import fabriclib.ipam.run_ipam_command as m_cmd  # noqa: E402
from agent.post_networks import _vid  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.ipam.add_subnet import add_subnet  # noqa: E402
from fabriclib.ipam.add_vlan import add_vlan  # noqa: E402
from fabriclib.ipam.check_vlan import check_vlan  # noqa: E402
from fabriclib.ipam.common.fields import find_vlan  # noqa: E402
from fabriclib.ipam.common.vlan_refs import parse_vlan_ref, subnet_base, vlan_label, vlan_ref  # noqa: E402
from fabriclib.ipam.networks_view import networks_view  # noqa: E402
from fabriclib.ipam.plan_rows import COLUMNS, plan_rows  # noqa: E402
from fabriclib.ipam.plan_to_dhcp import plan_to_dhcp  # noqa: E402
from fabriclib.ipam.remove_vlan import remove_vlan  # noqa: E402
from fabriclib.ipam.set_vlan import set_vlan  # noqa: E402
from fabriclib.ipam.show_plan import show_plan  # noqa: E402

m_cmd.apply_intent = __import__("functools").partial(  # the apply intent in a folder of the test's own
    __import__("fabriclib.common.apply_intent", fromlist=["x"]).apply_intent,
    os.path.join(__import__("tempfile").mkdtemp(), ".apply.intent"))
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


def subnet(name, cidr, vid, location="", gateway=""):
    return {"name": name, "cidr": cidr, "vlan": vid, "location": location, "gateway": gateway, "dhcp": True, "id": 1,
            "relay": "", "notes": "", "allow_overlap": "", "options": [], "kind": "dhcp", "ranges": [],
            "addresses": []}


PLAN = {"vlans": [{"id": 10, "location": "", "name": "iot", "purpose": "", "access": "full", "notes": ""},
                  {"id": 10, "location": "branch", "name": "iot", "purpose": "", "access": "guest", "notes": ""},
                  {"id": 20, "location": "branch", "name": "cams", "purpose": "", "access": "full", "notes": ""}],
        "subnets": [subnet("iot", "10.1.10.0/24", 10, gateway="10.1.10.1"),
                    subnet("branch-iot", "10.9.10.0/24", 10, "branch", "10.9.10.1"),
                    subnet("branch-cams", "10.9.20.0/24", 20, "branch")],
        "networks": []}
READ = {"sites": [{"name": "lan", "created": "1", "block": 1}], "plans": {"lan": PLAN},
        "option_sets": {"domain": None, "lan": {"options": [], "option_defs": [], "client_classes": []}}}
WRITES = []
m_edit.check_access = lambda v, caller, action, target, container: {"tier": "directory", "by": "tier"}
m_edit.read_plan = lambda v, secrets, of, container, server=None: copy.deepcopy(READ)
m_edit.read_address_plan = lambda v, secrets, container: [
    {"site": "lan", "name": s["name"], "cidr": s["cidr"], "kind": "dhcp", "allow_overlap": ""}
    for s in PLAN["subnets"]]
m_edit.write_plan = lambda v, secrets, changes, container, server: WRITES.append(changes) or ["done"]
m_edit.save_plan_cache = lambda plan: None
m_edit.write_audit = lambda actor, event, detail, source: None
SEC = {"ad_agent_password": "x"}
LAN = {"site_name": "lan", "dc_name": "dc-0001", "fabric_subnet": "10.255.0.0/24"}
plan = {**PLAN, "site": "lan"}

print("--- naming a VLAN (1.10.4.46.1)")
check("a VLAN is named `10`, or `10@branch` at another location (lower case)",
      parse_vlan_ref("10") == (10, "") and parse_vlan_ref("10@Branch") == (10, "branch")
      and vlan_ref({"id": 10, "location": "branch"}) == "10@branch" and vlan_ref({"id": 10, "location": ""}) == "10"
      and vlan_label({"id": 10, "location": "branch"}) == "VLAN 10 at branch")
check("refused: a VLAN named with no number, out of range, or a location that is not one DNS label",
      refused(lambda: parse_vlan_ref("x@branch"), "a VLAN ID, 1 to 4094") is True
      and refused(lambda: parse_vlan_ref("4095"), "1 to 4094") is True
      and refused(lambda: parse_vlan_ref("10@a b"), "one DNS label") is True)
vlan, subs = find_vlan(plan, "10@branch")
check("find_vlan: `10@branch` is the branch's VLAN 10 with its subnets only, `10` the DC's own",
      vlan["location"] == "branch" and [s["name"] for s in subs] == ["branch-iot"]
      and [s["name"] for s in find_vlan(plan, "10")[1]] == ["iot"], (vlan, subs))
check("refused: a VLAN at a location that holds none, saying where",
      refused(lambda: find_vlan(plan, "10@shed"), "VLAN 10 at shed is not in lan's plan") is True)

print("--- the rules, per site and location (1.10.4.46.1)")
new = check_vlan({"id": 20, "location": "", "name": "cams"}, plan)
check("VLAN 20 `cams` at the DC's own location beside the branch's VLAN 20 `cams`: accepted",
      new["id"] == 20 and new["location"] == "" and new["name"] == "cams", new)
check("refused: an ID the location already holds, naming the location and its VLAN",
      refused(lambda: check_vlan({"id": 20, "location": "branch", "name": "x"}, plan),
              "VLAN 20 at branch is already in this site's plan (cams)") is True)
check("refused: a name another VLAN at the location has",
      refused(lambda: check_vlan({"id": 30, "location": "branch", "name": "cams"}, plan),
              "already VLAN 20's at branch") is True)
check("refused: a location that is not one DNS label",
      refused(lambda: check_vlan({"id": 30, "location": "a_b", "name": "x"}, plan), "one DNS label") is True)
check("a located VLAN's subnet is named `<location>-<VLAN name>`, cut to one label",
      subnet_base({"name": "iot", "location": "branch"}) == "branch-iot"
      and subnet_base({"name": "iot", "location": ""}) == "iot"
      and len(subnet_base({"name": "n" * 60, "location": "far"})) <= 63)

print("--- the changes (1.10.4.46.2, 1.10.4.46.3)")
WRITES.clear()
out = add_vlan(LAN, "root", "30@branch", "printers", subnet="10.9.30.0/24", secrets=SEC)
vch, sch = WRITES[-1][0], WRITES[-1][1]
check("vlan add 30@branch: its entry keyed `30@branch` with the label; its subnet `branch-printers` labelled too",
      vch["key"] == "30@branch" and vch["fields"]["location"] == "branch" and sch["what"] == "subnet"
      and sch["key"] == "branch-printers" and sch["fields"]["location"] == "branch"
      and out["result"]["subnet"]["name"] == "branch-printers", WRITES[-1][:2])
WRITES.clear()
add_vlan(LAN, "root", 30, "printers", subnet="10.9.31.0/24", secrets=SEC, location="branch")
check("the location may be given apart from the ID (the console's form)", WRITES[-1][0]["key"] == "30@branch",
      WRITES[-1][:1])
WRITES.clear()
check("refused, nothing written: a located VLAN without a network (none is suggested)",
      refused(lambda: add_vlan(LAN, "root", "30@branch", "printers", secrets=SEC), "give --subnet") is True
      and not WRITES)
check("refused, nothing written: two different locations given",
      refused(lambda: add_vlan(LAN, "root", "30@branch", "x", subnet="10.9.30.0/24", location="shed", secrets=SEC),
              "give one") is True and not WRITES)
add_subnet(LAN, "root", "20@branch", "10.9.21.0/24", secrets=SEC)
check("subnet add 20@branch: the next subnet of a located VLAN is `<location>-<name>-2`, labelled",
      WRITES[-1][0]["key"] == "branch-cams-2" and WRITES[-1][0]["fields"]["location"] == "branch", WRITES[-1][:1])
WRITES.clear()
set_vlan(LAN, "root", "20@branch", to_location="shed", secrets=SEC)
move = WRITES[-1]
check("vlan set 20@branch --to-location shed: the entry renamed to 20@shed, each subnet relabelled, names kept",
      move[0]["key"] == "20@branch" and move[0]["rename"] == "20@shed" and move[0]["fields"]["location"] == "shed"
      and move[1] == {"do": "set", "what": "subnet", "site": "lan", "key": "branch-cams",
                      "fields": {"location": "shed"}}, move)
WRITES.clear()
check("refused, nothing written: a move onto an ID the new location holds (the DC's own VLAN 10)",
      refused(lambda: set_vlan(LAN, "root", "10@branch", to_location="", secrets=SEC),
              "VLAN 10 is already in this site's plan (iot)") is True and not WRITES)
set_vlan(LAN, "root", "10@branch", name="sensors", secrets=SEC)
check("a change that keeps the location moves nothing", "rename" not in WRITES[-1][0] and len(WRITES[-1]) == 1,
      WRITES[-1])
WRITES.clear()
remove_vlan(LAN, "root", "10@branch", secrets=SEC)
check("vlan remove 10@branch: the branch's VLAN and its subnet only, the DC's own VLAN 10 kept",
      [(c["what"], c["key"]) for c in WRITES[-1]] == [("subnet", "branch-iot"), ("vlan", "10@branch")], WRITES[-1])

print("--- where it shows (1.10.4.46.4)")
text = show_plan(READ, "lan")
check("ipam show: the DC's own VLANs first, then each location under `at <location>`",
      text.index("VLAN 10    iot") < text.index("at branch") < text.index("10.9.10.0/24"), text)
rows = plan_rows(plan)
check("the address table has a location column, and each row its subnet's",
      "location" in COLUMNS and {r["subnet"]: r["location"] for r in rows}.get("10.9.10.0/24") == "branch"
      and {r["subnet"]: r["location"] for r in rows}.get("10.1.10.0/24") == "", rows[:2])
dhcp = plan_to_dhcp(plan)
access = {s["subnet"]: s.get("access", "full") for s in dhcp["subnets"]}
check("Kea: each subnet takes its own VLAN's access (the branch's VLAN 10 guest, the DC's own VLAN 10 full)",
      access == {"10.1.10.0/24": "full", "10.9.10.0/24": "guest", "10.9.20.0/24": "full"}, access)
view = networks_view({}, READ, "lan", [{"name": "lan", "own": False}])
refs = [(x["ref"], x["label"], [s["name"] for s in x["subnets"]]) for x in view["vlans"]]
check("the console's view names each VLAN by its ref and label, with its own subnets only",
      refs == [("10", "VLAN 10", ["iot"]), ("10@branch", "VLAN 10 at branch", ["branch-iot"]),
               ("20@branch", "VLAN 20 at branch", ["branch-cams"])], refs)

print("--- the agent's routes and the command (1.10.4.46.5)")
check("the agent takes a VLAN as `10` or `10@branch`", _vid("10") == "10" and _vid(" 10@Branch ") == "10@branch")
check("refused: a VLAN in a route that is not one", refused(lambda: _vid("ten"), "a VLAN ID") is True)
WRITES.clear()
buf = io.StringIO()
with redirect_stdout(buf):
    code = m_cmd.run_ipam_command(LAN, ["vlan", "set", "20@branch", "--to-location", "none", "--no-apply"],
                                  secrets=SEC)
check("fabricctl ipam vlan set 20@branch --to-location none: back to the DC's own location, said",
      code == 0 and WRITES[-1][0]["rename"] == "20" and "VLAN 20 changed" in buf.getvalue(),
      (code, buf.getvalue(), WRITES[-1:]))
print("FAILED" if FAILED else "all passed", FAILED)
sys.exit(1 if FAILED else 0)
