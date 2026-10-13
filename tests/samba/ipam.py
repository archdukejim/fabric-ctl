"""The `samba` suite, the address manager's plan in AD (manual 1.10.4.13 to 1.10.4.16): a real DC converged by fabric
with the plan's schema; a 0.7 site's DHCP subnets moved into its plan once (recorded, the settings keeping only
their own, nothing served changed, a second run changing nothing, convergence leaving the plan alone); the plan read
at an apply and, with the DC not answering, the copy kept; and `fabricctl ipam` against the domain as the site's
agent: every command's positive case and its refusals (each changing nothing), a site above writing a nested site's
plan and the nested site refused its parent's; the site's number (`ipam block` and setup's question, 2.1.10.16), a
reservation published in DNS (2.1.10.17) and several subnets on one VLAN (`ipam subnet`, 2.1.10.18). fabric's audit
log is stood in for, and setup's answers are typed through input().
    sudo python3 tests/samba/ipam.py
"""
import builtins
import copy
import glob
import io
import json
import os
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.dirname(os.path.abspath(__file__))]
from start_dc import POLICY, start_dc  # noqa: E402
import fabriclib.ipam.common.edit_plan as m_edit  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.dhcp.normalize_dhcp import normalize_dhcp  # noqa: E402
from fabriclib.ipam.load_address_plan import load_address_plan  # noqa: E402
from fabriclib.ipam.move_subnets_to_plan import move_subnets_to_plan  # noqa: E402
from fabriclib.ipam.read_plan import read_plan  # noqa: E402
from fabriclib.ipam.run_ipam_command import run_ipam_command  # noqa: E402
from fabriclib.samba.converge_domain import converge_domain  # noqa: E402
from fabriclib.secrets.random_password import random_password  # noqa: E402
from fabriclib.setup.ask_site_number import ask_site_number  # noqa: E402

W = os.path.join(os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests"), "samba-ipam")
NET, SUBNET, IP = "ipamtest_net", "10.254.41.0/24", "10.254.41.10"
DC = "ipamtest-dc"
FAILED = 0
AUDIT = []


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:600]}"))


def plan(site="lan"):
    return read_plan(V, SECRETS, of=site, container=DC)["plans"][site]


def sub(name, site="lan"):
    return next((s for s in plan(site)["subnets"] if s["name"] == name), None)


def block(site="lan"):
    return next(s["block"] for s in read_plan(V, SECRETS, container=DC)["sites"] if s["name"] == site)


def ipam(*argv, v=None, secrets=None):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = run_ipam_command(v or V, list(argv), secrets=secrets or SECRETS, container=DC)
    return code, out.getvalue() + err.getvalue()


subprocess.run(["docker", "rm", "-f", DC], capture_output=True)
dc = start_dc(W, DC, NET, SUBNET, IP)
V, SECRETS = dc["v"], dc["secrets"]
os.environ["DEPLOY_BASE_DIR"] = W            # the kept plan, vars.yaml and the upgrade record go under the test's folder
m_edit.write_audit = lambda actor, event, detail, source: AUDIT.append((event, detail))
CONFIG = os.path.join(W, "fabric", "config")
os.makedirs(CONFIG, exist_ok=True)

print("--- the schema and an empty plan (1.10.4.13)")
first = read_plan(V, SECRETS, container=DC)
check("the plan is read as the site's agent: the site, its LAN entry, no VLAN yet, no number",
      first["plans"]["lan"]["vlans"] == [] and [n["name"] for n in first["plans"]["lan"]["networks"]] == ["lan"]
      and first["sites"][0]["name"] == "lan" and first["sites"][0]["block"] is None, first)

print("--- the upgrade from 0.7 (1.10.4.15)")
OLD = {"interfaces": ["eth0"], "lease_time": 3600, "options": [{"name": "time-offset", "data": "3600"}], "subnets": [
    {"subnet": "10.1.20.0/24", "name": "iot", "vlan": 20, "id": 5, "notes": "cameras", "routers": "10.1.20.1",
     "pools": ["10.1.20.100 - 10.1.20.200"], "options": [{"name": "domain-name-servers", "data": "10.1.20.1"}],
     "reservations": [{"mac": "aa:bb:cc:dd:ee:01", "ip": "10.1.20.20", "hostname": "cam1",
                       "options": [{"name": "boot-file-name", "data": "cam.bin"}]}]},
    {"subnet": "10.1.99.0/24", "pools": ["10.1.99.100 - 10.1.99.150"], "access": "guest"}]}
V07 = {**V, "install_kea": True, "dhcp": copy.deepcopy(OLD)}
with open(os.path.join(CONFIG, "vars.yaml"), "w") as f:
    yaml.safe_dump({"site_name": "lan", "install_kea": True, "dhcp": copy.deepcopy(OLD)}, f)
done = converge_domain(V07, os.path.join(W, "federation.yaml"), SECRETS, container=DC)
check("a 0.7 site: convergence wrote its DHCP subnets as networks, as before",
      "network iot added" in done and any("10.1.99.0/24" in d for d in done), done)
lines = move_subnets_to_plan(V07, SECRETS, container=DC)
after = plan()
check("the subnets moved into the plan: each a VLAN and its subnet, the VLAN-less one given the lowest free ID",
      [(x["id"], x["name"]) for x in after["vlans"]] == [(1, "net-10-1-99-0-24"), (20, "iot")]
      and sorted(s["name"] for s in after["subnets"]) == ["iot", "net-10-1-99-0-24"], (lines, after))
iot = next(s for s in after["subnets"] if s["name"] == "iot")
check("...keeping the Kea id, router as gateway, notes, options, the pool as a dhcp range, the reservation",
      iot["id"] == 5 and iot["gateway"] == "10.1.20.1" and iot["notes"] == "cameras" and iot["dhcp"]
      and iot["options"] == [{"name": "domain-name-servers", "data": "10.1.20.1"}]
      and [(r["kind"], r["first"], r["last"]) for r in iot["ranges"]] == [("gateway", "10.1.20.1", "10.1.20.1"),
                                                                        ("dhcp", "10.1.20.100", "10.1.20.200")]
      and iot["addresses"] == [{"ip": "10.1.20.20", "kind": "reservation", "name": "cam1", "mac": "aa:bb:cc:dd:ee:01",
                                "owner": "", "notes": "", "dns": False,
                                "options": [{"name": "boot-file-name", "data": "cam.bin"}]}], iot)
check("...the guest subnet's access on its VLAN", next(x for x in after["vlans"] if x["id"] == 1)["access"] == "guest")
check("...the site given its number (its order in the organisation)",
      read_plan(V, SECRETS, container=DC)["sites"][0]["block"] == 1, lines)
saved = yaml.safe_load(open(os.path.join(CONFIG, "vars.yaml")))
records = glob.glob(os.path.join(CONFIG, "ipam-upgrade-*.json"))
check("vars.yaml keeps the interfaces and global defaults, not the subnets; the record written (0600)",
      "subnets" not in saved["dhcp"] and saved["dhcp"]["interfaces"] == ["eth0"]
      and saved["dhcp"]["options"] == OLD["options"] and len(records) == 1
      and oct(os.stat(records[0]).st_mode & 0o777) == "0o600"
      and json.load(open(records[0]))["vlans_assigned"] == [{"subnet": "10.1.99.0/24", "vlan": 1}], (saved, records))
check("the apply said what moved and which VLAN fabric chose", any("2 DHCP subnet(s) moved" in x for x in lines)
      and any("it is VLAN 1 now" in x for x in lines), lines)
check("a second run changes nothing", move_subnets_to_plan(V07, SECRETS, container=DC) == []
      and plan()["subnets"] == after["subnets"])
final = {**V, "install_kea": True, "dhcp": copy.deepcopy(saved["dhcp"])}
said = load_address_plan(final, SECRETS, container=DC)


def served(d):
    return sorted((s["id"], s["subnet"], s["pools"], s.get("routers"), s["reservations"], s.get("options"),
                   s.get("access"), s.get("vlan")) for s in d["subnets"])


before = normalize_dhcp({**V, "install_kea": True, "dhcp": copy.deepcopy(OLD)})
now = normalize_dhcp(final)
check("nothing a running site serves changes: the apply renders the same subnets from the plan",
      served(now)[0][:7] == served(before)[0][:7] and served(now)[1] == served(before)[1], (served(now),
                                                                                           served(before), said))
done = converge_domain(final, os.path.join(W, "federation.yaml"), SECRETS, container=DC)
check("convergence leaves the plan's subnets alone and drops the networks they replaced",
      not any("iot" in d for d in done) and plan()["subnets"] == after["subnets"]
      and [n["name"] for n in plan()["networks"]] == ["lan"], done)
done = converge_domain(V, os.path.join(W, "federation.yaml"), SECRETS, container=DC)
check("convergence from settings without the plan (setup's) keeps the plan's subnets in the AD site",
      not any("removed" in d for d in done) and plan()["subnets"] == after["subnets"], done)

print("--- fabricctl ipam: VLANs and their subnets (1.10.4.16)")
# covers: cli:ipam.vlan +
code, out = ipam("vlan", "add", "30", "--name", "cams", "--purpose", "cameras", "--no-apply")
cams = next((s for s in plan()["subnets"] if s["name"] == "cams"), None)
check("vlan add: the suggested 10.<site>.30.0/24, gateway .1 and the /24's split, the next Kea id",
      code == 0 and cams and cams["cidr"] == "10.1.30.0/24" and cams["gateway"] == "10.1.30.1" and cams["id"] == 6
      and [r["kind"] for r in cams["ranges"]] == ["gateway", "static", "dhcp", "reserved"], (out, cams))
code, out = ipam("vlan", "add", "300", "--name", "lab", "--subnet", "10.1.64.0/22", "--no-split", "--no-apply")
lab = next((s for s in plan()["subnets"] if s["name"] == "lab"), None)
check("vlan add with a subnet given and --no-split: no ranges, the gateway its first host",
      code == 0 and lab and lab["ranges"] == [] and lab["gateway"] == "10.1.64.1", out)
code, out = ipam("vlan", "add", "50", "--name", "printers", "--no-subnet", "--no-apply")
check("vlan add --no-subnet: a record only", code == 0 and any(x["id"] == 50 for x in plan()["vlans"])
      and not any(s.get("vlan") == 50 for s in plan()["subnets"]), out)
held = plan()
code, out = ipam("vlan", "add", "31", "--name", "cams2", "--subnet", "10.1.30.0/25", "--no-apply")
check("refused: a subnet overlapping another (named), and nothing written", code == 1
      and "overlaps 10.1.30.0/24 (cams) of site lan" in out and plan() == held, out)
code, out = ipam("vlan", "add", "30", "--name", "other", "--no-apply")
check("refused: a VLAN ID the site has", code == 1 and "already in this site's plan (cams)" in out
      and plan() == held, out)
code, out = ipam("vlan", "add", "400", "--name", "big", "--no-apply")
check("refused: no subnet to suggest above VLAN 255", code == 1 and "no subnet to suggest" in out, out)
code, out = ipam("vlan", "set", "30", "--notes", "trunked on switch1", "--dhcp", "off", "--no-apply")
cams = next(s for s in plan()["subnets"] if s["name"] == "cams")
check("vlan set: the record's notes and the subnet no longer served", code == 0 and not cams["dhcp"]
      and next(x for x in plan()["vlans"] if x["id"] == 30)["notes"] == "trunked on switch1", out)
code, out = ipam("vlan", "set", "30", "--dhcp", "on", "--no-apply")
code2, out2 = ipam("vlan", "set", "99", "--notes", "x", "--no-apply")
check("refused: vlan set on a VLAN the site does not have", code == 0 and code2 == 1 and "VLAN 99 is not in" in out2,
      out2)
code, out = ipam("vlan", "set", "50", "--gateway", "10.1.50.1", "--no-apply")
check("refused: a subnet setting for a VLAN without a subnet", code == 1 and "has no subnet" in out, out)

print("--- the site's number (2.1.10.16)")
# covers: cli:ipam.block +
code, out = ipam("block")
check("block: the site's number", code == 0 and "site lan  number 1" in out, out)
code, out = ipam("block", "5")
check("block 5: changed, saying the plan's subnets keep their networks", code == 0 and "(was 1)" in out
      and "keep their networks" in out and block() == 5 and sub("cams")["cidr"] == "10.1.30.0/24", out)
code, out = ipam("block", "5")
check("refused: the number the site already has (nothing to change)", code == 1 and "nothing to change" in out
      and block() == 5, out)
code, out = ipam("block", "256")
check("refused: a number outside 1-255, nothing written", code == 1 and "1 to 255" in out and block() == 5, out)
code, out = ipam("block", "1")
check("block 1: back to its order in the organisation", code == 0 and block() == 1, out)

print("--- more than one subnet per VLAN (2.1.10.18)")
# covers: cli:ipam.subnet +
code, out = ipam("subnet", "add", "30", "10.1.31.0/24", "--notes", "renumbering", "--no-apply")
two = [s for s in plan()["subnets"] if s.get("vlan") == 30]
check("subnet add: a second subnet on VLAN 30, named after it, with the /24's split and a Kea id of its own",
      code == 0 and [s["name"] for s in two] == ["cams", "cams-2"] and two[1]["gateway"] == "10.1.31.1"
      and two[1]["notes"] == "renumbering" and two[1]["dhcp"] and two[1]["id"] not in
      [s["id"] for s in plan()["subnets"] if s["name"] != "cams-2"]
      and [r["kind"] for r in two[1]["ranges"]] == ["gateway", "static", "dhcp", "reserved"], (out, two))
code, out = ipam("address", "add", "10.1.31.5", "--kind", "static", "--name", "nvr", "--vlan", "30", "--no-apply")
check("address add --vlan 30: into the VLAN's subnet holding it", code == 0
      and [a["ip"] for a in sub("cams-2")["addresses"]] == ["10.1.31.5"], out)
code, out = ipam("range", "remove", "30", "10.1.31.250", "--no-apply")
check("range remove on a VLAN with two subnets: found in the second", code == 0
      and all(r["first"] != "10.1.31.250" for r in sub("cams-2")["ranges"]), out)
held = plan()
code, out = ipam("range", "add", "30", "reserved", "10.1.32.1", "10.1.32.9", "--no-apply")
check("refused: a range in none of the VLAN's subnets, naming them, nothing written", code == 1
      and "none of VLAN 30's subnets (10.1.30.0/24, 10.1.31.0/24)" in out and plan() == held, out)
code, out = ipam("vlan", "set", "30", "--dhcp", "off", "--no-apply")
check("refused: vlan set's subnet settings on a VLAN with two subnets, naming them", code == 1
      and "has 2 subnets (cams, cams-2)" in out and plan() == held, out)
code, out = ipam("subnet", "set", "cams-2", "--dhcp", "off", "--notes", "old", "--no-apply")
check("subnet set by name: no longer served, its notes changed", code == 0 and not sub("cams-2")["dhcp"]
      and sub("cams-2")["notes"] == "old", out)
code, out = ipam("subnet", "set", "10.1.31.0/24", "--dhcp", "on", "--no-apply")
check("subnet set by network: served again", code == 0 and sub("cams-2")["dhcp"], out)
held = plan()
code, out = ipam("subnet", "set", "cams-2", "--gateway", "10.1.31.150", "--no-apply")
check("refused: a gateway inside the DHCP range, nothing written", code == 1 and "lies in the DHCP range" in out
      and plan() == held, out)
code, out = ipam("subnet", "add", "30", "10.1.31.128/25", "--no-apply")
check("refused: a subnet overlapping another (named), nothing written", code == 1
      and "overlaps 10.1.31.0/24 (cams-2) of site lan" in out and plan() == held, out)
code, out = ipam("subnet", "add", "77", "10.1.77.0/24", "--no-apply")
check("refused: a subnet for a VLAN the site does not have", code == 1 and "VLAN 77 is not in" in out
      and plan() == held, out)
code, out = ipam("subnet", "add", "30", "10.1.33.0/24", "--name", "cams", "--no-apply")
check("refused: a subnet name the site uses", code == 1 and "already used" in out and plan() == held, out)
code, out = ipam("subnet", "set", "nowhere", "--notes", "x", "--no-apply")
check("refused: subnet set on a subnet the site does not have", code == 1
      and "is not a subnet of lan's plan" in out, out)
final = {**V, "install_kea": True, "dhcp": copy.deepcopy(saved["dhcp"])}
load_address_plan(final, SECRETS, container=DC)
try:
    accepted = normalize_dhcp(final) and True
except ValidationError as e:
    accepted = str(e)
check("at an apply both of VLAN 30's subnets are Kea's, and fabric's DHCP checks accept them",
      [s["subnet"] for s in final["dhcp"]["subnets"] if s.get("vlan") == 30] == ["10.1.30.0/24", "10.1.31.0/24"]
      and accepted is True, (final["dhcp"]["subnets"], accepted))
code, out = ipam("subnet", "remove", "cams-2", "--no-apply")
check("refused: removing a subnet that records addresses, nothing removed", code == 1
      and "records 1 address(es)" in out and plan() == held, out)
code, out = ipam("subnet", "remove", "cams-2", "--force", "--no-apply")
check("subnet remove --force: the subnet with its ranges and addresses; the VLAN keeps its first", code == 0
      and [s["name"] for s in plan()["subnets"] if s.get("vlan") == 30] == ["cams"], out)
code, out = ipam("subnet", "remove", "cams-2", "--no-apply")
check("refused: removing a subnet that is not there", code == 1 and "is not a subnet" in out, out)
code, out = ipam("subnet", "add", "50", "10.1.50.0/24", "--no-split", "--no-apply")
check("subnet add: a first subnet for a VLAN kept as a record, named after the VLAN", code == 0
      and sub("printers")["cidr"] == "10.1.50.0/24" and sub("printers")["ranges"] == [], out)
code, out = ipam("subnet", "remove", "printers", "--no-apply")
check("subnet remove: the VLAN stays, a record only again", code == 0 and any(x["id"] == 50 for x in plan()["vlans"])
      and not any(s.get("vlan") == 50 for s in plan()["subnets"]), out)

print("--- ranges")
# covers: cli:ipam.range +
code, out = ipam("range", "add", "300", "dhcp", "10.1.64.100", "10.1.64.200", "--no-apply")
check("range add: a dhcp range in the /22", code == 0 and [r["kind"] for r in next(
    s for s in plan()["subnets"] if s["name"] == "lab")["ranges"]] == ["dhcp"], out)
held = plan()
code, out = ipam("range", "add", "30", "static", "10.1.30.50", "10.1.30.60", "--no-apply")
check("refused: a range overlapping another, nothing written", code == 1 and "overlaps the static range" in out
      and plan() == held, out)
code, out = ipam("range", "remove", "300", "10.1.64.100", "--no-apply")
check("range remove by its first address", code == 0 and next(s for s in plan()["subnets"]
                                                              if s["name"] == "lab")["ranges"] == [], out)
code, out = ipam("range", "remove", "300", "10.1.64.100", "--no-apply")
check("refused: a range that is not there", code == 1 and "no range starting at 10.1.64.100" in out, out)

print("--- addresses")
# covers: cli:ipam.address +
code, out = ipam("address", "add", "10.1.30.10", "--kind", "static", "--name", "nas", "--owner", "office",
                 "--dns", "on", "--no-apply")
check("address add: a static address with DNS on", code == 0 and any(
    a["ip"] == "10.1.30.10" and a["dns"] for s in plan()["subnets"] for a in s["addresses"]), out)
code, out = ipam("address", "add", "10.1.30.150", "--kind", "reservation", "--mac", "aa:bb:cc:dd:ee:30", "--name",
                 "cam2", "--no-apply")
check("address add: a reservation inside the DHCP range", code == 0, out)
code, out = ipam("address", "add", "10.1.30.151", "--kind", "reservation", "--mac", "aa:bb:cc:dd:ee:31", "--name",
                 "cam3", "--dns", "on", "--no-apply")
check("address add: a reservation with DNS on (2.1.10.17)", code == 0 and any(
    a["ip"] == "10.1.30.151" and a["dns"] for a in sub("cams")["addresses"]), out)
held = plan()
code, out = ipam("address", "add", "10.1.30.152", "--kind", "reservation", "--mac", "aa:bb:cc:dd:ee:32", "--name",
                 "nas", "--dns", "on", "--no-apply")
check("refused: a reservation published under a name another address publishes, nothing written", code == 1
      and "already published" in out and plan() == held, out)
code, out = ipam("address", "add", "10.1.30.152", "--kind", "reservation", "--mac", "aa:bb:cc:dd:ee:32", "--dns",
                 "on", "--no-apply")
check("refused: a reservation with DNS on and no name, nothing written", code == 1 and "needs a name" in out
      and plan() == held, out)
code, out = ipam("address", "add", "10.1.30.251", "--kind", "static", "--no-apply")
check("a static address outside the static ranges: recorded, with a warning", code == 0
      and "warning: 10.1.30.251 is a static address outside" in out, out)
held = plan()
code, out = ipam("address", "add", "10.1.30.10", "--kind", "static", "--no-apply")
check("refused: a second claim on an address, naming the first, nothing written", code == 1
      and "already claimed: a static address (nas)" in out and plan() == held, out)
code, out = ipam("address", "add", "10.1.30.120", "--kind", "static", "--no-apply")
check("refused: a static address in the DHCP range", code == 1 and "only a reservation" in out, out)
code, out = ipam("address", "add", "10.1.30.1", "--kind", "infrastructure", "--no-apply")
check("refused: the gateway's address", code == 1 and "it is the gateway" in out, out)
code, out = ipam("address", "add", "10.9.9.9", "--kind", "static", "--no-apply")
check("refused: an address in none of the site's subnets", code == 1 and "in none of lan's subnets" in out, out)
code, out = ipam("address", "set", "10.1.30.10", "--owner", "office 2", "--no-apply")
check("address set: the owner changed", code == 0 and any(
    a["owner"] == "office 2" for s in plan()["subnets"] for a in s["addresses"]), out)
code, out = ipam("address", "set", "10.1.30.11", "--owner", "x", "--no-apply")
check("refused: address set on an address nobody recorded", code == 1 and "not recorded" in out, out)
final = {**V, "install_kea": True, "dhcp": copy.deepcopy(saved["dhcp"])}
load_address_plan(final, SECRETS, container=DC)
check("at an apply the static address with DNS on is an A record of the site's zone, the reservation Kea's",
      {"name": "nas", "ip": "10.1.30.10"} in final["dns"]["dynamic_zone_var"]["A"]
      and any(r["ip"] == "10.1.30.150" for s in final["dhcp"]["subnets"] for r in s["reservations"]),
      final.get("dns"))
try:
    accepted = normalize_dhcp(final) and True
except ValidationError as e:
    accepted = str(e)
check("...and the reservation with DNS on is both: Kea's (its name in dhcp.<domain>) and an A record of the site's "
      "zone inside the DHCP range, which fabric's DHCP checks accept (2.1.10.17)",
      {"name": "cam3", "ip": "10.1.30.151"} in final["dns"]["dynamic_zone_var"]["A"]
      and any(r["ip"] == "10.1.30.151" and r["hostname"] == "cam3" for s in final["dhcp"]["subnets"]
              for r in s["reservations"]) and accepted is True, (final.get("dns"), accepted))

print("--- show, find, export")
# covers: cli:ipam.show +
code, out = ipam("show")
check("show: the site's number, its VLANs, subnets, ranges and addresses", code == 0 and "site lan  number 1" in out
      and "VLAN 30" in out and "10.1.30.10" in out and "(no subnet)" in out, out)
# covers: cli:ipam.find +
code, out = ipam("find", "nas")
code2, out2 = ipam("find", "10.1.30.77")
check("find: a name, and an address nobody recorded with its range", code == 0 and "10.1.30.10" in out
      and code2 == 0 and "unrecorded" in out2 and "static range" in out2, (out, out2))
code, out = ipam("find", "10.200.0.1")
check("find nothing: says so, exit 1", code == 1 and "not in any site's plan" in out, out)
# covers: cli:ipam.export +
code, out = ipam("export")
check("export: CSV with a header and the recorded addresses", code == 0
      and out.startswith("site,vlan,vlan_name,subnet,ip,kind") and "10.1.30.150,reservation,dhcp,cam2" in out, out)
code, out = ipam("show", "nowhere")
check("refused: show of a site that does not exist", code == 1 and "error:" in out, out)

print("--- removing")
code, out = ipam("address", "remove", "10.1.30.251", "--no-apply")
code2, out2 = ipam("address", "remove", "10.1.30.251", "--no-apply")
check("address remove, and refused a second time", code == 0 and code2 == 1 and "not recorded" in out2, out2)
held = plan()
code, out = ipam("vlan", "remove", "30", "--no-apply")
check("refused: removing a VLAN whose subnet records addresses, nothing removed", code == 1
      and "records 3 address(es)" in out and plan() == held, out)
code, out = ipam("vlan", "remove", "30", "--force", "--no-apply")
check("vlan remove --force: the VLAN, its subnet, ranges and addresses", code == 0
      and not any(x["id"] == 30 for x in plan()["vlans"]) and not any(s["name"] == "cams" for s in plan()["subnets"]),
      out)
code, out = ipam("vlan", "remove", "30", "--no-apply")
check("refused: removing a VLAN that is not there", code == 1 and "VLAN 30 is not in" in out, out)

print("--- another site's plan (--site, 2.1.9.13)")
house = {"site": "house2", "root": False, "parent": "lan", "password_policy": POLICY, "networks": [
    {"name": "lan", "cidr": "10.2.0.0/24", "kind": "lan", "vlan": None, "notes": "", "allow_overlap": ""}],
    "root_ca_pem": open(dc["root_ca"]).read(), "id_range": "200001-300000", "groups": [], "admin_group": "admins",
    "accounts": {f"fabric-{k}-house2": random_password() for k in ("agent", "keycloak", "radius")}, "radius_gid": 610,
    "lan_profile": ""}
res = subprocess.run(["docker", "exec", "-i", DC, "python3", "/fabric/converge.py"], input=json.dumps(house),
                     capture_output=True, text=True)
check("a nested site, house2, below lan", res.returncode == 0, res.stderr[-400:])
code, out = ipam("vlan", "add", "10", "--name", "mgmt", "--subnet", "10.2.10.0/24", "--site", "house2")
check("the site above writes house2's plan, which takes effect at house2's next apply", code == 0
      and "written to house2's plan" in out and [x["id"] for x in plan("house2")["vlans"]] == [10], out)
house_v = {**V, "site_name": "house2"}
house_s = {**SECRETS, "ad_agent_password": house["accounts"]["fabric-agent-house2"]}
held = plan()
code, out = ipam("vlan", "add", "11", "--name", "x", "--subnet", "10.1.11.0/24", "--site", "lan", v=house_v,
                 secrets=house_s)
check("refused: house2 writing its parent's plan (AD's access rules), nothing written", code == 1
      and "not permitted" in out and plan() == held, out)
code, out = ipam("vlan", "add", "12", "--name", "y", "--subnet", "10.1.20.128/25", "--site", "house2")
check("refused: house2's subnet overlapping lan's", code == 1 and "of site lan" in out, out)
code, out = ipam("block", "1", "--site", "house2")
check("refused: house2 given lan's number, naming it, nothing written", code == 1 and "already lan's" in out
      and block("house2") is None, out)
code, out = ipam("block", "7", "--site", "house2")
check("the site above numbers house2", code == 0 and block("house2") == 7, out)
code, out = ipam("block", "9", "--site", "lan", v=house_v, secrets=house_s)
check("refused: house2 numbering its parent (AD's access rules), nothing written", code == 1
      and "not permitted" in out and block() == 1, out)
code, out = ipam("subnet", "add", "10", "10.2.11.0/24", "--site", "house2")
check("the site above adds a second subnet to house2's VLAN", code == 0 and "written to house2's plan" in out
      and [s["name"] for s in plan("house2")["subnets"]] == ["mgmt", "mgmt-2"], out)

print("--- the plan at an apply with the DC not answering (1.10.4.14)")
final = {**V, "install_kea": True, "dhcp": copy.deepcopy(saved["dhcp"])}
said = load_address_plan(final, SECRETS, container="no-such-dc")
check("the copy kept is rendered, and the apply says so", any("did not answer" in x for x in said)
      and any(s["subnet"] == "10.1.20.0/24" for s in final["dhcp"]["subnets"]), said)
os.remove(os.path.join(CONFIG, "address-plan.json"))
try:
    load_address_plan({**V, "install_kea": True, "dhcp": copy.deepcopy(saved["dhcp"])}, SECRETS,
                      container="no-such-dc")
    check("refused: DHCP on with no plan to be had", False)
except ValidationError as e:
    check("refused: DHCP on with no plan to be had (start the samba service)", "start the samba service" in str(e), e)

print("--- setup's question for the site's number (2.1.10.16)")
house3 = {**house, "site": "house3", "id_range": "300001-400000", "radius_gid": 611, "networks": [
    {"name": "lan", "cidr": "10.3.0.0/24", "kind": "lan", "vlan": None, "notes": "", "allow_overlap": ""}],
    "accounts": {f"fabric-{k}-house3": random_password() for k in ("agent", "keycloak", "radius")}}
res = subprocess.run(["docker", "exec", "-i", DC, "python3", "/fabric/converge.py"], input=json.dumps(house3),
                     capture_output=True, text=True)
check("a second nested site, house3, below lan, with no number", res.returncode == 0 and block("house3") is None,
      res.stderr[-400:])
h3_v = {**V, "site_name": "house3"}
h3_s = {**SECRETS, "ad_agent_password": house3["accounts"]["fabric-agent-house3"]}
lines = ask_site_number({**h3_v, "ad_dc_type": "rodc"}, h3_s, False, container=DC)
check("a site whose DC is read-only is not asked: it is numbered from the site above, nothing written",
      any("read-only" in x and "--site house3" in x for x in lines) and block("house3") is None, lines)
answers, prompts = iter(["0", "1", "three", ""]), []
real_input = builtins.input
builtins.input = lambda prompt="": (prompts.append(prompt), next(answers))[1]
said = io.StringIO()
try:
    with redirect_stdout(said):
        lines = ask_site_number(h3_v, h3_s, False, container=DC)
finally:
    builtins.input = real_input
# covers: ask:setup.site_number -
check("refused: 0, another site's number and text, each saying why and asked again",
      len(prompts) == 4 and said.getvalue().count("1 to 255") == 2 and "already lan's" in said.getvalue(),
      (prompts, said.getvalue()))
# covers: ask:setup.site_number +
check("Enter takes the suggestion, house3's order in the organisation (3), shown as the default",
      prompts[0].strip() == "Site number [3]:" and block("house3") == 3 and any("site number: 3" in x for x in lines),
      (prompts, lines))
check("asked only once: a site with a number is not asked again",
      ask_site_number(h3_v, h3_s, False, container=DC) == [])
house4 = {**house3, "site": "house4", "id_range": "400001-500000", "radius_gid": 612, "networks": [
    {"name": "lan", "cidr": "10.4.0.0/24", "kind": "lan", "vlan": None, "notes": "", "allow_overlap": ""}],
    "accounts": {f"fabric-{k}-house4": random_password() for k in ("agent", "keycloak", "radius")}}
res = subprocess.run(["docker", "exec", "-i", DC, "python3", "/fabric/converge.py"], input=json.dumps(house4),
                     capture_output=True, text=True)
h4 = ({**V, "site_name": "house4"}, {**SECRETS, "ad_agent_password": house4["accounts"]["fabric-agent-house4"]})
builtins.input = lambda prompt="": (_ for _ in ()).throw(AssertionError("asked unattended"))
try:
    lines = ask_site_number(*h4, True, container=DC)
finally:
    builtins.input = real_input
check("unattended, a site with no number takes the suggestion without asking (house4: 4); a numbered one is left "
      "alone", res.returncode == 0 and block("house4") == 4 and any("site number: 4" in x for x in lines)
      and ask_site_number(house_v, house_s, True, container=DC) == [] and block("house2") == 7, (res.stderr, lines))
check("every change audited", [e for e, _ in AUDIT].count("IPAM_VLAN_ADD") >= 4 and "IPAM_ADDRESS_ADD" in
      [e for e, _ in AUDIT], AUDIT)

subprocess.run(["docker", "rm", "-f", DC], capture_output=True)
subprocess.run(["docker", "network", "rm", NET], capture_output=True)
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
