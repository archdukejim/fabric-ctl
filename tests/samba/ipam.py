"""The `samba` suite, the address manager's plan on 0.8.0's directory (manual 1.10.4.16, 1.10.4.33, 1.10.4.34): a real
DC converged by fabric, and `fabricctl ipam` against the domain as the DC's agent account, run as root (the Enterprise
Admin's): every command's positive case and its refusals, each changing nothing; the site's number; several subnets
on one VLAN; show, find and export; another site's plan written with --site; and a delegated person writing through
a grant's networks rights at one site, refused at another and refused with none; the DHCP options and netboot
(the domain's set, the site's, a subnet's; a delegated person's options right at one site, refused for the domain's
set); the 0.7 subnet commands' aliases (add-subnet, set-subnet, unreserve); the plan read at an apply (area 5:
Kea's subnets and the site's A records from it, the copy kept rendered when the DC does not answer, refused with
none). fabric's audit log is stood in for.
    sudo python3 tests/samba/ipam.py          (FABRIC_TEST_KEEP=1 leaves the DC for a look)
"""
import io
import json
import os
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.dirname(os.path.abspath(__file__))]
from start_dc import POLICY, start_dc  # noqa: E402
import fabriclib.grants.add_grant as m_add_grant  # noqa: E402
import fabriclib.ipam.common.edit_options as m_edit_opt  # noqa: E402
import fabriclib.ipam.common.edit_plan as m_edit  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.dhcp.normalize_dhcp import normalize_dhcp  # noqa: E402
from fabriclib.directory.run_op import run_op  # noqa: E402
from fabriclib.ipam.add_address import add_address  # noqa: E402
from fabriclib.ipam.add_dhcp_subnet import add_dhcp_subnet  # noqa: E402
from fabriclib.ipam.add_vlan import add_vlan  # noqa: E402
from fabriclib.ipam.common.plan_cache import plan_cache_path  # noqa: E402
from fabriclib.ipam.load_address_plan import load_address_plan  # noqa: E402
from fabriclib.ipam.options.set_plan_option import set_plan_option  # noqa: E402
from fabriclib.ipam.read_plan import read_plan  # noqa: E402
from fabriclib.ipam.remove_reservation_mac import remove_reservation_mac  # noqa: E402
from fabriclib.ipam.remove_vlan import remove_vlan  # noqa: E402
from fabriclib.ipam.run_ipam_command import run_ipam_command  # noqa: E402
from fabriclib.ipam.set_dhcp_subnet import set_dhcp_subnet  # noqa: E402
from fabriclib.secrets.random_password import random_password  # noqa: E402
import fabriclib.common.apply_intent as m_intent  # noqa: E402
import fabriclib.ipam.run_ipam_command as m_run  # noqa: E402

# the apply intent (2.1.10.45) in a folder of the test's own, never the checkout's config/.apply.intent
m_run.apply_intent = __import__("functools").partial(
    m_intent.apply_intent, os.path.join(__import__("tempfile").mkdtemp(), ".apply.intent"))

W =os.path.join(os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests"), "samba-ipam")
NET, SUBNET, IP = "ipamtest_net", "10.254.41.0/24", "10.254.41.10"
DC = "samba"            # the product's own name: fabric's functions use it
FAILED = 0
AUDIT = []


def check(name, cond, detail=""):
    """Purpose: record one check and print it.
    Inputs:  name — what is checked; cond — bool; detail — shown when it fails.
    Returns: None.
    Fails:   never.
    Feeds:   this script."""
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:600]}"), flush=True)


def plan(site="lan"):
    """Purpose: a site's plan as the domain holds it now.
    Inputs:  site — str.
    Returns: read_plan's plan of the site.
    Fails:   ValidationError from read_plan.
    Feeds:   this script."""
    return read_plan(V, SECRETS, of=site, container=DC)["plans"][site]


def sub(name, site="lan"):
    """Purpose: one subnet of a site's plan by name.
    Inputs:  name — the subnet's name; site — str.
    Returns: dict, or None.
    Fails:   ValidationError from read_plan.
    Feeds:   this script."""
    return next((s for s in plan(site)["subnets"] if s["name"] == name), None)


def block(site="lan"):
    """Purpose: a site's number.
    Inputs:  site — str.
    Returns: int or None.
    Fails:   ValidationError from read_plan.
    Feeds:   this script."""
    return next(s["block"] for s in read_plan(V, SECRETS, container=DC)["sites"] if s["name"] == site)


def ipam(*argv, v=None):
    """Purpose: `fabricctl ipam` as root runs it.
    Inputs:  argv — its arguments; v — vars (default this DC's).
    Returns: (exit status, what it printed).
    Fails:   never (refusals are its exit status).
    Feeds:   this script."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = run_ipam_command(v or V, list(argv), secrets=SECRETS, container=DC)
    return code, out.getvalue() + err.getvalue()


if subprocess.run(["docker", "inspect", "samba"], capture_output=True).returncode == 0 and \
        not subprocess.run(["docker", "inspect", "-f", "{{.Config.Image}}", "samba"], capture_output=True,
                           text=True).stdout.strip().endswith(":test"):
    sys.exit("a container named samba that is not a test DC runs here: not touching it")
dc = start_dc(W, DC, NET, SUBNET, IP)
V, SECRETS = dc["v"], dc["secrets"]
os.environ["DEPLOY_BASE_DIR"] = W            # the kept plan goes under the test's folder
m_edit.write_audit = m_edit_opt.write_audit = lambda actor, event, detail, source: AUDIT.append(
    (event, detail, source))
m_add_grant.write_audit = lambda *a, **k: None

print("--- an empty plan (1.10.4.32)")
first = read_plan(V, SECRETS, container=DC)
check("the plan read as the DC's agent: the site's record, its LAN entry, no VLAN yet, no number",
      [s["name"] for s in first["sites"]] == ["lan"] and first["sites"][0]["block"] is None
      and first["plans"]["lan"]["vlans"] == [] and [n["name"] for n in first["plans"]["lan"]["networks"]] == ["lan"],
      first)

print("--- VLANs and their subnets (1.10.4.16)")
# covers: cli:ipam.vlan +
code, out = ipam("vlan", "add", "30", "--name", "cams", "--purpose", "cameras", "--no-apply")
cams = sub("cams")
check("vlan add: the site given its number, the suggested 10.1.30.0/24, gateway .1 and the /24's split",
      code == 0 and "given the number 1" in out and block() == 1 and cams and cams["cidr"] == "10.1.30.0/24"
      and cams["gateway"] == "10.1.30.1" and [r["kind"] for r in cams["ranges"]]
      == ["gateway", "static", "dhcp", "reserved"] and AUDIT[-1][0] == "IPAM_VLAN_ADD", (out, cams))
check("the kept copy of this site's plan is written (0600)",
      oct(os.stat(os.path.join(W, "fabric", "config", "address-plan.json")).st_mode & 0o777) == "0o600")
code, out = ipam("vlan", "add", "300", "--name", "lab", "--subnet", "10.1.64.0/22", "--no-split", "--no-apply")
check("vlan add with a subnet given and --no-split: no ranges, the gateway its first host",
      code == 0 and sub("lab")["ranges"] == [] and sub("lab")["gateway"] == "10.1.64.1", out)
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
check("vlan set: the record's notes and the subnet no longer served", code == 0 and not sub("cams")["dhcp"]
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
check("refused: the number the site already has", code == 1 and "nothing to change" in out and block() == 5, out)
code, out = ipam("block", "256")
check("refused: a number outside 1-255, nothing written", code == 1 and "1 to 255" in out and block() == 5, out)
code, out = ipam("block", "1")
check("block 1: back to its order in the domain", code == 0 and block() == 1, out)

print("--- more than one subnet per VLAN (2.1.10.18)")
# covers: cli:ipam.subnet +
code, out = ipam("subnet", "add", "30", "10.1.31.0/24", "--notes", "renumbering", "--no-apply")
two = [s for s in plan()["subnets"] if s.get("vlan") == 30]
check("subnet add: a second subnet on VLAN 30, named after it, its split and a Kea id of its own",
      code == 0 and [s["name"] for s in two] == ["cams", "cams-2"] and two[1]["gateway"] == "10.1.31.1"
      and two[1]["notes"] == "renumbering" and two[1]["id"] != two[0]["id"], (out, two))
code, out = ipam("address", "add", "10.1.31.5", "--kind", "static", "--name", "nvr", "--vlan", "30", "--no-apply")
check("address add --vlan 30: into the VLAN's subnet holding it", code == 0
      and [a["ip"] for a in sub("cams-2")["addresses"]] == ["10.1.31.5"], out)
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
held = plan()
code, out = ipam("subnet", "set", "cams-2", "--gateway", "10.1.31.150", "--no-apply")
check("refused: a gateway inside the DHCP range, nothing written", code == 1 and "lies in the DHCP range" in out
      and plan() == held, out)
code, out = ipam("subnet", "remove", "cams-2", "--no-apply")
check("refused: removing a subnet that records addresses", code == 1 and "records 1 address(es)" in out
      and plan() == held, out)
code, out = ipam("subnet", "remove", "cams-2", "--force", "--no-apply")
check("subnet remove --force: the subnet with its ranges and addresses (a tree delete)", code == 0
      and [s["name"] for s in plan()["subnets"] if s.get("vlan") == 30] == ["cams"], out)

print("--- ranges")
# covers: cli:ipam.range +
code, out = ipam("range", "add", "300", "dhcp", "10.1.64.100", "10.1.64.200", "--no-apply")
check("range add: a dhcp range in the /22", code == 0 and [r["kind"] for r in sub("lab")["ranges"]] == ["dhcp"], out)
held = plan()
code, out = ipam("range", "add", "30", "static", "10.1.30.50", "10.1.30.60", "--no-apply")
check("refused: a range overlapping another, nothing written", code == 1 and "overlaps the static range" in out
      and plan() == held, out)
code, out = ipam("range", "remove", "300", "10.1.64.100", "--no-apply")
check("range remove by its first address", code == 0 and sub("lab")["ranges"] == [], out)

print("--- addresses")
# covers: cli:ipam.address +
code, out = ipam("address", "add", "10.1.30.10", "--kind", "static", "--name", "nas", "--owner", "office",
                 "--dns", "on", "--no-apply")
check("address add: a static address with DNS on", code == 0 and any(
    a["ip"] == "10.1.30.10" and a["dns"] for a in sub("cams")["addresses"]), out)
code, out = ipam("address", "add", "10.1.30.150", "--kind", "reservation", "--mac", "aa:bb:cc:dd:ee:30", "--name",
                 "cam2", "--no-apply")
check("address add: a reservation inside the DHCP range", code == 0, out)
held = plan()
code, out = ipam("address", "add", "10.1.30.10", "--kind", "static", "--no-apply")
check("refused: a second claim, naming the first, nothing written", code == 1
      and "already claimed: a static address (nas)" in out and plan() == held, out)
code, out = ipam("address", "set", "10.1.30.10", "--owner", "office 2", "--no-apply")
check("address set: the owner changed", code == 0 and any(
    a["owner"] == "office 2" for a in sub("cams")["addresses"]), out)

print("--- the plan at an apply: Kea and DNS from it (area 5, 1.10.4.14)")
final = {**V, "install_kea": True, "dhcp": {"interfaces": ["eth0"]}}
said = load_address_plan(final, SECRETS, container=DC)
check("at an apply the static address with DNS on is an A record of the site's zone, the reservation Kea's, the "
      "plan kept for the DC not answering", {"name": "nas", "ip": "10.1.30.10"} in final["dns"]["dynamic_zone_var"]["A"]
      and any(r["ip"] == "10.1.30.150" for s in final["dhcp"]["subnets"] for r in s["reservations"])
      and os.path.exists(plan_cache_path()), (said, final.get("dns")))
try:
    accepted = bool(normalize_dhcp(final))
except ValidationError as e:
    accepted = str(e)
check("...which fabric's DHCP checks accept", accepted is True, accepted)
final = {**V, "install_kea": True, "dhcp": {"interfaces": ["eth0"]}}
said = load_address_plan(final, SECRETS, container="no-such-dc")
check("the DC not answering: the copy kept is rendered, and the apply says so", any("did not answer" in x for x in said)
      and any(r["ip"] == "10.1.30.150" for s in final["dhcp"]["subnets"] for r in s["reservations"]), said)
os.remove(plan_cache_path())
try:
    load_address_plan({**V, "install_kea": True, "dhcp": {"interfaces": ["eth0"]}}, SECRETS, container="no-such-dc")
    check("refused: DHCP on with no plan to be had", False)
except ValidationError as e:
    check("refused: DHCP on with no plan to be had (start the samba service)", "start the samba service" in str(e), e)

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
# covers: cli:ipam.export +
code, out = ipam("export")
check("export: CSV with a header and the recorded addresses", code == 0
      and out.startswith("site,vlan,vlan_name,subnet,ip,kind") and "10.1.30.150,reservation,dhcp,cam2" in out, out)
code, out = ipam("show", "nowhere")
check("refused: show of a site the domain does not have", code == 1 and "no such site" in out, out)

print("--- another site's plan, and the grants' networks rights (1.10.4.34, 1.6.13.12)")
lab = {"site": "branch", "dc": "dc-0002", "dc_type": "writable", "root": False, "parent": "lan",
       "password_policy": POLICY, "networks": [], "root_ca_pem": open(dc["root_ca"]).read(), "groups": [],
       "accounts": {f"fabric-{k}-dc-0002": random_password() for k in ("agent", "keycloak", "radius")},
       "radius_gid": 610}
res = subprocess.run(["docker", "exec", "-i", DC, "python3", "/fabric/converge.py"], input=json.dumps(lab),
                     capture_output=True, text=True)
check("a second site, branch, converged: its record made", res.returncode == 0
      and "branch" in [s["name"] for s in read_plan(V, SECRETS, container=DC)["sites"]], res.stderr[-400:])
code, out = ipam("vlan", "add", "10", "--name", "mgmt", "--subnet", "10.2.10.0/24", "--site", "branch")
check("root writes branch's plan with --site; it takes effect at branch", code == 0
      and "written to branch's plan" in out and [x["id"] for x in plan("branch")["vlans"]] == [10], out)
code, out = ipam("block", "1", "--site", "branch")
check("refused: branch given lan's number, naming it", code == 1 and "already lan's" in out
      and block("branch") is None, out)
code, out = ipam("vlan", "add", "12", "--name", "y", "--subnet", "10.1.30.128/25", "--site", "branch")
check("refused: branch's subnet overlapping lan's, across sites", code == 1 and "of site lan" in out, out)
run_op(V, SECRETS, "create_person", {"uid": "nina", "first": "Nina", "last": "Test", "email": "nina@lan.test",
                                     "password": "Ot-" + random_password(20), "gid": 5000, "home_base": "/home",
                                     "shell": "/bin/bash"}, DC)
run_op(V, SECRETS, "add_group_member", {"group": "network-admins", "uid": "nina"}, DC)
for args in (["add", "branch-ops", "--groupou=OU=groups"], ["addmembers", "branch-ops", "nina"],
             ["removemembers", "network-admins", "nina"]):     # samba-tool needs the DC's smb.conf named
    subprocess.run(["docker", "exec", DC, "samba-tool", "group", *args, "-s", "/data/etc/smb.conf"], check=True,
                   capture_output=True)
m_add_grant.add_grant(V, "test", "branch-net", {"who": ["branch-ops"], "networks": ["plan"], "sites": ["branch"]},
                      container=DC)


def as_nina(site):
    """Purpose: a VLAN added by nina, a delegated person, through edit_plan's grant check.
    Inputs:  site — whose plan.
    Returns: "ok", or why it was refused.
    Fails:   never.
    Feeds:   this script."""
    try:
        add_vlan(V, "nina", 70, "nina", site=site, no_subnet=True, secrets=SECRETS, container=DC, source="web",
                 caller="nina")
        return "ok"
    except ValidationError as e:
        return str(e)


held = plan()
check("nina (branch-ops) writes branch's plan through the grant branch-net", as_nina("branch") == "ok"
      and any(x["id"] == 70 for x in plan("branch")["vlans"]) and AUDIT[-1][2] == "web")
got = as_nina("lan")
check("negative: nina refused at lan, which her grant does not reach; nothing written",
      "no grant gives you networks plan at lan" in got and plan() == held, got)
try:
    add_vlan(V, "pete", 71, "pete", site="branch", no_subnet=True, secrets=SECRETS, container=DC, caller="pete")
    got = "ok"
except ValidationError as e:
    got = str(e)
check("negative: someone who is not a person of the domain is refused", "not a person of the domain" in got, got)

print("--- the DHCP options and netboot (1.10.4.24 to 1.10.4.26; the port's area 4)")


def sets():
    """Purpose: the option sets as the domain holds them now.
    Inputs:  none.
    Returns: read_plan's option_sets ({"domain": set, <site>: set}).
    Fails:   ValidationError from read_plan.
    Feeds:   this script."""
    return read_plan(V, SECRETS, container=DC)["option_sets"]


def has(one, name, data):
    """Purpose: whether an option set holds an option with that data.
    Inputs:  one — an option set or None; name — the option's name; data — its value.
    Returns: bool.
    Fails:   never.
    Feeds:   this script."""
    return {"name": name, "data": data} in [{"name": o.get("name"), "data": o.get("data")}
                                            for o in (one or {}).get("options") or []]


# covers: cli:ipam.option +
code, out = ipam("option", "set", "domain", "ntp-servers", "10.1.0.1", "--no-apply")
check("option set domain: written to the domain's set (CN=dhcp-options)", code == 0
      and has(sets()["domain"], "ntp-servers", "10.1.0.1"), out)
code, out = ipam("option", "set", "org", "ntp-servers", "10.1.0.2", "--no-apply")
check("0.8's `org` is the domain's set: the option replaced there", code == 0
      and has(sets()["domain"], "ntp-servers", "10.1.0.2") and not has(sets()["domain"], "ntp-servers", "10.1.0.1"),
      out)
code, out = ipam("option", "set", "site", "domain-name", "lan.test", "--no-apply")
check("option set site: on the site's record", code == 0 and has(sets()["lan"], "domain-name", "lan.test"), out)
code, out = ipam("option", "define", "site", "ztp-url", "239", "string", "--no-apply")
code2, out2 = ipam("option", "set", "site", "ztp-url", "http://ztp/cfg", "--no-apply")
check("option define, then a custom option by its name", code == 0 and code2 == 0
      and has(sets()["lan"], "ztp-url", "http://ztp/cfg"), out + out2)
code, out = ipam("option", "set", "subnet", "lab", "domain-name-servers", "10.1.64.1", "--no-apply")
check("option set subnet: on the subnet's entry", code == 0 and any(
    o.get("name") == "domain-name-servers" for o in sub("lab")["options"]), out)
code, out = ipam("option", "show", "subnet", "lab")
check("option show subnet: its options with their sources", code == 0 and "domain-name-servers" in out
      and "subnet lab" in out and "ntp-servers" in out, out)
code, out = ipam("option", "show")
check("option show: the domain's set and the site's", code == 0 and out.startswith("the domain")
      and "site lan" in out, out)
code, out = ipam("option", "remove", "site", "ztp-url", "--no-apply")
code2, out2 = ipam("option", "undefine", "site", "ztp-url", "--no-apply")
check("option remove, then undefine", code == 0 and code2 == 0 and not has(sets()["lan"], "ztp-url", "http://ztp/cfg")
      and not sets()["lan"].get("option_defs"), out + out2)
# covers: cli:ipam.class +
code, out = ipam("class", "add", "site", "uefi", "--test", "option[93].hex == 0x0007", "--boot-file", "ipxe.efi",
                 "--no-apply")
check("class add: on the site's set", code == 0 and [c["name"] for c in sets()["lan"]["client_classes"]] == ["uefi"],
      out)
code, out = ipam("class", "remove", "site", "uefi", "--no-apply")
check("class remove", code == 0 and not sets()["lan"]["client_classes"], out)
# covers: cli:ipam.netboot +
code, out = ipam("netboot", "on", "300", "--server", "10.1.64.5", "--bios", "undionly.kpxe", "--ipxe",
                 "http://boot.lan/boot.ipxe", "--no-apply")
check("netboot on a VLAN: each of its subnets carries the preset", code == 0
      and (sub("lab").get("netboot") or {}).get("bios") == "undionly.kpxe", out)
code, out = ipam("netboot", "show", "300")
check("netboot show", code == 0 and "undionly.kpxe" in out, out)
code, out = ipam("netboot", "off", "lab", "--no-apply")
check("netboot off: the preset gone, the subnet's options kept", code == 0 and not sub("lab").get("netboot")
      and any(o.get("name") == "domain-name-servers" for o in sub("lab")["options"]), out)
held = sets()
code, out = ipam("netboot", "on", "10.1.30.10", "--server", "10.1.30.5", "--bios", "x.0", "--no-apply")
check("negative: netboot on a static address (only a reservation can netboot): nothing written", code == 1
      and "only a reservation can netboot" in out and sets() == held, out)
code, out = ipam("option", "set", "class", "nope", "domain-name", "x", "--no-apply")
check("negative: an option on a class that is not there: nothing written", code == 1 and "no client class" in out
      and sets() == held, out)
m_add_grant.add_grant(V, "test", "branch-opt", {"who": ["branch-ops"], "networks": ["options"], "sites": ["branch"]},
                      container=DC)


def nina_option(scope, site):
    """Purpose: an option set by nina, a delegated person, through edit_options' grant check.
    Inputs:  scope — "site" or "domain"; site — whose plan.
    Returns: "ok", or why it was refused.
    Fails:   never.
    Feeds:   this script."""
    try:
        set_plan_option(V, "nina", scope, "", "ntp-servers", "10.2.0.1", site=site, secrets=SECRETS, container=DC,
                        source="web", caller="nina")
        return "ok"
    except ValidationError as e:
        return str(e)


check("nina (branch-ops) sets branch's options through the grant branch-opt", nina_option("site", "branch") == "ok"
      and has(sets()["branch"], "ntp-servers", "10.2.0.1") and "site=branch by=grant branch-opt" in AUDIT[-1][1], AUDIT[-1:])
held = sets()
got = nina_option("domain", "branch")
check("negative: nina refused the domain's set, which needs networks options at every site; nothing written",
      "no grant gives you networks options at every site" in got and sets() == held, got)
got = nina_option("site", "lan")
check("negative: nina refused lan's options, which her grant does not reach", "networks options at lan" in got
      and sets() == held, got)

print("--- the 0.7 subnet commands as aliases, written to the domain (1.10.4.21, 2.1.10.27; area 4)")
DCK = {"secrets": SECRETS, "container": DC}


def why_refused(fn):
    """Purpose: what a call was refused with.
    Inputs:  fn — a function of no arguments.
    Returns: the refusal's text, or "not refused".
    Fails:   never.
    Feeds:   this script."""
    try:
        fn()
        return "not refused"
    except ValidationError as e:
        return str(e)


# covers: cli:dhcp.add-subnet +
out = add_dhcp_subnet(V, "root", "10.250.39.0/24", "alias39", 3939, "10.250.39.1", ["10.250.39.100 - 10.250.39.150"],
                      "via 0.7", **DCK)
s39 = sub("alias39")
check("add-subnet: a new VLAN named after the subnet, the subnet with its gateway, its pool a dhcp range, no split",
      out["result"]["vlan_added"] and any(x["id"] == 3939 and x["name"] == "alias39" for x in plan()["vlans"])
      and s39 and s39["gateway"] == "10.250.39.1" and s39["dhcp"]
      and [(r["kind"], r["first"], r["last"]) for r in s39["ranges"]] == [("dhcp", "10.250.39.100", "10.250.39.150")],
      s39)
held = plan()
why = why_refused(lambda: add_dhcp_subnet(V, "root", "10.250.39.128/25", "alias39b", 3939, None, [], "", **DCK))
check("negative: a subnet overlapping one of the plan's, naming it, nothing written", "overlap" in why
      and plan() == held, why)
# covers: cli:dhcp.set-subnet +
set_dhcp_subnet(V, "root", "alias39", notes="moved", remove_pools=["10.250.39.100 - 10.250.39.150"],
                add_pools=["10.250.39.160 - 10.250.39.200"], **DCK)
s39 = sub("alias39")
check("set-subnet: one pool removed and another added, the notes changed, in one change",
      [(r["first"], r["last"]) for r in s39["ranges"] if r["kind"] == "dhcp"] == [("10.250.39.160", "10.250.39.200")]
      and s39["notes"] == "moved", s39)
held = plan()
why = why_refused(lambda: set_dhcp_subnet(V, "root", "alias39", remove_pools=["10.250.39.1 - 10.250.39.9"], notes="x",
                                          **DCK))
check("negative: removing a pool the subnet does not have, nothing written (not even the notes)",
      "no DHCP pool" in why and plan() == held, why)
add_address(V, "root", "10.250.39.170", "reservation", "", "cam39", "02:00:00:00:39:01", **DCK)
# covers: cli:dhcp.unreserve +
remove_reservation_mac(V, "root", "02-00-00-00-39-01", **DCK)
check("unreserve: the reservation that MAC holds is removed (MAC given with dashes)",
      not any(a["ip"] == "10.250.39.170" for a in sub("alias39")["addresses"]))
why = why_refused(lambda: remove_reservation_mac(V, "root", "02:00:00:00:39:99", **DCK))
check("negative: unreserve for a MAC no reservation holds", "no reservation for 02:00:00:00:39:99" in why, why)
remove_vlan(V, "root", 3939, "", True, **DCK)
check("the alias VLAN removed again with its subnet", sub("alias39") is None)

print("--- removing")
held = plan()
code, out = ipam("vlan", "remove", "30", "--no-apply")
check("refused: removing a VLAN whose subnet records addresses, nothing removed", code == 1
      and "records 2 address(es)" in out and plan() == held, out)
code, out = ipam("vlan", "remove", "30", "--force", "--no-apply")
check("vlan remove --force: the VLAN, its subnet, ranges and addresses", code == 0
      and not any(x["id"] == 30 for x in plan()["vlans"]) and sub("cams") is None, out)
code, out = ipam("address", "remove", "10.1.30.10", "--no-apply")
check("refused: removing an address that went with its VLAN", code == 1 and "not recorded" in out, out)

if not os.environ.get("FABRIC_TEST_KEEP"):     # keep the DC to look into a failure
    subprocess.run(["docker", "rm", "-f", DC], capture_output=True)
    subprocess.run(["docker", "network", "rm", NET], capture_output=True)
print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
