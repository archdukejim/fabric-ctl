"""The `samba` suite, the address plan's store in AD (manual 1.10.4.31 to 1.10.4.33, 1.10.4.36; 2.1.10.33 to
2.1.10.35, 2.1.10.38): a real DC converged by fabric with the plan's schema numbered after 0.8.0's (fabricDcInfo 7,
the VLAN record 17, the site's record 18); the site's record and the domain's option set made by convergence, once;
the plan's directory operations as the DC's agent account (fabric-agent-dc-0001): a VLAN, a subnet, its ranges and
addresses written in the domain's OU=networks under the site's name, read back, changed and removed (a tree delete);
the site's number and both option sets on their entries; a second convergence leaving the plan's subnet alone and
giving its network to the AD site; a scan request made, read with its owner (an agent account), answered and removed;
and every refusal (an unknown change, a site with no record, a request id fabric does not make) changing nothing.
    sudo python3 tests/samba/plan_store.py
"""
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.dirname(os.path.abspath(__file__))]
from start_dc import start_dc  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.directory.run_op import run_op  # noqa: E402
from fabriclib.samba.converge_domain import converge_domain  # noqa: E402

W = os.path.join(os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests"), "samba-plan")
NET, SUBNET, IP = "sambaplan_net", "10.254.33.0/24", "10.254.33.10"
DC = "samba"            # the product's own name: fabric's functions use it
ARC = "1.2.840.113556.1.8000.2554"
FAILED = 0


def check(name, cond, detail=""):
    """Purpose: record one check and print it.
    Inputs:  name — what is checked; cond — bool; detail — shown when it fails.
    Returns: None.
    Fails:   never.
    Feeds:   this script."""
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def refused(fn, words):
    """Purpose: whether fn() is refused with a ValidationError naming `words`.
    Inputs:  fn — callable; words — text the message must hold.
    Returns: bool.
    Fails:   never.
    Feeds:   this script."""
    try:
        fn()
    except ValidationError as exc:
        if words.lower() in str(exc).lower():
            return True
        print(f"    refused, but not for {words!r}: {exc}")
    return False


def ldb(expr, *attrs):
    """Purpose: a search of the DC's own database, as the system (to see what the agent wrote).
    Inputs:  expr — an LDAP filter; attrs — attributes to print.
    Returns: str, ldbsearch's output.
    Fails:   never (an error is in the output).
    Feeds:   this script."""
    return subprocess.run(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb", expr, *attrs],
                          capture_output=True, text=True).stdout


if subprocess.run(["docker", "inspect", "samba"], capture_output=True).returncode == 0 and \
        not subprocess.run(["docker", "inspect", "-f", "{{.Config.Image}}", "samba"], capture_output=True,
                           text=True).stdout.strip().endswith(":test"):
    sys.exit("a container named samba that is not a test DC runs here: not touching it")
dc = start_dc(W, DC, NET, SUBNET, IP)
V, SECRETS = dc["v"], dc["secrets"]
SITE = V["site_name"]


def op(name, **args):
    """Purpose: one directory operation as the DC's agent account, as fabric-agent runs it.
    Inputs:  name — the operation; args — its arguments.
    Returns: its result.
    Fails:   ValidationError as run_op says.
    Feeds:   this script."""
    return run_op(V, SECRETS, name, args, DC)


# ---- the schema (1.10.4.31)
out = ldb("(|(lDAPDisplayName=fabricDcInfo)(lDAPDisplayName=fabricVlanRecord)(lDAPDisplayName=fabricSiteRecord))",
          "lDAPDisplayName", "governsID")
check("the schema: fabricDcInfo class 7, fabricVlanRecord 17, fabricSiteRecord 18",
      f"governsID: {ARC}" in out and ".2.7\n" in out and ".2.17\n" in out and ".2.18\n" in out, out)
check("no retired name in the schema (fabricAddressBlock, fabricLocalScan, fabricScanPolicy)",
      "lDAPDisplayName" not in ldb("(|(lDAPDisplayName=fabricAddressBlock)(lDAPDisplayName=fabricLocalScan)"
                                   "(lDAPDisplayName=fabricScanPolicy))", "lDAPDisplayName"))

# ---- the site's record and the domain's set (1.10.4.32)
plan = op("read_plan", of=SITE)
check("convergence made the site's record (no number yet) and the domain's empty option set",
      [s["name"] for s in plan["sites"]] == [SITE] and plan["sites"][0]["block"] is None
      and plan["option_sets"]["domain"] == {"options": [], "option_defs": [], "client_classes": []}
      and plan["plans"][SITE]["subnets"] == [], plan)
check("negative: a site with no record is refused", refused(lambda: op("read_plan", of="nowhere"), "no such site"))

# ---- the plan's entries (1.10.4.33)
changes = [
    {"do": "add", "what": "vlan", "site": SITE, "key": 20,
     "fields": {"id": 20, "name": "iot", "purpose": "things", "access": "full"}},
    {"do": "add", "what": "subnet", "site": SITE, "key": "iot",
     "fields": {"cidr": "10.1.20.0/24", "vlan": 20, "kind": "dhcp", "gateway": "10.1.20.1", "dhcp": True, "id": 7,
                "options": [{"name": "domain-name-servers", "data": "10.1.20.1"}],
                "netboot": {"server": "10.1.20.9", "bios": "pxelinux.0"}}},
    {"do": "add", "what": "range", "site": SITE, "subnet": "iot", "key": "dhcp-10.1.20.100",
     "fields": {"kind": "dhcp", "first": "10.1.20.100", "last": "10.1.20.249"}},
    {"do": "add", "what": "address", "site": SITE, "subnet": "iot", "key": "10.1.20.5",
     "fields": {"ip": "10.1.20.5", "kind": "reservation", "name": "cam1", "mac": "aa:bb:cc:00:11:22", "dns": True}},
]
done = op("write_plan", changes=changes)
plan = op("read_plan", of=SITE)["plans"][SITE]
sub = plan["subnets"][0] if plan["subnets"] else {}
check("a VLAN, a subnet, its range and address written as the agent and read back", len(done) == 4
      and plan["vlans"] == [{"id": 20, "name": "iot", "purpose": "things", "access": "full", "notes": ""}]
      and sub.get("cidr") == "10.1.20.0/24" and sub.get("dhcp") is True and sub.get("id") == 7
      and sub.get("netboot") == {"server": "10.1.20.9", "bios": "pxelinux.0"}
      and sub.get("options") == [{"name": "domain-name-servers", "data": "10.1.20.1"}]
      and [r["first"] for r in sub.get("ranges", [])] == ["10.1.20.100"]
      and [a["name"] for a in sub.get("addresses", [])] == ["cam1"], (done, plan))
out = ldb("(fabricSite=" + SITE + ")", "dn")
check("the entries are the domain's OU=networks, named with the site",
      f"dn: CN={SITE}/vlan/20,OU=networks," in out and f"dn: CN={SITE}/iot,OU=networks," in out, out)
op("write_plan", changes=[{"do": "set", "what": "subnet", "site": SITE, "key": "iot", "fields": {"notes": "cams"}}])
sub = op("read_plan", of=SITE)["plans"][SITE]["subnets"][0]
check("a set keeps the netboot preset it did not give", sub["notes"] == "cams" and sub["netboot"], sub)

# ---- convergence leaves the plan's subnet alone (1.10.4.33)
converge_domain(V, os.path.join(W, "federation.yaml"), SECRETS, container=DC)
sub = (op("read_plan", of=SITE)["plans"][SITE]["subnets"] or [{}])[0]
check("a second convergence keeps the plan's subnet, its ranges and addresses",
      sub.get("name") == "iot" and sub.get("addresses"), sub)
check("the AD site's subnets carry the plan's network", "10.1.20.0/24" in ldb("(objectClass=subnet)", "cn"))

# ---- the site's number and the option sets (1.10.4.32)
op("write_plan", changes=[{"do": "set", "what": "block", "site": SITE, "fields": {"block": 3}},
                          {"do": "set", "what": "options", "key": "domain",
                           "fields": {"options": [{"name": "ntp-servers", "data": "10.1.0.1"}]}},
                          {"do": "set", "what": "options", "key": SITE,
                           "fields": {"options": [{"code": 66, "data": "boot.lan"}]}}])
read = op("read_plan", of=SITE)
check("the site's number on its record; the domain's and the site's options on theirs",
      read["sites"][0]["block"] == 3 and read["options"] == [{"name": "ntp-servers", "data": "10.1.0.1"}]
      and read["plans"][SITE]["options"] == [{"code": 66, "data": "boot.lan"}], read)
check("negative: a number for a site with no record is refused, nothing written", refused(
    lambda: op("write_plan", changes=[{"do": "set", "what": "block", "site": "nowhere", "fields": {"block": 4}}]),
    "no such site") and op("read_plan", of=SITE)["sites"][0]["block"] == 3)
check("negative: an unknown change is refused", refused(
    lambda: op("write_plan", changes=[{"do": "set", "what": "local_scan", "site": SITE}]), "unknown plan change"))

# ---- a scan request (1.10.4.36)
RID = "scan-20261023120000-a1b2c3"
op("write_scan_request", do="add", of=SITE, subnet="iot", rid=RID, fields={"cidr": "10.1.20.0/24", "actor": "alice"})
reqs = op("read_scan_requests", of=SITE)
check("a scan request made by the agent: pending, its owner an agent account",
      [(r["id"], r["state"], r["by_agent"], r["actor"]) for r in reqs] == [(RID, "pending", True, "alice")], reqs)
op("write_scan_request", do="finish", of=SITE, subnet="iot", rid=RID,
   fields={"state": "done", "result": "{\"answered\": 1}", "done_at": "20261023120100Z"})
check("answered: done, its result read back",
      op("read_scan_requests", of=SITE)[0]["result"] == {"answered": 1})
check("negative: a state fabric does not write is refused", refused(
    lambda: op("write_scan_request", do="finish", of=SITE, subnet="iot", rid=RID, fields={"state": "pending"}),
    "is answered"))
op("write_scan_request", do="remove", of=SITE, subnet="iot", rid=RID)
check("removed", op("read_scan_requests", of=SITE) == [])

# ---- removal: a subnet with what is below it
op("write_plan", changes=[{"do": "remove", "what": "subnet", "site": SITE, "key": "iot"},
                          {"do": "remove", "what": "vlan", "site": SITE, "key": 20}])
plan = op("read_plan", of=SITE)["plans"][SITE]
check("a subnet removed with its ranges and addresses (a tree delete), and its VLAN",
      plan["subnets"] == [] and plan["vlans"] == [] and "10.1.20.5" not in ldb("(fabricIp=10.1.20.5)", "dn"), plan)

print("\nFAILED" if FAILED else "\nall passed", f"({FAILED} failures)")
sys.exit(1 if FAILED else 0)
