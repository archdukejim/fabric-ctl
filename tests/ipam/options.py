#!/usr/bin/env python3
"""The DHCP options in the plan with no container (decisions 2.1.10.23 to 2.1.10.25, manual 1.10.4.24 to 1.10.4.26):
the option sets' checks and merge (the organisation's under the site's under what the settings still carry), the
places a change works on, the netboot presets' checks and the Kea classes they become (rendered by the Kea template
into JSON Kea's own layout takes), the provenance of each option, the plan poll's states with its steps stubbed, and
`fabricctl ipam option | class | netboot | option-editors | watch`'s refusals that need no domain. The options in a
real domain: tests/samba/ipam.py; Kea itself taking them: tests/kea/run.py.

    python3 tests/ipam/options.py
"""
import io
import json
import os
import shutil
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
W = tempfile.mkdtemp(prefix="fabric-ipam-options-")
os.environ["DEPLOY_BASE_DIR"] = W               # the poll's kept state and vars.yaml go under the test's folder
os.makedirs(os.path.join(W, "fabric", "config"))
import fabriclib.ipam.poll_plan as m_poll  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.dhcp.normalize_dhcp import normalize_dhcp  # noqa: E402
from fabriclib.ipam.options.catalogue import CATALOGUE, CODES  # noqa: E402
from fabriclib.ipam.options.check_netboot import check_netboot  # noqa: E402
from fabriclib.ipam.options.check_option_set import check_option_set  # noqa: E402
from fabriclib.ipam.options.effective_options import effective_options  # noqa: E402
from fabriclib.ipam.options.merge_option_sets import merge_option_sets  # noqa: E402
from fabriclib.ipam.options.netboot_classes import netboot_classes  # noqa: E402
from fabriclib.ipam.options.plan_digest import plan_digest  # noqa: E402
from fabriclib.ipam.options.scope_options import scope_options  # noqa: E402
from fabriclib.ipam.options.watch_state import save_watch_state  # noqa: E402
from fabriclib.ipam.plan_to_dhcp import plan_to_dhcp  # noqa: E402
from fabriclib.ipam.run_ipam_command import run_ipam_command  # noqa: E402

FAILED = 0


def check(name, ok, detail=""):
    global FAILED
    FAILED += not ok
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:500]}"))


def refused(fn, words):
    try:
        fn()
    except ValidationError as e:
        return words in str(e)
    return False


SUB = {"name": "iot", "cidr": "10.1.20.0/24", "vlan": 20, "gateway": "10.1.20.1", "dhcp": True, "id": 3, "relay": "",
       "notes": "", "allow_overlap": "", "options": [{"name": "domain-name-servers", "data": "10.1.20.1"}],
       "netboot": {"server": "10.1.20.5", "bios": "undionly.kpxe", "uefi": "ipxe.efi",
                   "ipxe": "http://boot.lan/boot.ipxe", "http": "http://boot.lan/grubx64.efi"},
       "ranges": [{"kind": "dhcp", "first": "10.1.20.100", "last": "10.1.20.249", "notes": ""}],
       "addresses": [{"ip": "10.1.20.150", "kind": "reservation", "name": "cam1", "mac": "aa:bb:cc:dd:ee:01",
                      "owner": "", "notes": "", "dns": False, "options": [{"name": "ntp-servers", "data": "10.0.0.9"}],
                      "netboot": {"server": "10.1.20.6", "bios": "cam.0"}},
                     {"ip": "10.1.20.10", "kind": "static", "name": "nas", "mac": "", "owner": "", "notes": "",
                      "dns": True, "options": []}]}
ORG = {"options": [{"name": "ntp-servers", "data": "10.9.9.9"}, {"name": "domain-name", "data": "org.lan"}],
       "option_defs": [{"name": "ztp-url", "code": 239, "type": "string"}], "client_classes": []}
SITE = {"options": [{"name": "domain-name", "data": "lan.lan"}, {"name": "ztp-url", "data": "http://ztp/cfg"}],
        "option_defs": [], "client_classes": [{"name": "uefi", "test": "option[93].hex == 0x0007",
                                               "options": [{"name": "domain-name", "data": "uefi.lan"}]}]}
PLAN = {"site": "lan", "block": 1, "vlans": [{"id": 20, "name": "iot", "purpose": "", "access": "full", "notes": ""}],
        "subnets": [SUB], "networks": [], "org_options": ORG, "site_options": SITE, "org_editors": []}

print("--- the option sets' checks (2.1.10.23, 1.10.4.24.2)")
check("the catalogue: Kea's standard DHCPv4 options by code and name", CATALOGUE[67] == "boot-file-name"
      and CODES["tftp-server-name"] == 66 and CATALOGUE[42] == "ntp-servers")
got = check_option_set({"options": [{"code": 66, "data": "boot.lan"}]})
check("a standard option given by its code is kept by its name", got["options"] == [{"name": "tftp-server-name",
                                                                                     "data": "boot.lan"}], got)
check("refused: a name Kea does not know, saying how to define it",
      refused(lambda: check_option_set({"options": [{"name": "no-such", "data": "x"}]}), "define it first"))
check("a custom option by the name a definition in force gives (the organisation's, for a site's set)",
      check_option_set({"options": [{"name": "ztp-url", "data": "x"}]}, ORG["option_defs"])["options"][0]["name"]
      == "ztp-url")
check("refused: a client class named with fabric's netboot prefix", refused(
    lambda: check_option_set({"client_classes": [{"name": "fabric-nb-mine", "test": "true"}]}), "netboot"))
merged = merge_option_sets(ORG, SITE, {"options": [{"name": "ntp-servers", "data": "10.7.7.7"}]})
check("the merge, lowest first: the site's domain-name over the organisation's, the settings' ntp over both, the "
      "organisation's definition kept", {"name": "domain-name", "data": "lan.lan"} in merged["options"]
      and {"name": "ntp-servers", "data": "10.7.7.7"} in merged["options"]
      and len([o for o in merged["options"] if o["name"] == "ntp-servers"]) == 1
      and merged["option_defs"] == ORG["option_defs"], merged)

print("--- where a change works (1.10.4.24.5)")
check("the organisation's set", scope_options(PLAN, "org")["org"] is True)
check("a subnet by name or network", scope_options(PLAN, "subnet", "10.1.20.0/24")["options"] == SUB["options"])
check("a site's class", scope_options(PLAN, "class", "uefi")["options"] == SITE["client_classes"][0]["options"])
check("a reservation's address", scope_options(PLAN, "address", "10.1.20.150")["options"][0]["name"]
      == "ntp-servers")
check("refused: an unknown scope", refused(lambda: scope_options(PLAN, "vlan", "20"), ""))
check("refused: a class not there", refused(lambda: scope_options(PLAN, "class", "nope"), "no client class"))
check("refused: an address that is not a reservation", refused(lambda: scope_options(PLAN, "address", "10.1.20.10"),
                                                                "reservation"))
check("refused: the organisation's set not in the domain yet",
      refused(lambda: scope_options({**PLAN, "org_options": None}, "org"), ""))

print("--- netboot presets (2.1.10.25, 1.10.4.25)")
preset, warns = check_netboot({"server": "10.1.20.5", "bios": "undionly.kpxe", "uefi": "", "ipxe": ""})
check("a preset normalized to the fields set; iPXE binaries with no iPXE script warned (they would loop)",
      preset == {"server": "10.1.20.5", "bios": "undionly.kpxe"} and any("iPXE again" in w for w in warns), (preset, warns))
check("a server by name is taken, with a warning", any("name" in w for w in check_netboot(
    {"server": "boot.lan", "ipxe": "http://boot.lan/boot.ipxe"})[1]))
check("refused: no boot server", refused(lambda: check_netboot({"bios": "x.0"}), "boot server"))
check("refused: nothing to boot", refused(lambda: check_netboot({"server": "10.1.20.5"}), "nothing to boot"))
check("refused: an iPXE URL that is not http(s)", refused(
    lambda: check_netboot({"server": "10.1.20.5", "ipxe": "tftp://x/boot.ipxe"}), "http"))
check("refused: a file name with a space or quote", refused(
    lambda: check_netboot({"server": "10.1.20.5", "bios": "a b.0"}), ""))
check("refused: a file longer than the packet's file field (127)", refused(
    lambda: check_netboot({"server": "10.1.20.5", "bios": "x" * 128}), ""))
nb = netboot_classes(PLAN)
names = [c["name"] for c in nb["classes"]]
check("the subnet's classes, in order iPXE, HTTP, BIOS, UEFI, each only-in-additional-list; the reservation's "
      "marker first", names[0] == "fabric-nb-a-10.1.20.150" and nb["subnets"]["iot"] == [
          "fabric-nb-s3-ipxe", "fabric-nb-s3-http", "fabric-nb-s3-bios", "fabric-nb-s3-uefi"]
      and nb["reservations"] == {"10.1.20.150": ["fabric-nb-a-10.1.20.150"]}
      and all(c.get("additional") for c in nb["classes"] if c["name"].startswith("fabric-nb-s3-")), nb)
by = {c["name"]: c for c in nb["classes"]}
check("iPXE: matched by option 77 'iPXE', handed the script's URL",
      "option[77]" in by["fabric-nb-s3-ipxe"]["test"] and by["fabric-nb-s3-ipxe"]["boot_file_name"]
      == "http://boot.lan/boot.ipxe")
check("HTTP boot: matched by the HTTPClient vendor class, which it is sent back",
      "HTTPClient" in by["fabric-nb-s3-http"]["test"]
      and {"name": "vendor-class-identifier", "data": "HTTPClient"} in by["fabric-nb-s3-http"]["options"])
check("BIOS: architecture 0, not iPXE; its file, next server and option 66",
      "0x0000" in by["fabric-nb-s3-bios"]["test"] and "not" in by["fabric-nb-s3-bios"]["test"]
      and by["fabric-nb-s3-bios"]["boot_file_name"] == "undionly.kpxe"
      and by["fabric-nb-s3-bios"].get("next_server") == "10.1.20.5"
      and {"name": "tftp-server-name", "data": "10.1.20.5"} in by["fabric-nb-s3-bios"]["options"], by)
check("UEFI: architectures 7 and 9", "0x0007" in by["fabric-nb-s3-uefi"]["test"]
      and "0x0009" in by["fabric-nb-s3-uefi"]["test"])
check("the reservation's classes test the marker after the host lookup",
      "member('KNOWN')" in by["fabric-nb-a-10.1.20.150-bios"]["test"]
      and "fabric-nb-a-10.1.20.150" in by["fabric-nb-a-10.1.20.150-bios"]["test"]
      and by["fabric-nb-a-10.1.20.150"].get("marker") is True)

print("--- the plan rendered for Kea, each scope and preset (1.10.4.24.3)")
out = plan_to_dhcp(PLAN)
check("global level: the organisation's under the site's; definitions carried", out["options"] == [
    {"name": "ntp-servers", "data": "10.9.9.9"}, {"name": "domain-name", "data": "lan.lan"},
    {"name": "ztp-url", "data": "http://ztp/cfg"}] and out["option_defs"] == ORG["option_defs"], out["options"])
check("the site's class and the netboot classes", [c["name"] for c in out["client_classes"]][:2]
      == ["uefi", "fabric-nb-a-10.1.20.150"], out["client_classes"])
V = {"install_kea": True, "domain": "lan.test", "host_ip": "192.168.4.2", "ip_kea_ddns": "10.255.0.40",
     "dns": {"dynamic_zone_var": {"A": out["records"]}},
     "dhcp": {"interfaces": ["eth0"], "subnets": out["subnets"], "options": out["options"],
              "option_defs": out["option_defs"], "client_classes": out["client_classes"]}}
try:
    norm = normalize_dhcp(V)
    text = jinja_env(os.path.join(REPO, "templates")).get_template("kea/kea-dhcp4.conf.j2").render(**{**V, "dhcp": norm})
    conf = json.loads("\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("//")))["Dhcp4"]
    s4 = conf["subnet4"][0]
    cls = {c["name"]: c for c in conf["client-classes"]}
    check("Kea's configuration is JSON: the global options and the definition",
          {"name": "ztp-url", "data": "http://ztp/cfg"} in conf["option-data"]
          and any(d["name"] == "ztp-url" and d["code"] == 239 for d in conf["option-def"]), conf.get("option-data"))
    check("the subnet names its preset's classes for evaluation after the subnet is chosen",
          s4["evaluate-additional-classes"] == ["fabric-nb-s3-ipxe", "fabric-nb-s3-http", "fabric-nb-s3-bios",
                                                 "fabric-nb-s3-uefi"]
          and {"name": "domain-name-servers", "data": "10.1.20.1"} in s4["option-data"], s4)
    check("a preset class: only-in-additional-list, its boot file in the header field and option 67",
          cls["fabric-nb-s3-bios"].get("only-in-additional-list") is True
          and cls["fabric-nb-s3-bios"]["boot-file-name"] == "undionly.kpxe"
          and cls["fabric-nb-s3-bios"]["next-server"] == "10.1.20.5"
          and {"name": "boot-file-name", "data": "undionly.kpxe"} in cls["fabric-nb-s3-bios"]["option-data"], cls)
    check("the marker class has no test; the reservation carries it with its own options",
          cls["fabric-nb-a-10.1.20.150"] == {"name": "fabric-nb-a-10.1.20.150"}
          and "fabric-nb-a-10.1.20.150" in s4["reservations"][0]["client-classes"]
          and {"name": "ntp-servers", "data": "10.0.0.9"} in s4["reservations"][0]["option-data"], s4["reservations"])
    check("the admin's class with its test and option", cls["uefi"]["test"] == "option[93].hex == 0x0007"
          and cls["uefi"]["option-data"] == [{"name": "domain-name", "data": "uefi.lan"}])
except ValidationError as e:
    check("fabric's own DHCP checks accept the plan's options and presets", False, e)

print("--- the provenance of each option (1.10.4.24.3)")
eff = effective_options(PLAN, "address", "10.1.20.150")
rows = {r["name"]: r for r in eff["rows"]}
check("the router is fabric's", rows["routers"]["source"].startswith("fabric"))
check("domain-name: the site's, overriding the organisation's (and fabric's)", rows["domain-name"]["source"]
      == "site lan" and "organisation" in rows["domain-name"]["overrides"], rows["domain-name"])
check("ntp-servers: the reservation's, overriding the organisation's", rows["ntp-servers"]["source"]
      == "address 10.1.20.150" and "organisation" in rows["ntp-servers"]["overrides"], rows["ntp-servers"])
check("domain-name-servers: the subnet's", rows["domain-name-servers"]["source"] == "subnet iot")
classes = {c["name"]: c for c in eff["classes"]}
check("the classes that may apply there: the site's, the subnet's preset and the reservation's",
      classes["uefi"]["owner"] == "site" and classes["fabric-nb-s3-ipxe"]["owner"] == "netboot"
      and "fabric-nb-a-10.1.20.150-bios" in classes, list(classes))
sub_eff = effective_options({**PLAN, "subnets": [{**SUB, "options": SUB["options"]
                                                  + [{"name": "domain-name", "data": "iot.lan"}]}]}, "subnet", "iot")
over = next(r for r in next(c for c in sub_eff["classes"] if c["name"] == "uefi")["rows"])
check("a class's option the subnet sets too is marked overridden by the subnet (Kea ranks a class below it)",
      over["overridden_by"] == "subnet iot", over)
check("refused: a subnet not in the plan", refused(lambda: effective_options(PLAN, "subnet", "nope"), ""))
check("refused: an unknown kind", refused(lambda: effective_options(PLAN, "vlan", "20"), ""))

print("--- the plan poll (2.1.10.24, 1.10.4.26)")
d1 = plan_digest(out)
d2 = plan_digest(plan_to_dhcp({**PLAN, "site_options": {**SITE, "options": [{"name": "domain-name", "data": "x"}]}}))
check("the digest: an option change moves Kea's, not DNS's or the subnets", d1["kea"] != d2["kea"]
      and d1["dns"] == d2["dns"] and d1["subnets"] == d2["subnets"] == ["10.1.20.0/24"], (d1, d2))
calls = {"render": 0, "firewall": 0}
USN = {"n": 100}
audit = []
m_poll.write_audit = lambda actor, event, detail, source: audit.append((event, detail))
m_poll._try_lock = lambda path=None: io.StringIO()


def render(secrets, container="samba"):
    calls["render"] += 1
    return {"changed": True, "subnets": ["10.1.20.0/24"]}


def firewall():
    calls["firewall"] += 1
    return True, "ok"


def answer(site_set):
    """read_plan's answer for site lan, its option set as given."""
    bare = {k: x for k, x in PLAN.items() if k not in ("org_options", "site_options", "org_editors")}
    return lambda v, s, of, container: {"sites": [{"name": "lan", "block": 1}], "plans": {"lan": bare},
                                        "option_sets": {"org": ORG, "lan": site_set}, "org_editors": []}


def poll(v=None, read_plan=None):
    return m_poll.poll_plan(v or {"site_name": "lan", "install_kea": True}, container="none", secrets={},
                            render=render, firewall=firewall, usn=lambda c: USN["n"], read=read_plan or answer(SITE))


check("off: Kea not installed", poll({"site_name": "lan"})["state"] == "off")
with open(os.path.join(W, "fabric", "config", "vars.yaml"), "w") as f:
    f.write("dhcp:\n  subnets: []\n")
check("not upgraded: the subnets still in the settings", poll()["state"] == "not upgraded")
with open(os.path.join(W, "fabric", "config", "vars.yaml"), "w") as f:
    f.write("dhcp:\n  interfaces: [eth0]\n")
first = poll()
check("the first run renders Kea and brings the firewall in line (the served subnets new), audited",
      first["state"] == "rendered" and calls == {"render": 1, "firewall": 1}
      and audit and audit[-1][0] == "IPAM_WATCH_RENDER", (first, calls, audit))
check("unchanged: the USN did not move, nothing read", poll(read_plan=lambda *a, **k: 1 / 0)["state"] == "unchanged")
USN["n"] = 101
check("same plan: the USN moved, Kea's input did not", poll()["state"] == "same plan" and calls["render"] == 1)
USN["n"] = 102
changed = answer({**SITE, "options": [{"name": "domain-name", "data": "x.lan"}]})
again = poll(read_plan=changed)
check("rendered: an option change re-renders Kea alone, the firewall left (same subnets)",
      again["state"] == "rendered" and calls == {"render": 2, "firewall": 1}, (again, calls))
USN["n"] = 103
m_poll._try_lock = lambda path=None: None
busy = poll()
check("busy: an apply holds the settings, nothing rendered, the USN not kept", busy["state"] == "busy"
      and calls["render"] == 2, busy)
m_poll._try_lock = lambda path=None: io.StringIO()
save_watch_state("plan-dns", {"dns": "something else"})
check("a DNS change is reported, not applied", poll()["dns_pending"] is True)
USN["n"] = 104


def failing():
    return False, "nft said no"


try:
    m_poll.poll_plan({"site_name": "lan", "install_kea": True}, container="none", secrets={}, render=lambda s, container:
                     {"changed": True, "subnets": ["10.1.99.0/24"]}, firewall=failing, usn=lambda c: USN["n"],
                     read=answer({**SITE, "options": []}))
    check("refused loudly: the firewall step failing", False)
except ValidationError as e:
    check("refused loudly: the firewall step failing; the USN not kept, so the next run tries again",
          "firewall" in str(e) and poll()["state"] != "unchanged", e)
unit = open(os.path.join(REPO, "templates", "systemd", "fabric-plan-watch.service")).read()
timer = open(os.path.join(REPO, "templates", "systemd", "fabric-plan-watch.timer")).read()
check("the unit runs the poll once, scheduled; the timer every 30 s",
      "fabricctl ipam watch --scheduled" in unit and "Type=oneshot" in unit and "OnUnitActiveSec=30s" in timer, unit)


def cli(argv, v=None):
    o, e = io.StringIO(), io.StringIO()
    with redirect_stdout(o), redirect_stderr(e):
        code = run_ipam_command(v or {"site_name": "lan"}, argv, secrets={}, container="no-such-dc")
    return code, o.getvalue() + e.getvalue()


print("--- fabricctl ipam option | class | netboot | option-editors | watch: refusals that need no domain")
# covers: cli:ipam.option +
code, text = cli(["option", "--help"])
check("help lists every option command", code == 0 and "option set <scope>" in text and "netboot on" in text, text)
# covers: cli:ipam.option -
code, text = cli(["option", "set", "site", "ntp-servers"])
check("refused: option set without data", code == 1 and "option set <scope> <name|code> <data>" in text, text)
code, text = cli(["option", "set", "subnet"])
check("refused: a subnet scope without its name", code == 1 and "give its name" in text, text)
code, text = cli(["option", "set", "site", "x", "y", "--csv", "maybe"])
check("refused: --csv other than on or off", code == 1 and "--csv is on or off" in text, text)
code, text = cli(["option", "set", "site", "x", "y", "--frob"])
check("refused: an unknown flag", code == 1 and "unknown option --frob" in text, text)
code, text = cli(["option", "frobnicate"])
check("usage for an unknown option command", code == 2 and "usage:" in text, text)
# covers: cli:ipam.class -
code, text = cli(["class", "add", "site", "uefi"])
check("refused: class add without --test (usage)", code == 2 and "class add" in text, text)
# covers: cli:ipam.netboot -
code, text = cli(["netboot", "on", "iot", "--server"])
check("refused: --server without a value", code == 1 and "--server needs a value" in text, text)
# covers: cli:ipam.option-editors -
code, text = cli(["option-editors", "add"])
check("usage: option-editors add without a site", code == 2, text)
# covers: cli:ipam.watch +
code, text = cli(["watch"])
check("watch with DHCP off says so", code == 0 and "plan poll: off" in text, text)
code, text = cli(["watch", "--scheduled"])
check("the timer's run is quiet when there is nothing to do", code == 0 and text == "", text)
# covers: cli:ipam.watch -
code, text = cli(["watch", "now"])
check("usage: watch takes no argument", code == 2 and "usage:" in text, text)
code, text = cli(["watch"], v={"site_name": "lan", "install_kea": True})
check("refused loudly: the DC not answering for its USN", code == 1 and "error:" in text, text)

print("--- the agent's option routes (1.3.3, 1.10.4.24.6): permissions and refusals before anything is written")
from agent.post_options import post_options  # noqa: E402
from agent.route_not_found import RouteNotFound  # noqa: E402
from fabriclib.rbac.required_permission import required_permission  # noqa: E402
check("a site's options, classes, definitions and presets: dhcp:write; reading them: dhcp:read",
      all(required_permission("POST", ["ipam", k]) == "dhcp:write" for k in ("options", "classes", "option-defs",
                                                                              "netboot"))
      and required_permission("GET", ["ipam", "options", "lan"]) == "dhcp:read"
      and required_permission("GET", ["ipam", "options", "lan", "subnet:iot"]) == "dhcp:read")
check("the organisation's, and who may edit them: dhcp:org-options",
      all(required_permission("POST", ["ipam", k, "org"]) == "dhcp:org-options" for k in ("options", "classes",
                                                                                          "option-defs"))
      and required_permission("POST", ["ipam", "option-editors"]) == "dhcp:org-options")
check("refused: the organisation's option through a site's route (dhcp:write alone never reaches it)", refused(
    lambda: post_options(["ipam", "options"], "alice", {"scope": "org", "action": "set", "option": "ntp-servers",
                                                        "data": "10.1.1.1"}), "/v1/ipam/options/org"))
check("refused: a site's option through the organisation's route", refused(
    lambda: post_options(["ipam", "options", "org"], "alice", {"scope": "site", "action": "set",
                                                               "option": "ntp-servers", "data": "10.1.1.1"}),
    "/v1/ipam/options/org"))
check("refused: an action the route does not take", refused(
    lambda: post_options(["ipam", "classes"], "alice", {"action": "rename", "name": "x"}), "add or remove"))
try:
    post_options(["ipam", "frob"], "alice", {})
    check("an unknown route is not found", False)
except RouteNotFound:
    check("an unknown route is not found", True)

shutil.rmtree(W, ignore_errors=True)
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
