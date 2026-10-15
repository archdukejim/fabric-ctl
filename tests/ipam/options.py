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
from fabriclib.ipam.common.option_codes import CATALOGUE, CODES  # noqa: E402
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
# the scans requested from above (2.1.10.30): none here (their own cases: tests/ipam/scan_trigger.py)
m_poll.run_scan_requests = lambda v, secrets, container="samba": {"ran": [], "pending": False}


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
forced = m_poll.poll_plan({"site_name": "lan", "install_kea": True}, container="none", secrets={}, render=render,
                         firewall=firewall, usn=lambda c: USN["n"], read=answer(SITE), force=True,
                         take_lock=lambda: io.StringIO())
check("forced (Sync now, 2.1.10.29): the USN did not move, yet the plan is read; Kea's input unchanged, nothing "
      "rendered", forced["state"] == "same plan" and calls["render"] == 1, (forced, calls))
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
print("--- a plan with no subnet to serve yet (2.1.10.31)")
USN["n"] = 105
before_calls, before_audit = dict(calls), len(audit)


def empty_plan(v, s, of, container):
    out = answer(SITE)(v, s, of, container)
    out["plans"]["lan"] = {**out["plans"]["lan"], "subnets": [{**x, "dhcp": False}
                                                               for x in out["plans"]["lan"].get("subnets") or []]}
    return out


bare = poll(read_plan=empty_plan)
check("no subnet with a DHCP range: not a failure; nothing rendered, the firewall left, nothing audited; why says to "
      "define the subnet first", bare["state"] == "no subnet" and calls == before_calls and len(audit) == before_audit
      and "Define the subnet first" in bare["why"] and "best practice" in bare["why"], (bare, calls))
check("...the USN kept: the next run is quiet until the plan changes", poll(read_plan=empty_plan)["state"]
      == "unchanged")
USN["n"] = 106
same = poll()
check("the subnet back as Kea last had it: same plan (Kea was left as it was), nothing rendered",
      same["state"] == "same plan" and calls == before_calls, (same, calls))
USN["n"] = 107
back = poll(read_plan=answer({**SITE, "options": [{"name": "domain-name", "data": "y.lan"}]}))
check("a subnet with a range and a change: Kea is rendered", back["state"] == "rendered"
      and calls["render"] == before_calls["render"] + 1, (back, calls))
import fabriclib.ipam.options.run_option_command as m_roc  # noqa: E402
real_poll = m_roc.poll_plan
m_roc.poll_plan = lambda v, container="samba", secrets=None: {"state": "no subnet", "usn": 108, "why": m_poll.NO_SUBNET}
buf = io.StringIO()
with redirect_stdout(buf):
    rc = m_roc.run_option_command({"site_name": "lan", "install_kea": True}, "watch", ["--scheduled"], secrets={})
check("fabricctl ipam watch --scheduled says why when there is nothing to serve (the unit's journal)", rc == 0
      and "plan poll: no subnet" in buf.getvalue() and "Define the subnet first" in buf.getvalue(), buf.getvalue())
m_roc.poll_plan = real_poll
print("--- what DNS was rendered from is kept only once BIND took it (2.3.10.5.6)")
import fabriclib.ipam.load_address_plan as m_lap  # noqa: E402
from fabriclib.ipam.options.watch_state import load_watch_state  # noqa: E402
m_lap.read_plan = lambda v, secrets, of=None, container="samba": answer(SITE)(v, secrets, of, container)
m_lap.save_plan_cache = lambda plan: None
save_watch_state("plan-dns", {"dns": "before"})
fv, digest = {"site_name": "lan", "install_kea": True, "dhcp": {"interfaces": ["eth0"]}, "dns": {}}, {}
m_lap.load_address_plan(fv, {}, container="none", digest=digest)
check("load_address_plan gives the caller the DNS digest and writes nothing itself (an apply that fails later "
      "leaves plan-dns.json as it was)", digest.get("dns") == plan_digest(plan_to_dhcp(PLAN))["dns"]
      and load_watch_state("plan-dns") == {"dns": "before"}, (digest, load_watch_state("plan-dns")))
m_lap.load_address_plan({**fv, "dhcp": {"interfaces": ["eth0"]}}, {}, container="none")
check("the poll's render (no digest asked) writes nothing either", load_watch_state("plan-dns") == {"dns": "before"})
src = {f: open(os.path.join(REPO, "src", "fabriclib", *f.split("/")), encoding="utf-8").read()
       for f in ("deploy/apply_deployment.py", "dns/publish_zone_list.py")}
check("the apply keeps it after its restarts; a zone change after BIND serves the new list",
      src["deploy/apply_deployment.py"].index('save_watch_state("plan-dns"')
      > src["deploy/apply_deployment.py"].index("restart_changed(paths, final_vars")
      and src["dns/publish_zone_list.py"].index('save_watch_state("plan-dns"')
      > src["dns/publish_zone_list.py"].index('rndc(["zonestatus", zone])'))
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

print("--- the agent's option routes, each accepted and refused (fabriclib's writes stubbed; tests/samba/ipam.py "
      "runs them against a real DC)")
import agent.get_route as m_get  # noqa: E402
import agent.post_options as m_post  # noqa: E402
import fabriclib.ipam.options.options_overview as m_over  # noqa: E402

READ = {"sites": [{"name": "lan", "created": "1", "block": 1}],
        "plans": {"lan": {"vlans": PLAN["vlans"], "subnets": [SUB], "networks": []}},
        "option_sets": {"org": ORG, "lan": SITE}, "org_editors": []}
m_over.read_plan = lambda v, secrets=None, of=None, container="samba": READ
m_over.is_root_site = lambda: False
m_get.load_vars = m_post.load_vars = lambda: {"site_name": "lan"}
CALLS, APPLIES = [], []


def recorder(name):
    def fn(v, actor, *args, **kw):
        CALLS.append((name, args, kw))
        return {"result": name, "warnings": [], "site": "lan"}
    return fn


for fname in ("set_plan_option", "remove_plan_option", "add_plan_class", "remove_plan_class", "define_plan_option",
              "undefine_plan_option", "set_netboot", "clear_netboot"):
    setattr(m_post, fname, recorder(fname))
m_post.set_option_editor = lambda v, actor, site, add, source="": CALLS.append(("set_option_editor", (site, add),
                                                                               {"source": source})) or {"site": site}
m_post.apply_changes = lambda actor, source="": APPLIES.append(actor) or (True, "applied")
m_post.refresh_firewall = lambda: (True, "")
# covers: agent:get.ipam.options.* +
out = m_get.get_route(["ipam", "options", "-"])
check("GET /v1/ipam/options/<site>: this site's sets, its subnets and reservations, no target shown",
      out["site"] == "lan" and out["org"] == ORG and out["subnets"][0]["reservations"][0]["ip"] == "10.1.20.150"
      and out["effective"] is None, out)
# covers: agent:get.ipam.options.* -
check("refused: another site's options from a site that is not the top",
      refused(lambda: m_get.get_route(["ipam", "options", "house2"]), "at the top site"))
# covers: agent:get.ipam.options.*.* +
out = m_get.get_route(["ipam", "options", "-", "subnet:iot"])
check("GET /v1/ipam/options/<site>/<target>: the subnet's effective options with their sources",
      out["effective"] is not None and "domain-name-servers" in json.dumps(out["effective"]), out["effective"])
# covers: agent:get.ipam.options.*.* -
check("refused: a target that is not site, subnet:<name> or address:<ip>",
      refused(lambda: m_get.get_route(["ipam", "options", "-", "vlan:20"]), "target: site"))

POSTS = [  # (route after /v1/, a body it takes, the function it calls, a body it refuses, words)
    (["options"], {"scope": "site", "action": "set", "option": "ntp-servers", "data": "10.1.1.1"}, "set_plan_option",
     {"scope": "org", "action": "set", "option": "ntp-servers", "data": "10.1.1.1"}, "/v1/ipam/options/org"),
    (["options", "org"], {"scope": "org", "action": "remove", "option": "ntp-servers"}, "remove_plan_option",
     {"scope": "site", "action": "remove", "option": "ntp-servers"}, "/v1/ipam/options/org"),
    (["classes"], {"action": "add", "name": "uefi", "test": "option[93].hex == 0x0007"}, "add_plan_class",
     {"action": "rename", "name": "uefi"}, "add or remove"),
    (["classes", "org"], {"action": "remove", "name": "uefi"}, "remove_plan_class", {"action": "add", "name": 7},
     "must be text"),
    (["option-defs"], {"action": "define", "name": "ztp-url", "code": "239", "type": "string"}, "define_plan_option",
     {"action": "redefine", "name": "ztp-url"}, "define or undefine"),
    (["option-defs", "org"], {"action": "undefine", "name": "ztp-url"}, "undefine_plan_option",
     {"action": "undefine", "name": ["ztp-url"]}, "must be text"),
    (["netboot"], {"action": "on", "target": "subnet:iot", "server": "10.1.20.5", "bios": "x.0"}, "set_netboot",
     {"action": "maybe", "target": "subnet:iot"}, "on or off"),
    (["option-editors"], {"action": "add", "site": "house2"}, "set_option_editor", {"action": "grant", "site": "house2"},
     "add or remove")]
for route, body, fname, bad, words in POSTS:
    del CALLS[:], APPLIES[:]
    out = m_post.post_options(["ipam", *route], "alice", body)
    # covers: agent:post.ipam.options agent:post.ipam.options.org agent:post.ipam.classes +
    # covers: agent:post.ipam.classes.org agent:post.ipam.option-defs agent:post.ipam.option-defs.org +
    # covers: agent:post.ipam.netboot agent:post.ipam.option-editors +
    check(f"POST /v1/ipam/{'/'.join(route)}: {fname}, source web; applied here unless it is who may edit",
          [c[0] for c in CALLS] == [fname] and CALLS[0][2].get("source") == "web"
          and len(APPLIES) == (route != ["option-editors"]), (CALLS, out))
    del CALLS[:], APPLIES[:]
    # covers: agent:post.ipam.options agent:post.ipam.options.org agent:post.ipam.classes -
    # covers: agent:post.ipam.classes.org agent:post.ipam.option-defs agent:post.ipam.option-defs.org -
    # covers: agent:post.ipam.netboot agent:post.ipam.option-editors -
    check(f"refused: POST /v1/ipam/{'/'.join(route)} ({words}): nothing written or applied",
          refused(lambda: m_post.post_options(["ipam", *route], "alice", bad), words) and not CALLS and not APPLIES,
          CALLS)

print("--- the console's options page and forms, each accepted and refused (the agent stubbed)")
import webui.routes.options_page as m_page  # noqa: E402
import webui.routes.options_post as m_form  # noqa: E402
from webui.devpreview.sample_data import SAMPLE_OPTIONS  # noqa: E402


class Page:
    def __init__(self):
        self.sent = None

    def send(self, code, body, *_a):
        self.sent = (code, body)
        return code, body

    def redirect(self, url):
        return 303, url

    def deny(self, code, text):
        return code, text


SENT = []


def agent_sets(site, target):
    SENT.append((site, target))
    return {**SAMPLE_OPTIONS, "effective": None}


def agent_no_sets(site, target):
    raise m_page.actions.ValidationError("target: site, subnet:<name> or address:<ip>")


CTX = {"user": "alice", "csrf": "x", "perms": ["dhcp:read", "dhcp:write"], "version": {"version": "test"}}
m_page.actions.option_sets = agent_sets
page = Page()
# covers: web:get.kea.options +
code, body = m_page.options_page(page, CTX, {"site": "lan"})
check("console: GET /kea/options shows the option sets, links back to Kea and to the Networks tab",
      code == 200 and SENT[-1] == ("lan", "") and 'href="/networks"' in body
      and 'action="/kea/options/options"' in body, body[:300])
m_page.actions.option_sets = agent_no_sets
page = Page()
try:
    m_page.options_page(page, CTX, {"target": "vlan:20"})
    ok = False
except m_page.actions.ValidationError:
    ok = page.sent is None
# covers: web:get.kea.options -
check("console: refused GET /kea/options with a target the agent refuses (400 by handle_request, nothing sent)", ok)


def agent_ok(kind, org, body):
    SENT.append((kind, org, body))
    return {"what": kind, "result": {}, "warnings": [], "site": "lan", "applied": True, "output": ""}


def agent_no(kind, org, body):
    raise m_form.actions.ValidationError(f"the agent refused {kind}")


for parts in (["options"], ["options", "org"], ["classes"], ["classes", "org"], ["option-defs"], ["option-defs", "org"],
              ["netboot"], ["option-editors"]):
    m_form.actions.option_change = agent_ok
    del SENT[:]
    code, url = m_form.options_post(Page(), parts, {"csrf": "x", "action": "set", "site": "lan", "evil": "1",
                                                    "view_target": "subnet:iot", "always_send": "on"})
    # covers: web:post.kea.options.options web:post.kea.options.options.org web:post.kea.options.classes +
    # covers: web:post.kea.options.classes.org web:post.kea.options.option-defs +
    # covers: web:post.kea.options.option-defs.org web:post.kea.options.netboot web:post.kea.options.option-editors +
    check(f"console: POST /kea/options/{'/'.join(parts)} is one agent call with the form's own fields, back to the "
          "page with the target kept", code == 303 and "msg=" in url and "target=subnet%3Aiot" in url
          and SENT[0][:2] == (parts[0], parts[1:] == ["org"]) and "evil" not in SENT[0][2]
          and SENT[0][2].get("always_send") is True, (code, url, SENT))
    m_form.actions.option_change = agent_no
    code, url = m_form.options_post(Page(), parts, {"csrf": "x", "action": "set"})
    # covers: web:post.kea.options.options web:post.kea.options.options.org web:post.kea.options.classes -
    # covers: web:post.kea.options.classes.org web:post.kea.options.option-defs -
    # covers: web:post.kea.options.option-defs.org web:post.kea.options.netboot web:post.kea.options.option-editors -
    check(f"console: refused POST /kea/options/{'/'.join(parts)}: back to the page with the agent's why",
          code == 303 and "err=" in url and "msg=" not in url and "agent+refused" in url, (code, url))
import webui.routes.post_action as m_action  # noqa: E402
m_action.options_post = lambda h, parts, form: ("options_post", parts)
m_action.kea_post = lambda h, parts, form: ("kea_post", parts)
SESS = {"user": "alice", "sid": "s"}
check("console routing: /kea/options/<kind> to the options page; the Kea tab's 0.7 /kea/options and "
      "/kea/options/delete forms keep going to the Kea tab (found at the 0.8.0 merge)",
      m_action.post_action(None, SESS, "/kea/options/classes/org", {}) == ("options_post", ["classes", "org"])
      and m_action.post_action(None, SESS, "/kea/options/delete", {}) == ("kea_post", ["options", "delete"])
      and m_action.post_action(None, SESS, "/kea/options", {}) == ("kea_post", ["options"]))
check("console: a kind the page does not have, or a third segment, is 404",
      m_form.options_post(Page(), ["frob"], {})[0] == 404 and m_form.options_post(Page(), ["options", "x"], {})[0] == 404)

shutil.rmtree(W, ignore_errors=True)
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
