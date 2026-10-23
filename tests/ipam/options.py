#!/usr/bin/env python3
"""The DHCP options in the plan with no container (decisions 2.1.10.23 to 2.1.10.25, manual 1.10.4.24 to 1.10.4.26;
the port's area 4, 1.10.4.41): the option sets' checks and merge (the domain's under the site's under what the
settings still carry), the places a change works on (0.8's `org` read as `domain`), the netboot presets' checks and
the Kea classes they become, the provenance of each option, one change made the way every option command makes it
(the grant's networks options right first, at all sites for the domain's set; the writable DC; nothing written on a
refusal), and `fabricctl ipam option | class | netboot`'s refusals that need no domain. Area 5: Kea rendered from
them (each scope and preset), the plan poll (2.1.10.24, 1.10.4.26: Kea alone re-rendered when its input changed, a
plan with no subnet to serve, the DNS digest kept only once BIND took it) and `fabricctl ipam watch`. The options in a
real domain: tests/samba/ipam.py.

    python3 tests/ipam/options.py
"""
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
W = tempfile.mkdtemp(prefix="fabric-ipam-options-")
os.environ["DEPLOY_BASE_DIR"] = W               # the poll's kept state and vars.yaml go under the test's folder
os.makedirs(os.path.join(W, "fabric", "config"))
import fabriclib.ipam.common.edit_options as m_edit  # noqa: E402
import fabriclib.ipam.poll_plan as m_poll  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.dhcp.normalize_dhcp import normalize_dhcp  # noqa: E402
from fabriclib.ipam.common.option_codes import CATALOGUE, CODES  # noqa: E402
from fabriclib.ipam.options.add_plan_class import add_plan_class  # noqa: E402
from fabriclib.ipam.options.check_netboot import check_netboot  # noqa: E402
from fabriclib.ipam.options.check_option_set import check_option_set  # noqa: E402
from fabriclib.ipam.options.effective_options import effective_options  # noqa: E402
from fabriclib.ipam.options.merge_option_sets import merge_option_sets  # noqa: E402
from fabriclib.ipam.options.netboot_classes import netboot_classes  # noqa: E402
from fabriclib.ipam.options.plan_digest import plan_digest  # noqa: E402
from fabriclib.ipam.options.scope_options import scope_options  # noqa: E402
from fabriclib.ipam.options.set_netboot import set_netboot  # noqa: E402
from fabriclib.ipam.options.set_owner import set_owner  # noqa: E402
from fabriclib.ipam.options.set_plan_option import set_plan_option  # noqa: E402
from fabriclib.ipam.options.show_options import show_options  # noqa: E402
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
DOM = {"options": [{"name": "ntp-servers", "data": "10.9.9.9"}, {"name": "domain-name", "data": "corp.lan"}],
       "option_defs": [{"name": "ztp-url", "code": 239, "type": "string"}], "client_classes": []}
SITE = {"options": [{"name": "domain-name", "data": "lan.lan"}, {"name": "ztp-url", "data": "http://ztp/cfg"}],
        "option_defs": [], "client_classes": [{"name": "uefi", "test": "option[93].hex == 0x0007",
                                               "options": [{"name": "domain-name", "data": "uefi.lan"}]}]}
PLAN = {"site": "lan", "block": 1, "vlans": [{"id": 20, "name": "iot", "purpose": "", "access": "full", "notes": ""}],
        "subnets": [SUB], "networks": [], "domain_options": DOM, "site_options": SITE}

print("--- the option sets' checks (2.1.10.23, 1.10.4.24.2)")
check("the catalogue: Kea's standard DHCPv4 options by code and name", CATALOGUE[67] == "boot-file-name"
      and CODES["tftp-server-name"] == 66 and CATALOGUE[42] == "ntp-servers")
got = check_option_set({"options": [{"code": 66, "data": "boot.lan"}]})
check("a standard option given by its code is kept by its name", got["options"] == [{"name": "tftp-server-name",
                                                                                     "data": "boot.lan"}], got)
check("negative: a name Kea does not know, saying how to define it",
      refused(lambda: check_option_set({"options": [{"name": "no-such", "data": "x"}]}), "define it first"))
check("a custom option by the name a definition in force gives (the domain's, for a site's set)",
      check_option_set({"options": [{"name": "ztp-url", "data": "x"}]}, DOM["option_defs"])["options"][0]["name"]
      == "ztp-url")
check("negative: a client class named with fabric's netboot prefix", refused(
    lambda: check_option_set({"client_classes": [{"name": "fabric-nb-mine", "test": "true"}]}), "netboot"))
merged = merge_option_sets(DOM, SITE, {"options": [{"name": "ntp-servers", "data": "10.7.7.7"}]})
check("the merge, lowest first: the site's domain-name over the domain's, the settings' ntp over both, the domain's "
      "definition kept", {"name": "domain-name", "data": "lan.lan"} in merged["options"]
      and {"name": "ntp-servers", "data": "10.7.7.7"} in merged["options"]
      and len([o for o in merged["options"] if o["name"] == "ntp-servers"]) == 1
      and merged["option_defs"] == DOM["option_defs"], merged)

print("--- where a change works (1.10.4.24.5)")
dom = scope_options(PLAN, "domain")
check("the domain's set: written under the key `domain`", dom["domain"] is True
      and dom["write"]([])[0]["key"] == "domain" and dom["label"] == "the domain", dom)
check("0.8's word `org` reads as the domain's set", scope_options(PLAN, "org")["domain"] is True
      and set_owner(PLAN, "org")["key"] == "domain")
check("the site's set: written under the site's name, not the domain's", scope_options(PLAN, "site")["domain"] is False
      and scope_options(PLAN, "site")["write"]([])[0]["key"] == "lan")
check("a subnet by name or network", scope_options(PLAN, "subnet", "10.1.20.0/24")["options"] == SUB["options"])
check("a site's class", scope_options(PLAN, "class", "uefi")["options"] == SITE["client_classes"][0]["options"])
check("a reservation's address", scope_options(PLAN, "address", "10.1.20.150")["options"][0]["name"]
      == "ntp-servers")
check("a site's set takes the domain's definitions as in force", set_owner(PLAN, "site")["defs"] == DOM["option_defs"])
check("negative: an unknown scope", refused(lambda: scope_options(PLAN, "vlan", "20"), ""))
check("negative: a class not there", refused(lambda: scope_options(PLAN, "class", "nope"), "no client class"))
check("negative: an address that is not a reservation", refused(lambda: scope_options(PLAN, "address", "10.1.20.10"),
                                                                 "reservation"))
check("negative: the domain's set not made yet (the root's convergence makes it), saying so",
      refused(lambda: scope_options({**PLAN, "domain_options": None}, "domain"), "not made yet")
      and refused(lambda: set_owner({**PLAN, "domain_options": None}, "org"), "run an apply at the root site"))
check("negative: definitions and classes belong to the domain or a site", refused(lambda: set_owner(PLAN, "subnet"),
                                                                                  "domain or site"))

print("--- netboot presets (2.1.10.25, 1.10.4.25)")
preset, warns = check_netboot({"server": "10.1.20.5", "bios": "undionly.kpxe", "uefi": "", "ipxe": ""})
check("a preset normalized to the fields set; iPXE binaries with no iPXE script warned (they would loop)",
      preset == {"server": "10.1.20.5", "bios": "undionly.kpxe"} and any("iPXE again" in w for w in warns),
      (preset, warns))
check("a server by name is taken, with a warning", any("name" in w for w in check_netboot(
    {"server": "boot.lan", "ipxe": "http://boot.lan/boot.ipxe"})[1]))
check("negative: no boot server", refused(lambda: check_netboot({"bios": "x.0"}), "boot server"))
check("negative: nothing to boot", refused(lambda: check_netboot({"server": "10.1.20.5"}), "nothing to boot"))
check("negative: an iPXE URL that is not http(s)", refused(
    lambda: check_netboot({"server": "10.1.20.5", "ipxe": "tftp://x/boot.ipxe"}), "http"))
check("negative: a file name with a space or quote", refused(
    lambda: check_netboot({"server": "10.1.20.5", "bios": "a b.0"}), ""))
check("negative: a file longer than the packet's file field (127)", refused(
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
check("global level: the domain's under the site's; definitions carried", out["options"] == [
    {"name": "ntp-servers", "data": "10.9.9.9"}, {"name": "domain-name", "data": "lan.lan"},
    {"name": "ztp-url", "data": "http://ztp/cfg"}] and out["option_defs"] == DOM["option_defs"], out["options"])
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
check("domain-name: the site's, overriding the domain's (and fabric's)", rows["domain-name"]["source"]
      == "site lan" and "domain" in rows["domain-name"]["overrides"], rows["domain-name"])
check("ntp-servers: the reservation's, overriding the domain's", rows["ntp-servers"]["source"]
      == "address 10.1.20.150" and "domain" in rows["ntp-servers"]["overrides"], rows["ntp-servers"])
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
check("negative: a subnet not in the plan", refused(lambda: effective_options(PLAN, "subnet", "nope"), ""))
check("negative: an unknown kind", refused(lambda: effective_options(PLAN, "vlan", "20"), ""))
shown = show_options({"site": "lan", "domain": DOM, "site_options": SITE, "settings": None, "subnets": []})
check("option show: the domain's set and the site's, no editors line (the grants say who edits, 1.6.13.12)",
      shown.startswith("the domain\n") and "site lan" in shown and "editors" not in shown
      and "may edit" not in shown, shown)
check("option show before the domain's set is made says so", "not made yet" in show_options(
    {"site": "lan", "domain": None, "site_options": SITE, "settings": None, "subnets": []}))

print("--- one option change, the way every option command makes it (common/edit_options, 1.6.13.12)")
calls = []
READ = {"sites": [{"name": "lan", "created": "1", "block": 1}, {"name": "lab", "created": "2", "block": None}],
        "plans": {"lan": {"vlans": PLAN["vlans"], "subnets": [SUB], "networks": []}},
        "option_sets": {"domain": DOM, "lan": SITE}}
m_edit.check_access = lambda v, caller, action, target, container: calls.append(("check", caller, action, target)) or {
    "tier": "delegated", "by": "grant net-ops"}
m_edit.read_plan = lambda v, secrets, of, container, server=None: calls.append(("read", of)) or READ
m_edit.write_plan = lambda v, secrets, changes, container, server: calls.append(("write", server, changes)) or [
    "done"]
m_edit.save_plan_cache = lambda plan: calls.append(("keep", plan["site"]))
m_edit.write_audit = lambda actor, event, detail, source: calls.append(("audit", event, detail, source))
SEC = {"ad_agent_password": "x"}
LAN = {"site_name": "lan", "dc_name": "dc-0001"}
out = set_plan_option(LAN, "root", "site", "", "ntp-servers", "10.1.0.5", secrets=SEC)
check("the site's set: checked first (root, networks:options at the site), read, written at this DC, kept, "
      "audited with this DC, the site and what allowed it (1.10.4.34)",
      [c[0] for c in calls] == ["check", "read", "write", "read", "keep", "audit"]
      and calls[0] == ("check", None, "networks:options", {"site": "lan"}) and calls[2][1] is None
      and calls[2][2][0]["key"] == "lan" and calls[5][1] == "IPAM_OPTION_SET" and out["site"] == "lan"
      and calls[5][2].startswith("from=dc-0001 site=lan by=grant net-ops "), calls)
calls.clear()
set_plan_option(LAN, "nina", "domain", "", "ntp-servers", "10.1.0.6", secrets=SEC, caller="nina")
check("the domain's set: the grant checked at all sites (a grant for one site never reaches it)",
      calls[0] == ("check", "nina", "networks:options", {"site": "all"}) and calls[2][2][0]["key"] == "domain", calls)
calls.clear()
set_plan_option(LAN, "nina", "org", "", "ntp-servers", "10.1.0.7", secrets=SEC, caller="nina")
check("0.8's `org` is the domain's set, checked at all sites", calls[0][3] == {"site": "all"}, calls)
calls.clear()
set_plan_option(LAN, "nina", "class", "uefi", "domain-name", "u.lan", secrets=SEC, caller="nina")
check("a site's class: checked at the site", calls[0][3] == {"site": "lan"}, calls)
calls.clear()
add_plan_class(LAN, "nina", "domain", "arm", "option[93].hex == 0x000b", site="lab", secrets=SEC, source="web",
               caller="nina")
check("a class for the domain's set from another site: checked at all; not kept here; audited from the web",
      calls[0][3] == {"site": "all"} and "keep" not in [c[0] for c in calls] and calls[-1][3] == "web"
      and "site=lab" in calls[-1][2], calls)
calls.clear()
set_netboot(LAN, "nina", "iot", {"server": "10.1.20.5", "ipxe": "http://boot.lan/boot.ipxe"}, secrets=SEC,
            caller="nina")
check("a netboot preset: checked at the site (a subnet's, not the domain's)",
      calls[0] == ("check", "nina", "networks:options", {"site": "lan"})
      and calls[2][2][0]["what"] == "subnet", calls)


def refuse_grant(v, caller, action, target, container):
    at = "every site (the domain's own)" if target["site"] == "all" else target["site"]
    raise ValidationError(f"no grant gives you networks options at {at} (manual 1.6.13.12)")


calls.clear()
m_edit.check_access = refuse_grant
check("negative: no grant for the domain's set: refused before the plan is read, nothing written",
      refused(lambda: set_plan_option(LAN, "pete", "domain", "", "ntp-servers", "10.1.0.8", secrets=SEC,
                                      caller="pete"), "networks options at every site") and calls == [], calls)
m_edit.check_access = lambda v, caller, action, target, container: calls.append(("check",)) or {"by": "tier"}
RODC = {**LAN, "ad_dc_type": "rodc", "ad_join_server": "10.0.0.2"}
set_plan_option(RODC, "root", "site", "", "ntp-servers", "10.1.0.9", secrets=SEC)
check("a site with a read-only DC writes at its writable DC (2.1.6.52)",
      next(c for c in calls if c[0] == "write")[1] == "10.0.0.2", calls)
calls.clear()
check("negative: a read-only DC with no writable DC known: refused before anything is read or written",
      refused(lambda: set_plan_option({**LAN, "ad_dc_type": "rodc"}, "root", "site", "", "ntp-servers", "10.1.0.9",
                                      secrets=SEC), "no writable domain controller is known")
      and [c[0] for c in calls] == ["check"], calls)
calls.clear()
check("negative: a rule refused (an option Kea does not know): nothing written, nothing audited",
      refused(lambda: set_plan_option(LAN, "root", "site", "", "no-such", "x", secrets=SEC), "define it first")
      and "write" not in [c[0] for c in calls] and "audit" not in [c[0] for c in calls], calls)
check("negative: no domain yet (no agent password): refused before the DC is asked",
      refused(lambda: set_plan_option(LAN, "root", "site", "", "ntp-servers", "10.1.0.9", secrets={}),
              "ad_agent_password"))


print("--- the plan poll (2.1.10.24, 1.10.4.26)")
d1 = plan_digest(plan_to_dhcp(PLAN))
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
    bare = {k: x for k, x in PLAN.items() if k not in ("domain_options", "site_options")}
    return lambda v, s, of, container: {"sites": [{"name": "lan", "block": 1}], "plans": {"lan": bare},
                                        "option_sets": {"domain": DOM, "lan": site_set}}


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


print("--- fabricctl ipam option | class | netboot: refusals that need no domain (1.10.4.24.5)")
# covers: cli:ipam.option +
code, text = cli(["option", "--help"])
check("help lists every option command, with the domain's scope", code == 0 and "option set <scope>" in text
      and "netboot on" in text and "option define domain|site" in text and "option-editors" not in text, text)
code, text = cli(["--help"])
check("fabricctl ipam --help names the option commands", code == 0 and "option|class|netboot" in text, text)
# covers: cli:ipam.option -
code, text = cli(["option", "set", "site", "ntp-servers"])
check("negative: option set without data", code == 1 and "option set <scope> <name|code> <data>" in text, text)
code, text = cli(["option", "set"])
check("negative: option set without a scope, saying which there are", code == 1 and "give where: domain" in text,
      text)
code, text = cli(["option", "set", "subnet"])
check("negative: a subnet scope without its name", code == 1 and "give its name" in text, text)
code, text = cli(["option", "set", "site", "x", "y", "--csv", "maybe"])
check("negative: --csv other than on or off", code == 1 and "--csv is on or off" in text, text)
code, text = cli(["option", "set", "site", "x", "y", "--frob"])
check("negative: an unknown flag", code == 1 and "unknown option --frob" in text, text)
code, text = cli(["option", "show", "vlan", "20"])
check("negative: option show of a place it does not show", code == 1 and "option show: domain, site" in text, text)
code, text = cli(["option", "frobnicate"])
check("usage for an unknown option command", code == 2 and "usage:" in text, text)
code, text = cli(["option", "set", "domain", "ntp-servers", "10.1.0.1"])
check("negative: a change without the domain's agent password: refused, saying why", code == 1
      and "ad_agent_password" in text, text)
code, text = cli(["option", "watch"])
check("negative: the plan watch is not an option command here (area 5)", code == 2 and "usage:" in text, text)
code, text = cli(["option-editors"])
check("negative: option-editors is gone (the grants' networks options right replaces it): usage, exit 2",
      code == 2 and "usage:" in text, text)
# covers: cli:ipam.class -
code, text = cli(["class", "add", "site", "uefi"])
check("negative: class add without --test (usage)", code == 2 and "class add" in text, text)
code, text = cli(["class", "remove", "site", "uefi", "--org"])
check("negative: class remove without the domain's agent password (--org taken as --domain)", code == 1
      and "ad_agent_password" in text, text)
# covers: cli:ipam.netboot -
code, text = cli(["netboot", "on", "iot", "--server"])
check("negative: --server without a value", code == 1 and "--server needs a value" in text, text)
code, text = cli(["netboot", "on", "iot", "--server", "10.1.20.5"])
check("negative: netboot on with nothing to boot, refused before the domain is asked", code == 1
      and "nothing to boot" in text, text)
code, text = cli(["netboot", "off"])
check("negative: netboot off without a target: usage, exit 2", code == 2 and "usage:" in text, text)

print("--- fabricctl ipam watch (1.10.4.26)")
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

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
