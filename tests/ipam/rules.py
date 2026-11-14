#!/usr/bin/env python3
"""The `ipam` suite, a site's access table with no container (decision 2.1.10.63, manual 1.10.4.48.10 and
1.10.4.48.11): each VLAN, the other sites and outside, every service allowed or not; the host's VLAN, a VLAN with two
subnets, outside as every address but the networks denied; an upgraded site's table (2.1.10.59); the lockout guard
and --force (2.1.10.57); the warnings and the listing; Kea left silent for a VLAN not allowed dhcp; what the firewall
(ufw, DOCKER-USER), ping (ufw's before.rules) and the templates (BIND's and the resolver's blackhole) are built from;
one change made the way every command makes it (the grant first, the rows written, nothing on a refusal); `fabricctl
ipam access` and the agent's route, each both ways. A denied network getting no packet back from the real services:
the sandbox (tests/lab).

    python3 tests/ipam/rules.py
"""
import functools
import io
import os
import sys
import tempfile
import types
from contextlib import redirect_stderr, redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src")]
import agent.post_networks as m_post  # noqa: E402
import fabriclib.common.apply_intent as m_intent  # noqa: E402
import fabriclib.ipam.cli.run_plan_change as m_change  # noqa: E402
import fabriclib.ipam.cli.run_plan_read as m_read  # noqa: E402
import fabriclib.ipam.common.edit_plan as m_edit  # noqa: E402
import fabriclib.ipam.rules.set_access as m_set  # noqa: E402
import fabriclib.ipam.run_ipam_command as m_cmd  # noqa: E402
import fabriclib.undo.undo_firewall as m_undo  # noqa: E402
from agent.pending_networks import describe_networks  # noqa: E402
from agent.route_not_found import RouteNotFound  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.ipam.rules.access_table import access_table  # noqa: E402
from fabriclib.ipam.rules.access_view import access_view  # noqa: E402
from fabriclib.ipam.rules.access_warnings import access_warnings  # noqa: E402
from fabriclib.ipam.rules.change_access_rows import change_access_rows  # noqa: E402
from fabriclib.ipam.rules.check_cut_off import check_cut_off  # noqa: E402
from fabriclib.ipam.rules.constants import SERVICES  # noqa: E402
from fabriclib.ipam.rules.dhcp_allowed import dhcp_allowed  # noqa: E402
from fabriclib.ipam.rules.network_in import network_in  # noqa: E402
from fabriclib.ipam.rules.rule_networks import rule_networks  # noqa: E402
from fabriclib.ipam.rules.service_sources import service_sources  # noqa: E402
from fabriclib.ipam.rules.set_access import set_access  # noqa: E402
from fabriclib.ipam.rules.show_access import show_access  # noqa: E402
from fabriclib.rbac.required_permission import required_permission  # noqa: E402
from fabriclib.security.apply_docker_firewall import _published_ports, _rules  # noqa: E402
from fabriclib.security.apply_ping_rules import BEGIN, STOCK, STOCK6, apply_ping_rules  # noqa: E402
from fabriclib.security.firewall_rules import firewall_rules  # noqa: E402

FAILED = 0
m_cmd.apply_intent = functools.partial(m_intent.apply_intent, os.path.join(tempfile.mkdtemp(), ".apply.intent"))


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


def row(net, *allowed):
    """One kept row: the services named allowed, the rest denied."""
    return {"net": net, **{s: "allow" if s in allowed else "deny" for s in SERVICES}}


def vlan(i):
    return {"id": i, "location": "", "name": f"v{i}"}


def subnet(cidr, i, dhcp=True):
    return {"cidr": cidr, "vlan": i, "location": "", "dhcp": dhcp}


V = {"site_name": "house", "dc_name": "dc-0001", "host_ip": "10.1.10.5", "lan_cidr": "10.1.10.0/24",
     "fabric_subnet": "10.255.0.0/24"}
SIX = {"site": "house", "vlans": [vlan(10), vlan(20), vlan(30), vlan(40), vlan(50), vlan(60)],
       "subnets": [subnet("10.1.10.0/24", 10), subnet("10.1.20.0/24", 20), subnet("10.1.21.0/24", 20),
                   subnet("10.1.30.0/24", 30, dhcp=False), subnet("10.1.40.0/24", 40), subnet("10.1.50.0/24", 50)],
       "networks": [], "rules_kept": True,
       "rules": [row("20", "dns", "dhcp", "web"), row("40", "ntp"), row("50", "dhcp", "ntp")]}

print("--- the table (1.10.4.48.10)")
fresh = {"site": "house", "vlans": [], "subnets": [], "networks": [], "rules": [], "rules_kept": False}
src = service_sources(V, fresh)
check("positive: a fresh site: only the host's network (lan_cidr) reaches every service",
      all(nets == ["10.1.10.0/24"] for nets in src.values()) and len(src) == 8, src)
table = access_table(SIX, "10")
check("positive: every network has all eight services: each VLAN, then fabric and any",
      list(table) == ["10", "20", "30", "40", "50", "60", "fabric", "any"]
      and all(list(r) == list(SERVICES) for r in table.values()), table)
check("positive: defaults: the host's VLAN everything; a VLAN with no row kept (30, 60), fabric and any nothing",
      set(table["10"].values()) == {"allow"} and all(set(table[k].values()) == {"deny"}
                                                      for k in ("30", "60", "fabric", "any")), table)
check("negative: a kept row naming a network the site has not is left out",
      "70" not in access_table({**SIX, "rules": [row("70", "dns")]}, "10"))
src = service_sources(V, SIX)
check("positive: six VLANs: each service answers only the networks allowed it, the host's first",
      src["dns"] == ["10.1.10.0/24", "10.1.20.0/24", "10.1.21.0/24"]
      and src["dhcp"] == ["10.1.10.0/24", "10.1.20.0/24", "10.1.21.0/24", "10.1.50.0/24"]
      and src["ssh"] == ["10.1.10.0/24"] and src["web"] == ["10.1.10.0/24", "10.1.20.0/24", "10.1.21.0/24"], src)
check("positive: a VLAN with two subnets: its row covers both", "10.1.21.0/24" in src["dns"], src)
check("negative: a VLAN denied a service reaches nothing of it (30 ntp, 40 dns)",
      "10.1.30.0/24" not in src["ntp"] and "10.1.40.0/24" not in src["dns"] and "10.1.40.0/24" not in src["ping"], src)
check("negative: no outside address while outside is denied", "0.0.0.0/0" not in src["ntp"]
      and not network_in("8.8.8.8/32", src["ntp"]), src["ntp"])
holes = service_sources(V, {**SIX, "rules": [*SIX["rules"], row("any", "dns")]})["dns"]
check("positive: outside allowed: every address but the networks denied, as the fewest CIDRs",
      network_in("10.1.20.0/24", holes) and network_in("8.8.8.8/32", holes) and network_in("10.1.10.0/24", holes)
      and len(holes) < 40, holes)
check("negative: ...the denied VLANs stay out of outside's list", not network_in("10.1.30.0/24", holes)
      and not network_in("10.1.40.0/24", holes) and not network_in("10.1.30.7/32", holes), holes)
TWO = {**SIX, "fabric_networks": ["10.2.20.0/24", "10.2.30.0/24"]}
check("positive: fabric: the other sites' networks, after this site's",
      service_sources(V, {**TWO, "rules": [row("fabric", "ad")]})["ad"][-2:] == ["10.2.20.0/24", "10.2.30.0/24"])
check("negative: another site's networks are not reached while fabric is denied",
      "10.2.20.0/24" not in service_sources(V, TWO)["ad"])
nets = rule_networks({**V, "host_ip": "192.168.9.9"}, SIX)
check("positive: no VLAN holds host_ip: the host's network is lan_cidr, always allowed",
      nets["host"] == ["10.1.10.0/24"] and nets["host_vlan"] is None
      and service_sources({**V, "host_ip": "192.168.9.9"}, {**SIX, "rules": [row("10")]})["ssh"][0] == "10.1.10.0/24",
      nets)
check("positive: the VLAN that holds host_ip is the host's", rule_networks(V, SIX)["host_vlan"] == "10")

print("--- an upgraded site (1.10.4.48.10, 2.1.10.59)")
seed = access_table({**SIX, "rules_kept": False}, "10")
check("positive: nothing kept: every VLAN with a served subnet every service but ssh, the host's VLAN everything",
      seed["40"]["web"] == "allow" and seed["50"]["dns"] == "allow" and seed["50"]["ssh"] == "deny"
      and seed["10"]["ssh"] == "allow", seed)
check("negative: a VLAN without a served subnet (30, 60), fabric and any are given nothing",
      all(set(seed[k].values()) == {"deny"} for k in ("30", "60", "fabric", "any")), seed)
blank = access_table(fresh, None)
check("negative: a fresh site (no VLAN) is given nothing: fabric and any denied",
      list(blank) == ["fabric", "any"] and all(set(r.values()) == {"deny"} for r in blank.values()), blank)

print("--- the guard, the warnings, the listing (1.10.4.48.10, 1.10.4.48.11)")
nets = rule_networks(V, SIX)
check("positive: the host's VLAN keeps ssh and web: no cut-off", check_cut_off(table, "10") is None)
cut = check_cut_off({**table, "10": {**table["10"], "web": "deny"}}, "10")
check("negative: the host's VLAN denied web is a cut-off, naming --force", cut and "without web" in cut
      and "--force" in cut, cut)
check("positive: no VLAN holds the host: nothing to guard", check_cut_off(table, None) is None)
warn = access_warnings(access_table({**SIX, "rules": [*SIX["rules"][:2], row("50", "dhcp")]}, "10"), nets)
check("positive: warned: VLAN 50 has dhcp but not dns; VLAN 30 reaches nothing",
      any("VLAN 50 gets DHCP" in w for w in warn) and any("VLAN 30 reaches none" in w for w in warn), warn)
check("negative: not warned: a VLAN with no subnet (60), a VLAN allowed something (40)",
      not any("VLAN 60" in w or "VLAN 40" in w for w in warn), warn)
check("negative: outside denied: no warning that a service is open to every address",
      not any("every address" in w for w in warn), warn)
warn = access_warnings(access_table({**SIX, "rules": [row("any", "dns", "ping")]}, "10"), nets)
check("positive: warned: outside allowed a service, naming each", "outside: dns, ping open to every address, outside "
      "ones too" in warn, warn)
lines = show_access(table, nets, kept=True)
check("positive: the listing: a header of the services, a line per network, the host's marked, each VLAN's subnets",
      lines[0].startswith("network") and "ping" in lines[0] and lines[1].startswith("10 (host)")
      and lines[2].split() == ["20", "yes", "-", "yes", "yes", "-", "-", "-", "-"]
      and "VLAN 20: 10.1.20.0/24, 10.1.21.0/24" in lines, lines)
check("negative: nothing kept: the listing says so", show_access(seed, nets, kept=False)[-1].startswith("(none written"))
view = access_view(V, SIX, True)
check("positive: the console's view: a tab per VLAN, the host's first, then Other sites and Outside",
      [n["key"] for n in view["networks"]] == ["10", "20", "30", "40", "50", "60", "fabric", "any"]
      and view["networks"][0]["host"] and view["networks"][-2]["label"] == "Other sites"
      and view["networks"][-1]["label"] == "Outside", view["networks"])
check("positive: each tab lists the eight services with their ports; the host's ssh and web are guarded",
      all(len(n["services"]) == 8 for n in view["networks"])
      and [s["name"] for s in view["networks"][0]["services"] if s["guarded"]] == ["web", "ssh"]
      and not any(s["guarded"] for s in view["networks"][1]["services"]), view["networks"][0])

print("--- Kea (1.10.4.48.3: no subnet selected, nothing said)")
kea = [{"subnet": "10.1.10.0/24"}, {"subnet": "10.1.40.0/24"}, {"subnet": "10.1.50.0/24"}]
check("positive: Kea serves the subnets allowed dhcp", dhcp_allowed(kea, V, SIX) == [kea[0], kea[2]])
check("negative: a VLAN not allowed dhcp (40) is left out of Kea", {"subnet": "10.1.40.0/24"}
      not in dhcp_allowed(kea, V, SIX))
opened = {**SIX, "rules": [*SIX["rules"], row("any", "dhcp")]}
check("positive: outside allowed dhcp, 40 denied it: Kea serves every subnet but the denied one (its list is CIDRs that "
      "cover them)", dhcp_allowed(kea, V, opened) == [kea[0], kea[2]], dhcp_allowed(kea, V, opened))

print("--- the firewall (1.10.4.48.3)")
cfg = tempfile.mkdtemp()
fw = firewall_rules({**V, "access_sources": src, "security": {"firewall_allow": ["203.0.113.7/32"]}}, cfg)
check("positive: ufw: SSH from the networks allowed ssh, then firewall_allow; the DC's ports from those allowed ad",
      fw["ssh"] == ["10.1.10.0/24", "203.0.113.7/32"] and any("@10.1.10.0/24@" in a for a in fw["ad"])
      and any("@10.255.0.0/24@" in a for a in fw["ad"]), fw)
check("negative: ufw: a network not allowed ssh or ad gets neither", "10.1.20.0/24" not in fw["ssh"]
      and not any("@10.1.20.0/24@" in a for a in fw["ad"]), fw)
ports = _published_ports({"bind_dns_port": 5053})
chain = _rules(src, ports, ["203.0.113.7/32"], ["10.1.99.9"])
check("positive: DOCKER-USER: each allowed network to its service's own ports, by the port the client asked for",
      ["-s", "10.1.20.0/24", "-p", "tcp", "-m", "conntrack", "--ctorigdstport", "443", "-j", "RETURN"] in chain
      and ["-s", "10.1.20.0/24", "-p", "udp", "-m", "conntrack", "--ctorigdstport", "5053", "-j", "RETURN"] in chain
      and ["-s", "203.0.113.7/32", "-j", "RETURN"] in chain, chain)
check("negative: DOCKER-USER: a network allowed only dhcp gets no published port; every other NEW is dropped",
      not any(r[:2] == ["-s", "10.1.50.0/24"] for r in chain)
      and chain[-1] == ["-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"], chain[-3:])

print("--- ping (2.1.10.56)")
before, before6 = os.path.join(cfg, "before.rules"), os.path.join(cfg, "before6.rules")
with open(before, "w") as f:
    f.write(f"*filter\n# ok icmp codes for INPUT\n{STOCK}\nCOMMIT\n")
with open(before6, "w") as f:
    f.write(f"*filter\n{STOCK6}\nCOMMIT\n")
out = apply_ping_rules({**V, "access_sources": src}, cfg, before, before6)
text = open(before).read()
check("positive: ufw's answer to every echo request becomes one line per network allowed ping; IPv6's is left out",
      out["changed"] and STOCK not in text and BEGIN in text
      and "-s 10.1.10.0/24 -j ACCEPT" in text and STOCK6 not in open(before6).read(), (out, text))
check("positive: the files as they were are kept once for uninstall",
      STOCK in open(os.path.join(cfg, "host-originals", "ufw.before.rules")).read())
again = apply_ping_rules({**V, "access_sources": src}, cfg, before, before6)
check("positive: run again with the same rules: nothing changes (no reload)", not again["changed"], again)
more = apply_ping_rules({**V, "access_sources": {**src, "ping": ["10.1.10.0/24", "10.1.20.0/24"]}}, cfg, before,
                        before6)
check("positive: a rule change rewrites fabric's block in place", more["changed"]
      and open(before).read().count(BEGIN) == 1 and "-s 10.1.20.0/24" in open(before).read(), open(before).read())
hand = os.path.join(cfg, "hand.rules")
with open(hand, "w") as f:
    f.write("*filter\nCOMMIT\n")
out = apply_ping_rules({**V, "access_sources": src}, cfg, hand, os.path.join(cfg, "none"))
check("negative: a file changed by hand (no stock line) is left, and said", not out["changed"]
      and any("changed by hand" in s for s in out["skipped"]), out)
m_undo.BEFORE, m_undo.BEFORE6 = before, before6
m_undo.subprocess = types.SimpleNamespace(run=lambda *a, **k: types.SimpleNamespace(returncode=1))   # no ufw here
done = m_undo.undo_firewall(cfg)
check("positive: uninstall puts both files back as they were", open(before).read().count(STOCK) == 1
      and BEGIN not in open(before).read() and any("put back as it was" in d for d in done), done)

print("--- the templates (1.10.4.48.3)")
TPL = jinja_env(os.path.join(REPO, "templates"))
deny = {"dns": ["10.1.40.0/24", "10.1.50.0/24"]}
bind = TPL.get_template("bind9/config/named.conf.options.j2").render(
    bind_dns_port=53, bind9_doh_port=8053, access_denied=deny, host_ip="10.1.10.5", fabric_subnet="10.255.0.0/24")
check("positive: BIND ignores a network not allowed dns (blackhole), never this host or fabric's containers",
      "blackhole { !127.0.0.1; !10.1.10.5; !10.255.0.0/24; 10.1.40.0/24; 10.1.50.0/24; };" in bind, bind)
check("negative: BIND answers no IPv6", "listen-on-v6 { none; };" in bind)
none = TPL.get_template("bind9/config/named.conf.options.j2").render(bind_dns_port=53, bind9_doh_port=8053)
check("negative: nothing denied: no blackhole line", "blackhole" not in none)

print("--- one change, the way every command makes it (1.10.4.48.11)")
calls = []
READ = {"sites": [{"name": "house", "created": "1", "block": 1, "rules": SIX["rules"], "rules_kept": True},
                  {"name": "cabin", "created": "2", "block": 2, "rules": [], "rules_kept": False}],
        "plans": {"house": {k: SIX[k] for k in ("vlans", "subnets", "networks")},
                  "cabin": {"vlans": [], "subnets": [], "networks": []}}, "option_sets": {}}
m_edit.check_access = lambda v, caller, action, target, container: calls.append(("check", caller, action)) or {
    "by": "grant net-ops"}
m_edit.read_plan = lambda v, secrets, of, container, server=None: calls.append(("read", of)) or READ
m_edit.write_plan = lambda v, secrets, changes, container, server: calls.append(("write", changes)) or ["done"]
m_edit.save_plan_cache = lambda plan: calls.append(("keep",))
m_edit.write_audit = lambda actor, event, detail, source: calls.append(("audit", event, detail, source))
m_set.write_audit = lambda actor, event, detail, source: calls.append(("audit", event, detail, source))
SEC = {"ad_agent_password": "x"}
out = set_access(V, "root", "40", {"dns": "allow"}, secrets=SEC)
written = [c for c in calls if c[0] == "write"]
rows = written[0][1][0]["fields"]["rules"] if written else []
check("positive: set: the grant first, the rows written as one change (one per network off its default), audited",
      calls[0] == ("check", None, "networks:plan") and written[0][1][0]["what"] == "rules"
      and row("40", "ntp", "dns") in rows and len(rows) == 3 and calls[-1][1] == "IPAM_ACCESS_SET", calls)
check("positive: ...it says what changed and the network's row after", out["result"]["did"] == "40: dns allow"
      and out["result"]["row"]["ntp"] == "allow", out["result"])
calls.clear()
out = set_access(V, "root", "20", {"all": "deny"}, secrets=SEC)
check("positive: `all`: every service at once; a row back at its default is no longer kept",
      [r["net"] for r in [c for c in calls if c[0] == "write"][0][1][0]["fields"]["rules"]] == ["40", "50"],
      calls)
out = set_access(V, "root", "fabric", {"ad": "allow", "dns": "allow"}, secrets=SEC)
check("positive: the other sites, by name", out["result"]["network"] == "fabric"
      and out["result"]["row"]["ad"] == "allow", out["result"])
out = set_access(V, "root", "any", {"dns": "allow"}, secrets=SEC)
check("positive: outside, by name, warned that it opens dns to every address", out["result"]["network"] == "any"
      and any("every address" in w for w in out["warnings"]), out)
calls.clear()
out = set_access(V, "nina", "20", {"dns": "allow", "web": "allow"}, whole=True, secrets=SEC, source="web",
                 caller="nina")
check("positive: a whole row (the console's tab): a service left out is denied", out["result"]["row"]["dhcp"]
      == "deny" and out["result"]["row"]["web"] == "allow" and calls[0] == ("check", "nina", "networks:plan"),
      out["result"])
for name, fn, words in (
        ("an unknown service", lambda: set_access(V, "root", "20", {"smtp": "allow"}, secrets=SEC), "service 'smtp'"),
        ("a VLAN the site has not", lambda: set_access(V, "root", "70", {"dns": "allow"}, secrets=SEC),
         "network '70'"),
        ("a network that is no VLAN", lambda: set_access(V, "root", "site", {"dns": "allow"}, secrets=SEC),
         "a VLAN of the site"),
        ("an action that is not one", lambda: set_access(V, "root", "20", {"dns": "maybe"}, secrets=SEC),
         "allow or deny"),
        ("no service", lambda: set_access(V, "root", "20", {}, secrets=SEC), "no service given"),
        ("a change that changes nothing", lambda: set_access(V, "root", "50", {"dhcp": "allow"}, secrets=SEC),
         "nothing to change"),
        ("the host's VLAN cut off", lambda: set_access(V, "root", "10", {"ssh": "deny"}, secrets=SEC),
         "without ssh"),
        ("the host's VLAN cut off by a whole row", lambda: set_access(V, "nina", "10", {"dns": "allow"}, whole=True,
                                                                      secrets=SEC, source="web", caller="nina"),
         "without ssh"),
        ("--force from the console", lambda: set_access(V, "nina", "10", {"ssh": "deny"}, force=True, secrets=SEC,
                                                        source="web", caller="nina"), "only on the command line")):
    calls.clear()
    check(f"negative: refused, nothing written: {name}", refused(fn, words) is True
          and not [c for c in calls if c[0] == "write"], (refused(fn, words), calls))
calls.clear()
out = set_access(V, "root", "10", {"ssh": "deny"}, force=True, secrets=SEC)
check("positive: --force on the command line, as root: written, and audited IPAM_RULE_FORCED",
      out["result"]["forced"] and [c[1] for c in calls if c[0] == "audit"] == ["IPAM_ACCESS_SET", "IPAM_RULE_FORCED"],
      calls)
out = set_access(V, "root", "any", {"dns": "allow"}, site="cabin", secrets=SEC)
check("positive: another site's table: its own rows, the host's network not known there",
      out["site"] == "cabin" and out["result"]["row"]["dns"] == "allow", out)
rows, after, net, did = change_access_rows(SIX, "10", "20@", {"ping": "allow"})
check("positive: change_access_rows alone (the dev preview's): rows and the table after, nothing written",
      net == "20" and after["20"]["ping"] == "allow" and row("20", "dns", "dhcp", "web", "ping") in rows, rows)

print("--- fabricctl ipam access (1.10.4.48.11)")
m_read.read_plan = lambda v, secrets, of, container: READ
m_change.report_change = lambda v, out, bare: 0


def cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = m_cmd.run_ipam_command(V, argv, secrets=SEC, container="none")
    return code, out.getvalue() + err.getvalue()


# covers: cli:ipam.access +
code, text = cli(["access"])
check("positive: `ipam access` lists each network's services, the host's marked", code == 0
      and "10 (host)" in text and "fabric" in text and "VLAN 20: 10.1.20.0/24" in text, text)
code, text = cli(["access", "set", "40", "dns", "allow"])
check("positive: `ipam access set` says what it did and what the network reaches after", code == 0
      and "40: dns allow" in text and "40 reaches: dns, ntp" in text, text)
code, text = cli(["access", "set", "10", "ssh", "deny", "--force"])
check("positive: `ipam access set --force` as root at the host: taken, and said", code == 0 and "forced" in text,
      text)
# covers: cli:ipam.access -
code, text = cli(["access", "set", "40", "telnet", "allow"])
check("negative: `ipam access set` with an unknown service: refused, exit 1", code == 1
      and "service 'telnet'" in text, text)
code, text = cli(["access", "set", "10", "web", "deny"])
check("negative: `ipam access set` cutting the host's VLAN off the console: refused, naming --force", code == 1
      and "without web" in text and "--force" in text, text)
code, text = cli(["access", "set", "40"])
check("negative: `ipam access set` without service and action: usage, exit 2", code == 2 and "usage:" in text, text)
code, text = cli(["rule", "add", "40", "dns", "allow"])
check("negative: `ipam rule` is gone: refused, naming ipam access", code == 1 and "ipam access" in text, text)
code, text = cli(["vlan", "add", "70", "--name", "x", "--access", "guest"])
check("negative: --access is no longer taken (2.1.10.58), naming ipam access", code == 1
      and "fabricctl ipam access" in text, text)

print("--- the agent's route (1.10.4.48.11)")
APPLIED = []
m_post.load_vars = lambda: V
m_edit.load_secrets = lambda: SEC
m_post.apply_plan_change = lambda v, actor, out, apply=True: APPLIED.append(out["site"]) or {**out, "own": True}
calls.clear()
# covers: agent:post.networks.*.access.* +
out = m_post.post_networks(["networks", "house", "access", "40"], "alice", {"dns": "allow", "ntp": "allow"},
                           caller="alice")
check("positive: POST /v1/networks/<site>/access/<network>: the whole row written as the signed-in person, applied",
      [c for c in calls if c[0] == "write"] and calls[0] == ("check", "alice", "networks:plan")
      and APPLIED == ["house"] and out["result"]["row"]["dns"] == "allow"
      and out["result"]["row"]["dhcp"] == "deny", (calls, out))
del APPLIED[:]
calls.clear()
# covers: agent:post.networks.*.access.* -
check("negative: refused: an unknown network: nothing written or applied",
      refused(lambda: m_post.post_networks(["networks", "house", "access", "99"], "alice", {"dns": "allow"}, "alice"),
              "network '99'") is True and not APPLIED and not [c for c in calls if c[0] == "write"], calls)
check("negative: the agent never takes force: the host's VLAN cut off from the console is refused",
      refused(lambda: m_post.post_networks(["networks", "house", "access", "10"], "alice",
                                           {"dns": "allow", "force": "on"}, "alice"), "without ssh") is True)
try:
    m_post.post_networks(["networks", "house", "rules"], "alice", {"from": "40", "service": "ntp"}, "alice")
    gone = False
except RouteNotFound:
    gone = True
check("negative: the old rules routes are gone (no such route)", gone and not APPLIED)
check("negative: a VLAN's access is refused from the console (2.1.10.58)",
      refused(lambda: m_post.post_networks(["networks", "house", "vlans"], "alice",
                                           {"id": "70", "name": "x", "access": "guest"}, "alice"),
              "no longer set") is True)
check("positive: the access route needs dhcp:write", required_permission("POST", ["networks", "house", "access", "40"])
      == "dhcp:write")
check("positive: a held access change in a sentence",
      describe_networks(["networks", "house", "access", "40"], {"dns": "allow", "ntp": "allow"})
      == "Let VLAN 40 reach dns, ntp at house"
      and describe_networks(["networks", "house", "access", "any"], {}) == "Let outside addresses reach nothing at house"
      and describe_networks(["networks", "house", "access", "fabric"], {"ad": "allow"})
      == "Let the other sites reach ad at house")

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
