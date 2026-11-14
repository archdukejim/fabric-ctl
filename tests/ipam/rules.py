#!/usr/bin/env python3
"""The `ipam` suite, a site's access rules with no container (decisions 2.1.10.53 to 2.1.10.60, manual 1.10.4.48):
first match and the implied deny; the host's VLAN, a VLAN with two subnets and `any` (the site's networks only); an
upgraded site's rules (2.1.10.59); the lockout guard and --force (2.1.10.57); the warnings and the listing; Kea left
silent for a VLAN not allowed dhcp; what the firewall (ufw, DOCKER-USER), ping (ufw's before.rules) and the templates
(BIND's and the resolver's blackhole, nginx's 444) are built from; one change made the way every command makes it
(the grant first, the whole list written, nothing on a refusal); `fabricctl ipam rule` and the agent's routes, each
both ways. A denied network getting no packet back from the real services: the sandbox (tests/lab).

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
import fabriclib.ipam.rules.change_rules as m_rules  # noqa: E402
import fabriclib.ipam.run_ipam_command as m_cmd  # noqa: E402
import fabriclib.undo.undo_firewall as m_undo  # noqa: E402
from agent.pending_networks import describe_networks  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.ipam.rules.add_rule import add_rule  # noqa: E402
from fabriclib.ipam.rules.check_cut_off import check_cut_off  # noqa: E402
from fabriclib.ipam.rules.dhcp_allowed import dhcp_allowed  # noqa: E402
from fabriclib.ipam.rules.effective_rules import effective_rules  # noqa: E402
from fabriclib.ipam.rules.move_rule import move_rule  # noqa: E402
from fabriclib.ipam.rules.remove_rule import remove_rule  # noqa: E402
from fabriclib.ipam.rules.rule_networks import rule_networks  # noqa: E402
from fabriclib.ipam.rules.rule_warnings import rule_warnings  # noqa: E402
from fabriclib.ipam.rules.seed_rules import seed_rules  # noqa: E402
from fabriclib.ipam.rules.service_sources import service_sources  # noqa: E402
from fabriclib.ipam.rules.show_rules import show_rules  # noqa: E402
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


def rule(src, service, action="allow"):
    return {"from": src, "service": service, "action": action}


def vlan(i, access="full"):
    return {"id": i, "location": "", "name": f"v{i}", "access": access}


def subnet(cidr, i, dhcp=True):
    return {"cidr": cidr, "vlan": i, "location": "", "dhcp": dhcp}


V = {"site_name": "house", "dc_name": "dc-0001", "host_ip": "10.1.10.5", "lan_cidr": "10.1.10.0/24",
     "fabric_subnet": "10.255.0.0/24"}
SIX = {"site": "house", "vlans": [vlan(10), vlan(20), vlan(30), vlan(40, "guest"), vlan(50), vlan(60)],
       "subnets": [subnet("10.1.10.0/24", 10), subnet("10.1.20.0/24", 20), subnet("10.1.21.0/24", 20),
                   subnet("10.1.30.0/24", 30, dhcp=False), subnet("10.1.40.0/24", 40), subnet("10.1.50.0/24", 50)],
       "networks": [], "rules_kept": True,
       "rules": [rule("host", "any"), rule("20", "dns"), rule("20", "dhcp"), rule("20", "web"),
                 rule("30", "ntp", "deny"), rule("any", "ntp"), rule("50", "dhcp")]}

print("--- the model (1.10.4.48.1)")
fresh = {"site": "house", "vlans": [], "subnets": [], "networks": [], "rules": [], "rules_kept": False}
src = service_sources(V, fresh)
check("positive: a fresh site: only the host's VLAN (lan_cidr) reaches every service",
      all(nets == ["10.1.10.0/24"] for nets in src.values()) and len(src) == 8, src)
src = service_sources(V, SIX)
check("positive: six VLANs: each service answers only the networks a rule allows, the host's first",
      src["dns"] == ["10.1.10.0/24", "10.1.20.0/24", "10.1.21.0/24"]
      and src["dhcp"] == ["10.1.10.0/24", "10.1.20.0/24", "10.1.21.0/24", "10.1.50.0/24"]
      and src["ssh"] == ["10.1.10.0/24"] and src["web"] == ["10.1.10.0/24", "10.1.20.0/24", "10.1.21.0/24"], src)
check("positive: a VLAN with two subnets: a rule naming it covers both", "10.1.21.0/24" in src["dns"], src)
check("positive: first match: VLAN 30's ntp deny comes before `any ntp allow`, which still reaches 40 and 50",
      "10.1.30.0/24" not in src["ntp"] and {"10.1.40.0/24", "10.1.50.0/24"} <= set(src["ntp"]), src["ntp"])
check("negative: the implied deny: a VLAN no rule names (60, no subnet; 40 for dns) reaches nothing of it",
      "10.1.40.0/24" not in src["dns"] and "10.1.40.0/24" not in src["ping"], src)
everything = service_sources(V, {**SIX, "rules": [rule("any", "any")]})
check("negative: `any` is the site's networks only, never every address (2.1.10.60)",
      "0.0.0.0/0" not in everything["dns"] and len(everything["dns"]) == 6, everything["dns"])
nets = rule_networks({**V, "host_ip": "192.168.9.9"}, SIX)
check("positive: no VLAN holds host_ip: `host` is lan_cidr", nets["host"] == ["10.1.10.0/24"]
      and nets["host_vlan"] is None, nets)
check("positive: the VLAN that holds host_ip is `host`", rule_networks(V, SIX)["host_vlan"] == "10", nets)

print("--- an upgraded site (1.10.4.48.7, 2.1.10.59)")
seed = seed_rules({**SIX, "rules_kept": False}, "10")
check("positive: the host's VLAN everything (rule 1), a guest VLAN dhcp, dns and ntp, a full served VLAN all but ssh",
      seed[0] == rule("host", "any") and rule("40", "dns") in seed and rule("40", "ntp") in seed
      and rule("40", "dhcp") in seed
      and rule("40", "web") not in seed and rule("50", "web") in seed and rule("50", "ssh") not in seed, seed)
check("negative: a VLAN without a served subnet (30) and the host's own (10) get no rule of their own",
      not [r for r in seed if r["from"] in ("30", "60", "10")], seed)
check("positive: rules kept are enforced as kept", effective_rules(SIX) == SIX["rules"])
check("positive: none kept: the seed is enforced until written", effective_rules({**SIX, "rules_kept": False})
      == seed_rules({**SIX, "rules_kept": False}))
check("negative: a fresh site gets the one default rule, nothing seeded", effective_rules(fresh) == [rule("host", "any")])

print("--- the guard, the warnings, the listing (1.10.4.48.5, 1.10.4.48.6)")
nets = rule_networks(V, SIX)
check("positive: the host's VLAN keeps ssh and web: no cut-off", check_cut_off(SIX["rules"], nets) is None)
cut = check_cut_off([rule("10", "ssh", "deny"), *SIX["rules"]], nets)
check("negative: a deny of the host's VLAN's ssh before its allow is a cut-off, naming the rule",
      cut and "without ssh (rule 1 denies it)" in cut and "--force" in cut, cut)
cut = check_cut_off([rule("20", "any")], nets)
check("negative: no rule left allowing the host's VLAN: the implied deny cuts it off", cut and "no rule allows" in cut,
      cut)
warn = rule_warnings([*SIX["rules"], rule("60", "dns"), rule("20", "dns", "deny")], nets)
check("positive: warned: VLAN 50 has dhcp but not dns; VLAN 30 reaches nothing (its ntp denied before `any ntp`)",
      any("VLAN 50 gets DHCP" in w for w in warn) and any("VLAN 30 reaches none" in w for w in warn), warn)
check("negative: not warned: VLAN 40 reaches ntp through `any ntp allow`", not any("VLAN 40" in w for w in warn), warn)
check("positive: warned: a rule whose VLAN has no subnet, a rule that never decides",
      any("rule 8 (from 60) matches no network" in w for w in warn)
      and any("rule 9 never decides" in w for w in warn), warn)
lines = show_rules(SIX["rules"], nets)
check("positive: the listing: numbered, the source's networks, the ports, the implied deny last",
      lines[0].startswith("1  from host (10.1.10.0/24)") and "53/udp" in lines[1]
      and lines[-1].startswith("*  from any") and "implied" in lines[-1], lines)

print("--- Kea (1.10.4.48.3: no subnet selected, nothing said)")
kea = [{"subnet": "10.1.10.0/24"}, {"subnet": "10.1.40.0/24"}, {"subnet": "10.1.50.0/24"}]
check("positive: Kea serves the subnets allowed dhcp", dhcp_allowed(kea, V, SIX) == [kea[0], kea[2]])
check("negative: a VLAN not allowed dhcp (40) is left out of Kea", {"subnet": "10.1.40.0/24"}
      not in dhcp_allowed(kea, V, SIX))

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

print("--- one change, the way every command makes it (1.10.4.48.5)")
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
m_rules.write_audit = lambda actor, event, detail, source: calls.append(("audit", event, detail, source))
SEC = {"ad_agent_password": "x"}
out = add_rule(V, "root", "40", "dns", "allow", at="2", secrets=SEC)
written = [c for c in calls if c[0] == "write"]
check("positive: add: the grant first, the whole list written as one change, rule 2 the new one, audited",
      calls[0] == ("check", None, "networks:plan") and written[0][1][0]["what"] == "rules"
      and written[0][1][0]["fields"]["rules"][1] == rule("40", "dns")
      and len(written[0][1][0]["fields"]["rules"]) == 8 and calls[-1][1] == "IPAM_RULE_ADD", calls)
for name, fn, words in (
        ("an unknown service", lambda: add_rule(V, "root", "20", "smtp", "allow", secrets=SEC), "service 'smtp'"),
        ("a VLAN the site has not", lambda: add_rule(V, "root", "70", "dns", "allow", secrets=SEC), "no VLAN 70"),
        ("an action that is not one", lambda: add_rule(V, "root", "20", "dns", "maybe", secrets=SEC), "allow or deny"),
        ("a rule twice", lambda: add_rule(V, "root", "20", "dns", "allow", secrets=SEC), "already in the list"),
        ("a position out of range", lambda: add_rule(V, "root", "20", "ntp", "allow", at="99", secrets=SEC),
         "1 to 8"),
        ("the host's VLAN cut off", lambda: add_rule(V, "root", "host", "ssh", "deny", at="1", secrets=SEC),
         "without ssh"),
        ("--force from the console", lambda: add_rule(V, "nina", "host", "ssh", "deny", at="1", force=True,
                                                      secrets=SEC, source="web", caller="nina"),
         "only on the command line"),
        ("a number that is no rule", lambda: remove_rule(V, "root", "12", secrets=SEC), "numbered 1 to 7"),
        ("a move onto itself", lambda: move_rule(V, "root", "2", "2", secrets=SEC), "nothing to change")):
    calls.clear()
    check(f"negative: refused, nothing written: {name}", refused(fn, words) is True
          and not [c for c in calls if c[0] == "write"], (refused(fn, words), calls))
calls.clear()
out = add_rule(V, "root", "host", "ssh", "deny", at="1", force=True, secrets=SEC)
check("positive: --force on the command line, as root: written, and audited IPAM_RULE_FORCED",
      out["result"]["forced"] and [c[1] for c in calls if c[0] == "audit"] == ["IPAM_RULE_ADD", "IPAM_RULE_FORCED"],
      calls)
calls.clear()
out = move_rule(V, "root", "7", "2", secrets=SEC)
check("positive: move: rule 7 becomes rule 2", out["result"]["rules"][1] == rule("50", "dhcp"), out["result"])
out = remove_rule(V, "root", "7", secrets=SEC)
check("positive: remove: the rule gone, the rest kept in order", len(out["result"]["rules"]) == 6
      and rule("50", "dhcp") not in out["result"]["rules"], out["result"])
out = add_rule(V, "root", "any", "dns", "allow", site="cabin", secrets=SEC)
check("positive: another site's rules: its own list (the default first), judged by host and any alone",
      out["site"] == "cabin" and out["result"]["rules"] == [rule("host", "any"), rule("any", "dns")], out["result"])

print("--- fabricctl ipam rule (1.10.4.48.5)")
m_read.read_plan = lambda v, secrets, of, container: READ
m_change.report_change = lambda v, out, bare: 0


def cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = m_cmd.run_ipam_command(V, argv, secrets=SEC, container="none")
    return code, out.getvalue() + err.getvalue()


# covers: cli:ipam.rule +
code, text = cli(["rule"])
check("positive: `ipam rule` lists the rules with their ports and the implied deny", code == 0
      and "from host (10.1.10.0/24)" in text and "* " in text and "implied" in text, text)
code, text = cli(["rule", "add", "40", "ntp", "allow"])
check("positive: `ipam rule add` says what it did and the list after", code == 0 and "added as rule 8" in text
      and "  * from any service any deny" in text, text)
# covers: cli:ipam.rule -
code, text = cli(["rule", "add", "40", "telnet", "allow"])
check("negative: `ipam rule add` with an unknown service: refused, exit 1", code == 1 and "service 'telnet'" in text,
      text)
code, text = cli(["rule", "add", "40"])
check("negative: `ipam rule add` without service and action: usage, exit 2", code == 2 and "usage:" in text, text)
code, text = cli(["rule", "add", "host", "web", "deny", "--at", "1"])
check("negative: `ipam rule add` cutting the host's VLAN off the console: refused, naming --force", code == 1
      and "without web" in text and "--force" in text, text)
code, text = cli(["vlan", "add", "70", "--name", "x", "--access", "guest"])
check("negative: --access is no longer taken (2.1.10.58), naming ipam rule", code == 1
      and "fabricctl ipam rule" in text, text)

print("--- the agent's routes (1.10.4.48.5)")
APPLIED = []
m_post.load_vars = lambda: V
m_edit.load_secrets = lambda: SEC
m_post.apply_plan_change = lambda v, actor, out, apply=True: APPLIED.append(out["site"]) or {**out, "own": True}
ROUTES = [(["rules"], {"from": "40", "service": "ntp", "action": "allow"}, {"from": "40", "service": "x"}, "service"),
          (["rules", "3", "delete"], {}, {}, None),
          (["rules", "2", "move"], {"to": "1"}, {"to": "77"}, "numbered 1 to")]
for sub, body, bad, words in ROUTES:
    del APPLIED[:]
    calls.clear()
    # covers: agent:post.networks.*.rules agent:post.networks.*.rules.*.delete agent:post.networks.*.rules.*.move +
    out = m_post.post_networks(["networks", "house", *sub], "alice", body, caller="alice")
    check(f"positive: POST /v1/networks/<site>/{'/'.join(sub)}: written as the signed-in person, source web, applied",
          [c for c in calls if c[0] == "write"] and calls[0] == ("check", "alice", "networks:plan")
          and APPLIED == ["house"], calls)
    del APPLIED[:]
    calls.clear()
    bad_sub = ["rules", "99", sub[2]] if len(sub) == 3 else sub
    # covers: agent:post.networks.*.rules agent:post.networks.*.rules.*.delete agent:post.networks.*.rules.*.move -
    check(f"negative: refused: POST /v1/networks/<site>/{'/'.join(sub)}: nothing written or applied",
          refused(lambda: m_post.post_networks(["networks", "house", *bad_sub], "alice", bad, "alice"),
                  words or "numbered 1 to") is True and not APPLIED
          and not [c for c in calls if c[0] == "write"], calls)
check("negative: the agent never takes force: a cut-off from the console is refused",
      refused(lambda: m_post.post_networks(["networks", "house", "rules"], "alice",
                                           {"from": "host", "service": "ssh", "action": "deny", "at": "1",
                                            "force": "on"}, "alice"), "without ssh") is True)
check("negative: a VLAN's access is refused from the console (2.1.10.58)",
      refused(lambda: m_post.post_networks(["networks", "house", "vlans"], "alice",
                                           {"id": "70", "name": "x", "access": "guest"}, "alice"),
              "no longer set") is True)
check("positive: each rule route needs dhcp:write", all(required_permission("POST", r) == "dhcp:write" for r in (
    ["networks", "house", "rules"], ["networks", "house", "rules", "2", "delete"],
    ["networks", "house", "rules", "2", "move"])))
check("positive: a held rule change in a sentence",
      describe_networks(["networks", "house", "rules"], {"from": "40", "service": "ntp", "action": "allow"})
      == "Add access rule from 40 service ntp allow at house"
      and describe_networks(["networks", "house", "rules", "3", "move"], {"to": "1"})
      == "Move access rule 3 to 1 at house")

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
