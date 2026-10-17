"""Asking before fabric changes the host (manual 1.2.9): the recorded answers, the questions setup asks
(unattended and interactive), what steps may do with them, the account plan with its move from the previous
accounts, and the upgrade of an older install's settings. No containers and nothing changed on this host: the
answers live in a scratch folder and the account checks read (or stand in for) the host's accounts."""
import builtins
import contextlib
import io
import os
import sys
import tempfile

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.common.keep_original import keep_original  # noqa: E402
from fabriclib.common.restore_original import restore_original  # noqa: E402
from fabriclib.consent import plan_accounts as pa  # noqa: E402
from fabriclib.consent.allowed_to_change import allowed_to_change  # noqa: E402
from fabriclib.consent.ask_consent import ask_consent  # noqa: E402
from fabriclib.consent.check_consent import check_consent  # noqa: E402
from fabriclib.consent.consent_status import consent_status  # noqa: E402
from fabriclib.consent.plan_firewall import plan_firewall  # noqa: E402
from fabriclib.consent.plan_own_rules import plan_own_rules  # noqa: E402
from fabriclib.consent.plan_ports import plan_ports  # noqa: E402
from fabriclib.consent.groups import GROUPS  # noqa: E402
import fabriclib.consent.ask_consent as ask_consent_mod  # noqa: E402
from fabriclib.deploy.render_vars import render_vars  # noqa: E402
from fabriclib.security.ufw_rule import ufw_rule  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402
from fabriclib.setup.upgrade_vars import upgrade_vars  # noqa: E402
from fabriclib.undo import undo_runtime as ur  # noqa: E402
from fabriclib.undo.undo_group import undo_group  # noqa: E402
from fabriclib.undo.uninstall_plan import uninstall_plan  # noqa: E402

FAILED = 0
JINJA = os.path.join(REPO, "templates")


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def refused(fn):
    """The SetupError message fn raises, or "" when it does not raise."""
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            fn()
    except SetupError as e:
        return str(e)
    return ""


cfg = tempfile.mkdtemp()
PLAN = {"packages": ["apt: install docker.io"], "accounts": ["create user fabric-dns (uid 600, gid 600)"],
        "firewall": ["ufw: allow 22/tcp (SSH) from 10.0.0.0/24"]}

print("--- before anything was asked")
check("an install set up before consent existed keeps converging (apply, timers), setup does not",
      allowed_to_change(cfg, "time", ["x"], unasked_install=True) and not allowed_to_change(cfg, "time", ["x"]))
check("nothing to change is always allowed", allowed_to_change(cfg, "firewall", []))

print("--- unattended")
msg = refused(lambda: ask_consent(cfg, PLAN, interactive=False))
check("--non-interactive without --approve stops and names every group to answer",
      "need an answer: packages, accounts, firewall" in msg and "--approve" in msg, msg)
check("... and approves nothing", not allowed_to_change(cfg, "packages", PLAN["packages"]))
check("an unknown group name is refused",
      "unknown host-change group" in refused(lambda: ask_consent(cfg, PLAN, False, approve=["firewal"])))
with contextlib.redirect_stdout(io.StringIO()):
    ask_consent(cfg, PLAN, interactive=False, approve=["all"])
check("--approve all: every planned change is allowed",
      all(allowed_to_change(cfg, g, c) for g, c in PLAN.items()))
check("a change that was not part of the approval is not allowed (subset rule)",
      not allowed_to_change(cfg, "firewall", PLAN["firewall"] + ["ufw: allow 22/tcp (SSH) from 0.0.0.0/0"]))
check("a re-run with the same plan asks nothing (unattended, no --approve)",
      refused(lambda: ask_consent(cfg, PLAN, interactive=False)) == "")
more = dict(PLAN, firewall=PLAN["firewall"] + ["ufw: allow 123/udp (NTP) from 10.0.0.0/24"])
msg = refused(lambda: ask_consent(cfg, more, interactive=False))
check("a new firewall rule asks again — about the firewall only", "need an answer: firewall" in msg, msg)
with contextlib.redirect_stdout(io.StringIO()):
    ask_consent(cfg, more, interactive=False, approve=["firewall"])
check("an approval keeps what was approved before: a run that changes less still matches",
      allowed_to_change(cfg, "firewall", PLAN["firewall"]) and allowed_to_change(cfg, "firewall", more["firewall"]))
saved = yaml.safe_load(open(os.path.join(cfg, "consent.yaml")))["groups"]["firewall"]
check("consent.yaml records the answer, the changes, when and who; it is root-only (0600)",
      saved["answer"] == "yes" and saved["when"] and saved["by"]
      and oct(os.stat(os.path.join(cfg, "consent.yaml")).st_mode & 0o777) == "0o600", saved)

print("--- declining")
with contextlib.redirect_stdout(io.StringIO()):
    ask_consent(cfg, more, interactive=False, decline=["firewall"])
out = io.StringIO()
with contextlib.redirect_stdout(out):
    went_ahead = check_consent(cfg, "firewall", more["firewall"])
check("a declined recommended group: the step leaves the host as it is and says what that means",
      went_ahead is False and "not approved" in out.getvalue(), out.getvalue())
row = next(r for r in consent_status(cfg) if r["group"] == "firewall")
check("status shows it declined, with the relaxation", row["state"] == "declined" and "reachable" in row["relaxation"],
      row)
msg = refused(lambda: ask_consent(cfg, PLAN, interactive=False, decline=["accounts"]))
check("declining a required group stops setup and says why", "Service accounts declined" in msg, msg)
check("... and a step of a required group refuses on its own too",
      "not approved" in refused(lambda: check_consent(cfg, "accounts", PLAN["accounts"])))

print("--- interactive without a plan (a --step run, or --yes): one question for every change that needs one")
cfg2 = tempfile.mkdtemp()
answers = iter(["", "maybe", "y"])
real_input = builtins.input
builtins.input = lambda prompt="": next(answers)
try:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        got = ask_consent(cfg2, {"packages": PLAN["packages"], "runtime": ["restart Docker"]}, interactive=True)
finally:
    builtins.input = real_input
# covers: ask:consent.step +-
check("every group listed with its changes and what no means, one question for all; no default answer: Enter and "
      "'maybe' asked again", got == {"packages": "yes", "runtime": "yes"} and out.getvalue().count("If no:") == 2
      and out.getvalue().count("Allow these changes?") == 0 and "apt: install docker.io" in out.getvalue()
      and next(answers, None) is None, got)
builtins.input = lambda prompt="": "n"
msg = refused(lambda: ask_consent(tempfile.mkdtemp(), {"packages": PLAN["packages"], "runtime": ["x"]},
                                  interactive=True))
builtins.input = real_input
check("negative: no to the one question declines them all, and a required one stops setup naming it",
      "Packages declined" in msg, msg)

print("--- the plan's Proceed (decided): the one yes for every host change listed (1.2.9.11.4, 2.1.2.18)")
cfg3 = tempfile.mkdtemp()
builtins.input = lambda prompt="": (_ for _ in ()).throw(AssertionError("asked"))
plan3 = {"packages": ["apt: install x"], "runtime": ["restart Docker"], "ports": ["p"], "firewall": ["f"],
         "own_rules": ["o"]}
with contextlib.redirect_stdout(io.StringIO()):
    got = ask_consent(cfg3, plan3, interactive=True, decided={"packages": True, "runtime": False, "ports": True,
                                                              "firewall": False, "own_rules": False})
builtins.input = real_input
rec3 = yaml.safe_load(open(os.path.join(cfg3, "consent.yaml")))["groups"]
check("Proceed records every group as the consent file always did, nothing asked: allowed ones yes, those turned off "
      "in the menu no (a relaxation), what needs a declined one skipped",
      got == {"packages": "yes", "runtime": "no", "ports": "yes", "firewall": "no", "own_rules": "skipped"}
      and rec3["packages"]["answer"] == "yes" and rec3["runtime"]["answer"] == "no" and "own_rules" not in rec3, got)
row = next(r for r in consent_status(cfg3) if r["group"] == "runtime")
check("…and status shows the one turned off as declined, with its relaxation", row["state"] == "declined", row)
plan3b = dict(plan3, packages=["apt: install x", "apt: install y"])
with contextlib.redirect_stdout(io.StringIO()):
    got = ask_consent(cfg3, plan3b, interactive=True, decided={g: True for g in plan3b})
check("an upgrade that adds a change: Proceed approves the changed group with its new line (the old kept)",
      got["packages"] == "yes" and allowed_to_change(cfg3, "packages", plan3b["packages"]), got)
msg = refused(lambda: ask_consent(cfg3, {"packages": ["apt: install z"]}, interactive=False))
check("…and unattended, a changed group still needs --approve, named", "need an answer: packages" in msg, msg)

print("--- service accounts")
v = yaml.safe_load(jinja_env(JINJA).get_template("vars.yaml.j2").render(
    domain="lan.test", hostname="h", host_ip="10.0.0.5", lan_cidr="10.0.0.0/24", lan_gateway="10.0.0.1"))
users = v["service_users"]
check("defaults: fabric-* names in the 600-649 band (bind -> fabric-dns 600, Keycloak keeps gid 0)",
      users["bind"] == {"uid": 600, "gid": 600, "name": "fabric-dns"} and users["keycloak"]["gid"] == 0
      and all(600 <= u["uid"] <= 649 and u["name"].startswith("fabric-") for u in users.values()), users)
msg = refused(lambda: pa.plan_accounts({"service_users": {"bind": {"uid": 1, "gid": 1, "name": "fabric-dns"}}},
                                       "/nonexistent", JINJA))
check("an id taken by another account stops setup, naming both (fabric never takes one over)",
      "is taken by" in msg and "service_users.bind" in msg, msg)
fake = {"bind": 53, "fabric-dns": None}
saved_fns = (pa._user_uid, pa._group_gid, pa._uid_owner, pa._gid_owner, pa._fabric_dirs)
pa._user_uid = lambda n: fake.get(n)
pa._group_gid = lambda n: 53 if n == "bind" else None
pa._uid_owner = pa._gid_owner = lambda i: "bind" if i == 53 else None
pa._fabric_dirs = lambda base, j: ["/opt/bind9", "/opt/fabric"]
try:
    acts = pa.plan_accounts({"service_users": {"bind": users["bind"]}}, "/opt", JINJA)
finally:
    pa._user_uid, pa._group_gid, pa._uid_owner, pa._gid_owner, pa._fabric_dirs = saved_fns
check("an install with the previous bind (53) account: create fabric-dns, move its files, remove bind",
      [a["do"] for a in acts] == ["group", "user", "move", "remove"]
      and acts[2]["uid"] == (53, 600) and acts[2]["gid"] == (53, 600) and acts[3]["name"] == "bind", acts)

print("--- upgrading an older install's settings")
old = {"service_users": {"bind": {"uid": 53, "gid": 53}, "nginx": {"uid": 1443, "gid": 1443}}}
changes = upgrade_vars(old, set())
check("previous defaults are dropped (the new accounts apply), an admin's own ids are kept",
      old["service_users"] == {"nginx": {"uid": 1443, "gid": 1443}} and len(changes) == 1, (old, changes))
# certs.<domain> dropped (1.5.1.5): its keys and the default CNAME go; an admin's other records stay
old = {"hostname": "fab", "cname_certs": "certs", "hostname_certs": "certs.lan.test",
       "dns": {"dynamic_zone_var": {"CNAME": [{"canonical": "fab", "name": "certs"}, {"canonical": "fab", "name": "ca"},
                                             {"canonical": "nas", "name": "certs2"}]}}}
changes = [c for c in upgrade_vars(old, set()) if "certs" in c]
check("a vars file without dc_name is not given one at the upgrade (keep_old_install deleted 2026-10-13, S10): the "
      "template's dc-0001 applies", "dc_name" not in old, old)
check("an older install's certs.<domain>: cname_certs, hostname_certs and its CNAME removed, other CNAMEs kept",
      "cname_certs" not in old and "hostname_certs" not in old and len(changes) == 2
      and [r["name"] for r in old["dns"]["dynamic_zone_var"]["CNAME"]] == ["ca", "certs2"], (old, changes))
old = {"hostname": "fab", "dns": {"dynamic_zone_var": {"CNAME": [{"canonical": "elsewhere", "name": "certs"}]}}}
changes = [c for c in upgrade_vars(old, set()) if "certs" in c]
check("…but a certs record the admin pointed elsewhere is not the old default: kept, nothing reported",
      old["dns"]["dynamic_zone_var"]["CNAME"] == [{"canonical": "elsewhere", "name": "certs"}] and changes == [],
      (old, changes))

print("--- the firewall's questions (2.1.2.13): the ports fabric needs, then securing, then the host's own rules")
rules = plan_firewall({**v, "ntp_serve": False}, cfg, active=False)
check("securing: the default policy, SSH, the DOCKER-USER limit — and no fabric port (those are the first question)",
      rules[0].startswith("ufw: deny incoming") and "ufw: allow 22/tcp (SSH) from 10.0.0.0/24" in rules
      and rules[-1].startswith("iptables DOCKER-USER") and not any("domain controller" in x for x in rules), rules)
on = plan_firewall({**v, "ntp_serve": False}, cfg, active=True)
check("ufw on already: the first line says so, the rest the same",
      on[0].startswith("ufw is on already: deny incoming") and on[1:] == rules[1:], on[:2])
check("the three questions in order; securing needs the ports, the host's own rules need securing",
      list(GROUPS).index("ports") < list(GROUPS).index("firewall") < list(GROUPS).index("own_rules")
      and GROUPS["firewall"]["needs"] == "ports" and GROUPS["own_rules"]["needs"] == "firewall")
with contextlib.redirect_stdout(io.StringIO()):
    _ans = ask_consent_mod.ask_consent(os.path.join(cfg, "needs"), {"ports": ["p"], "firewall": ["f"], "own_rules": ["o"]},
                                       interactive=False, decline=["ports"])
check("the ports declined: securing and the host's own rules are not made (skipped, nothing recorded)",
      _ans == {"ports": "no", "firewall": "skipped", "own_rules": "skipped"}, _ans)
_seen = []
builtins.input = lambda prompt="": (_seen.append(prompt), "y")[1]
with contextlib.redirect_stdout(io.StringIO()) as _out:
    _ans = ask_consent_mod.ask_consent(os.path.join(cfg, "needs"), {"ports": ["p"], "firewall": ["f"], "own_rules": ["o"]},
                                       interactive=True, stops={"ports"})
builtins.input = real_input
check("a declined change that stops setup is asked again in the next interactive run without a plan (never stuck "
      "with the no): the one question, its yes taking what needs it along",
      len(_seen) == 1 and "(Firewall) Open the ports fabric needs?" in _out.getvalue() and _ans.get("ports") == "yes"
      and _ans.get("firewall") == "yes", (_seen, _ans))
_ans = ask_consent_mod.ask_consent(os.path.join(cfg, "needs"), {"ports": ["p"]}, interactive=False, stops={"ports"})
check("…and unattended, the recorded answer stands (no question without a person)", _ans.get("ports") == "yes", _ans)
fake = os.path.join(cfg, "fakebin")
os.makedirs(fake, exist_ok=True)
with open(os.path.join(fake, "ufw"), "w") as f:
    f.write("\n".join(["#!/bin/sh", "echo \"Added user rules (see 'ufw status' for running firewall):\"",
                       "echo 'ufw allow from 10.0.0.0/24 to any port 9090 proto tcp'", "echo 'ufw allow OpenSSH'",
                       "echo 'ufw allow from 10.0.0.0/24 to any port 22 proto tcp'", ""]))
os.chmod(os.path.join(fake, "ufw"), 0o755)
os.environ["PATH"] = fake + os.pathsep + os.environ["PATH"]
own = plan_own_rules({**v, "ntp_serve": False}, cfg)
check("the host's own rules: ufw's added rules less fabric's (SSH from the LAN is fabric's), each named",
      own == ["ufw: remove `ufw allow from 10.0.0.0/24 to any port 9090 proto tcp` (the host's own)",
              "ufw: remove `ufw allow OpenSSH` (the host's own)"], own)
os.environ["PATH"] = os.environ["PATH"].split(os.pathsep, 1)[1]
_orig = os.path.join(cfg, "host-originals")
os.makedirs(_orig, exist_ok=True)
with open(os.path.join(_orig, "ufw.state"), "w") as f:
    f.write("active\n")
check("the wording follows ufw as it was before fabric (its record), so it does not change once fabric turns it on",
      plan_firewall({**v, "ntp_serve": False}, cfg)[0].startswith("ufw is on already"))
os.remove(os.path.join(_orig, "ufw.state"))
# covers: setting:security +
check("security.firewall false asks nothing", plan_firewall({**v, "security": {"firewall": False}}, cfg) == [])
dc_rules = plan_ports({**v, "ntp_serve": False, "ad_rpc_ports": "49152-49251"}, cfg)
dc_lines = [r for r in dc_rules if "domain controller" in r]
# covers: setting:ad_rpc_ports +
check("the DC's TCP ports (RPC range included) and UDP ports, from the LAN and fabric_net",
      f"ufw: allow 88,135,389,445,464,636,3268,3269,49152:49251/tcp (the Windows domain controller) from "
      f"{v['lan_cidr']}" in dc_lines
      and f"ufw: allow 88,389,464/udp (the Windows domain controller) from {v['fabric_subnet']}" in dc_lines
      and len(dc_lines) == 4, dc_lines)
peer_cfg = tempfile.mkdtemp()
with open(os.path.join(peer_cfg, "federation.yaml"), "w") as f:
    yaml.safe_dump({"upstream": {"site_name": "lan", "address": "192.0.2.10"},
                    "sites": {"edge": {"address": "198.51.100.7"}}}, f)
peer_lines = [r for r in plan_ports({**v, "ntp_serve": False}, peer_cfg) if "domain controller" in r]
check("the DC's ports also from the federation's peers (its upstream and each joined site: replication, 1.9.8.5)",
      any("from 192.0.2.10/32" in r and "/tcp" in r for r in peer_lines)
      and any("from 198.51.100.7/32" in r and "/udp" in r for r in peer_lines) and len(peer_lines) == 8, peer_lines)
check("the DC's ufw rule round-trips through its record form",
      ufw_rule("ad", "tcp@10.0.0.0/24@88,445") == ["from", "10.0.0.0/24", "to", "any", "port", "88,445", "proto", "tcp"])
check("SSH's rule carries sshd's port; a record from before names the network only and means port 22",
      ufw_rule("ssh", "10.0.0.0/24@2222") == ["from", "10.0.0.0/24", "to", "any", "port", "2222", "proto", "tcp"]
      and ufw_rule("ssh", "10.0.0.0/24") == ["from", "10.0.0.0/24", "to", "any", "port", "22", "proto", "tcp"])
import fabriclib.security.ssh_ports as m_ports  # noqa: E402
_real_run = m_ports.subprocess.run
m_ports.subprocess.run = lambda *a, **k: type("R", (), {"stdout": "port 2222\nport 22\nlistenaddress 0.0.0.0:2222\n"})()
two = m_ports.ssh_ports()
m_ports.subprocess.run = lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError("sshd"))
none = m_ports.ssh_ports()
m_ports.subprocess.run = _real_run
check("the ports sshd listens on are read from `sshd -T` (both of two); without sshd, 22", two == [22, 2222]
      and none == [22], (two, none))
final, _ = render_vars(jinja_env(JINJA), {}, {"domain": "lan.test", "hostname": "h", "host_ip": "10.0.0.5",
                                              "lan_cidr": "10.0.0.0/24", "lan_gateway": "10.0.0.1"})
check("the settings render without secrets (a fresh install plans before anything exists)",
      final["service_users"]["bind"]["uid"] == 600)

print("--- undoing a host change (setup --undo, uninstall)")
host = tempfile.mkdtemp()                         # stands in for the host's files
orig = os.path.join(host, "etc", "app.conf")
os.makedirs(os.path.dirname(orig))
open(orig, "w").write("theirs\n")
kept = keep_original(orig, cfg)
open(orig, "w").write("# fabric: ours\n")
check("the host's file is kept once, before fabric's first change; a later change does not replace the copy",
      kept and not keep_original(orig, cfg) and restore_original(orig, cfg) == "restored"
      and open(orig).read() == "theirs\n" and restore_original(orig, cfg) is None)
new = os.path.join(host, "etc", "new.conf")
keep_original(new, cfg)
open(new, "w").write("x")
link = os.path.join(host, "etc", "resolv.conf")
os.symlink("/run/systemd/resolve/stub-resolv.conf", link)
keep_original(link, cfg)
os.remove(link)
os.symlink("/run/systemd/resolve/resolv.conf", link)
check("a file fabric added is removed again; a symlink gets its own target back",
      restore_original(new, cfg) == "removed" and not os.path.exists(new) and restore_original(link, cfg) == "restored"
      and os.readlink(link) == "/run/systemd/resolve/stub-resolv.conf")
ours = os.path.join(host, "etc", "ours.conf")
open(ours, "w").write("# fabric: rendered by fabricctl\n")
check("a file already fabric's (an install from before copies were kept) is not taken for the original",
      not keep_original(ours, cfg, marker="# fabric") and restore_original(ours, cfg) is None)
check("fabric's ufw rules: the same words add and delete them",
      ufw_rule("ssh", "10.0.0.0/24") == ["from", "10.0.0.0/24", "to", "any", "port", "22", "proto", "tcp"]
      and ufw_rule("dhcp", "eth1") == ["in", "on", "eth1", "to", "any", "port", "67", "proto", "udp"])
daemon = os.path.join(host, "daemon.json")
ur.DAEMON_JSON = daemon
open(daemon, "w").write('{"data-root": "/srv/docker", "icc": false, "no-new-privileges": true, "live-restore": false,'
                        ' "log-opts": {"max-size": "10m", "max-file": "3", "labels": "a"}}')
before = open(daemon).read()
done = ur.undo_runtime(cfg, restart=False)
check("without a kept copy only the keys still holding fabric's values leave daemon.json (an admin's value stays)",
      yaml.safe_load(open(daemon)) == {"data-root": "/srv/docker", "live-restore": False, "log-opts": {"labels": "a"}}
      and done and "no copy" in done[0], (open(daemon).read(), done))
open(daemon, "w").write(before)
keep_original(daemon, cfg)
open(daemon, "w").write('{"icc": false}')
check("with a kept copy daemon.json is put back exactly",
      ur.undo_runtime(cfg, restart=False)[0].endswith("put back as it was") and open(daemon).read() == before)


class Ctx:
    def __init__(self, config_dir, v):
        self.config_dir, self.vars = config_dir, v


fresh = tempfile.mkdtemp()
check("undo refuses the kinds fabric needs (uninstall removes those), naming the way",
      "fabricctl uninstall" in refused(lambda: undo_group(Ctx(cfg, {}), "accounts", True, True)))
# covers: setting:use_host_dns +
check("undo refuses the resolver while BIND needs port 53",
      "use_host_dns" in refused(lambda: undo_group(Ctx(cfg, {"use_host_dns": False}), "resolver", True, True)))
check("undo refuses on an install never asked (setup asks first), and an unknown group",
      "set up before" in refused(lambda: undo_group(Ctx(fresh, {}), "trust", True, True))
      and "unknown" in refused(lambda: undo_group(Ctx(cfg, {}), "bogus", True, True)))
check("undo without --yes never runs unattended",
      "--yes" in refused(lambda: undo_group(Ctx(cfg, {"domain_file": "x"}), "trust", False, False)))
print("--- an answer given before a group was split carries over (2.1.2.14; found by the upgrade test)")
split_plan = {"ports": ["ufw: allow 53/udp from 10.0.0.0/24"], "firewall": ["ufw: deny incoming (default)"],
              "own_rules": ["ufw: remove `ufw allow OpenSSH` (the host's own)"]}


def _old_install(answer):
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "consent.yaml"), "w") as f:      # 0.6.1's record: one firewall group, no ports
        yaml.safe_dump({"groups": {"firewall": {"answer": answer, "changes": ["ufw: allow 53/udp from 10.0.0.0/24"],
                                                "when": "2026-10-07T10:00:00-04:00", "by": "tempuser"}}}, f)
    return d


old_yes = _old_install("yes")
msg = refused(lambda: ask_consent(old_yes, split_plan, interactive=False))
check("0.6.1's yes to the firewall answers ports and securing; only the new question (own rules) is asked",
      "need an answer: own_rules" in msg and "ports" not in msg.split("need an answer:")[1].split(".")[0], msg)
with contextlib.redirect_stdout(io.StringIO()):
    ans = ask_consent(old_yes, split_plan, interactive=False, decline=["own_rules"])
rec = yaml.safe_load(open(os.path.join(old_yes, "consent.yaml")))["groups"]
check("…and with own_rules answered, setup goes ahead: ports and firewall yes, recorded as carried from 0.6.1's",
      ans == {"ports": "yes", "firewall": "yes", "own_rules": "no"}
      and rec["ports"]["carried_from"].startswith("firewall") and rec["ports"]["by"] == "tempuser", (ans, rec))
old_no = _old_install("no")
with contextlib.redirect_stdout(io.StringIO()):
    ans = ask_consent(old_no, split_plan, interactive=False)
check("negative: 0.6.1's no carries over as a no (nothing opened or secured, own rules not asked)",
      ans == {"ports": "no", "firewall": "skipped", "own_rules": "skipped"}, ans)
new_install = tempfile.mkdtemp()
with open(os.path.join(new_install, "consent.yaml"), "w") as f:   # after the split: firewall's no stands alone
    yaml.safe_dump({"groups": {"ports": {"answer": "yes", "changes": split_plan["ports"]},
                               "firewall": {"answer": "no", "changes": ["ufw: something else"]}}}, f)
msg = refused(lambda: ask_consent(new_install, split_plan, interactive=False))
check("negative: an install answered after the split is not touched (its changed firewall is asked again)",
      "need an answer: firewall" in msg, msg)
empty = tempfile.mkdtemp()
msg = refused(lambda: ask_consent(empty, split_plan, interactive=False))
check("negative: a fresh install has nothing to carry: every question needs an answer",
      "need an answer: ports, firewall, own_rules" in msg, msg)

rows = {t: (how, what) for t, how, what in uninstall_plan()}
check("uninstall lists every kind of host change: removed, undone or kept (Docker's settings: how to undo first)",
      len(rows) == 11 and rows["Service accounts"][0] == "removed" and rows["Secure this host"][0] == "undone"
      and rows["Ports fabric needs"][0] == rows["The host's own firewall rules"][0] == "undone"
      and rows["Docker daemon settings"][0] == "kept" and "--undo runtime" in rows["Docker daemon settings"][1], rows)

print("--- setup's plan: DHCP named a preview until 0.8.0, off by default (2.1.1.49, manual 1.10.3.9)")
import types  # noqa: E402

from fabriclib.setup.choose_plan import choose_plan  # noqa: E402


def plan_text(v):
    """setup's plan as printed, unattended (nothing asked), for these settings."""
    out = io.StringIO()
    from fabriclib.setup.context import SetupContext
    plan_ctx = SetupContext(deploy_base=os.path.join(fresh, "no-such"), vars=dict(v), non_interactive=True,
                            assume_yes=True)
    with contextlib.redirect_stdout(out):
        choose_plan(plan_ctx, lambda: (None, {}))
    return [line for line in out.getvalue().splitlines() if "DHCP" in line or "DNS filter" in line]


off, on = plan_text({"webui_admin_user": "fabric-admin"}), plan_text({"install_kea": True, "dhcp": {
    "subnets": [{"subnet": "10.0.0.0/24"}]}})
check("DHCP off by default, and named a preview until 0.8.0, off and on",
      any("off: DHCP" in line and "preview until 0.8.0" in line for line in off)
      and any("✓" in line and "preview until 0.8.0" in line and "10.0.0.0/24" in line for line in on), (off, on))
check("negative: no other part of the plan is called a preview (the DNS filter is finished)",
      not any("preview" in line for line in off + on if "DHCP" not in line), off + on)

print("--- setup's permanent questions marked ⚠ Permanent, the others not (2.1.2.20, manual 1.3.2.2)")
import builtins  # noqa: E402
import importlib  # noqa: E402

import fabriclib.common.console as m_console  # noqa: E402
from fabriclib.setup.advanced.ask_ca_lifetime import ask_ca_lifetime  # noqa: E402
from fabriclib.setup.common.ask_setting import ask_setting  # noqa: E402
import fabriclib.setup.permanent_mark as m_mark  # noqa: E402
from fabriclib.menu.constants import IMMUTABLE_KEYS  # noqa: E402
from fabriclib.setup.ask_ad_domain import ask_ad_domain  # noqa: E402
from fabriclib.setup.ask_dc_name import ask_dc_name  # noqa: E402


def prompts(fn, answers):
    """The prompts a question showed, answered with these answers (nothing else is printed)."""
    feed, real, seen = iter(answers), builtins.input, []
    builtins.input = lambda prompt="": (seen.append(prompt), next(feed))[1]
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            fn()
    finally:
        builtins.input = real
    return seen


q = types.SimpleNamespace(vars={"domain": "lan.test", "hostname": "pi", "cert_root_ca_days": 3650},
                          non_interactive=False, path=lambda *p: os.path.join(fresh, "no-such", *p))
asked = {key: prompts(lambda key=key: ask_setting(key, default), [default])[0]
         for key, default in (("domain", "lan.test"), ("friendly_name", "Home Network"), ("hostname", "pi"),
                              ("host_ip", "10.0.0.5"), ("lan_cidr", "10.0.0.0/24"), ("lan_gateway", "10.0.0.1"),
                              ("webui_admin_user", "fabric-admin"))}
asked["ad_domain"] = prompts(lambda: ask_ad_domain(q), [""])[0]
asked["dc_name"] = prompts(lambda: ask_dc_name(q), [""])[0]
# covers: ask:setup.dc_name setting:dc_name +
check("the DC's name: Enter takes the suggestion dc-0001", q.vars["dc_name"] == "dc-0001", q.vars)
q_dc = types.SimpleNamespace(vars={"hostname": "pi", "ad_domain": "ad.lan.test"}, non_interactive=False)
seen_dc = prompts(lambda: ask_dc_name(q_dc), ["dc_1", "ad", "DC-Garage"])
# covers: ask:setup.dc_name -
check("the DC's name: a name the DC cannot have (an underscore, the domain's NetBIOS name) is refused and asked again; "
      "the answer is kept in lower case", len(seen_dc) == 3 and q_dc.vars["dc_name"] == "dc-garage",
      (seen_dc, q_dc.vars))
q_host = types.SimpleNamespace(vars={"hostname": "pi", "ad_domain": "ad.lan.test"}, non_interactive=False)
out_host = io.StringIO()
with contextlib.redirect_stdout(out_host):
    feed_host = iter(["PI", "pi-dc"])
    real_in = builtins.input
    builtins.input = lambda prompt="": next(feed_host)
    try:
        ask_dc_name(q_host)
    finally:
        builtins.input = real_in
# covers: ask:setup.dc_name -
check("the DC's name: the host's own name is refused (the host joins the domain under it, 2.1.6.51), saying why, and "
      "asked again", q_host.vars["dc_name"] == "pi-dc" and "this host's own name" in out_host.getvalue(),
      (q_host.vars, out_host.getvalue()))
q_unatt = types.SimpleNamespace(vars={"hostname": "pi", "ad_domain": "ad.lan.test", "dc_name": "pi"},
                                non_interactive=True)
check("negative: unattended, a dc_name equal to the host's name is refused, saying why",
      "this host's own name" in refused(lambda: ask_dc_name(q_unatt)), q_unatt.vars)
asked["cert_root_ca_days"] = prompts(lambda: ask_ca_lifetime(q), [""])[0]
permanent = ("domain", "friendly_name", "ad_domain", "dc_name", "cert_root_ca_days")
check("each permanent question carries ⚠ Permanent after its label: the DNS domain, the organisation's name, the AD "
      "domain, the DC's name, the CA root's lifetime (Advanced)",
      all("⚠ Permanent" in asked[k] for k in permanent) and set(permanent) <= IMMUTABLE_KEYS, asked)
check("negative: none on a question that can change later: the host's name, its address, the subnet, the gateway, the "
      "first admin's name", not any("Permanent" in asked[k] for k in asked if k not in permanent), asked)
check("without a terminal the label is the same words, uncoloured",
      all("\033" not in asked[k] for k in permanent), [asked[k] for k in permanent])


class _Tty(io.StringIO):
    def isatty(self):
        return True


def mark_on_tty(no_color):
    """permanent_mark as a terminal shows it, with or without NO_COLOR (the console's colours are read at import)."""
    real_out, env = sys.stdout, {k: os.environ.get(k) for k in ("NO_COLOR", "TERM")}
    sys.stdout = _Tty()
    os.environ["TERM"] = "xterm"
    os.environ.pop("NO_COLOR", None)
    if no_color:
        os.environ["NO_COLOR"] = "1"
    try:
        importlib.reload(m_console)
        return importlib.reload(m_mark).permanent_mark("dc_name")
    finally:
        sys.stdout = real_out
        for k, val in env.items():
            os.environ.pop(k, None) if val is None else os.environ.__setitem__(k, val)
        importlib.reload(m_console)
        importlib.reload(m_mark)


check("on a terminal it is yellow; with NO_COLOR the same words uncoloured",
      mark_on_tty(False) == " \033[93m⚠ Permanent\033[0m" and mark_on_tty(True) == " ⚠ Permanent",
      (mark_on_tty(False), mark_on_tty(True)))

print("--- this host as a member of its domain (manual 1.6.11.8, 2.1.6.34)")
import struct  # noqa: E402

import fabriclib.consent.plan_member as pm  # noqa: E402
import fabriclib.setup.join_host_domain as jh  # noqa: E402
import fabriclib.undo.undo_member as um  # noqa: E402
from fabriclib.consent.plan_host_changes import plan_host_changes  # noqa: E402
from fabriclib.deploy.check_samba_settings import check_samba_settings  # noqa: E402
from fabriclib.setup.advanced.ask_host_change import ask_host_change  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402
from fabriclib.setup.common.render_member_files import render_member_files  # noqa: E402
from fabriclib.setup.steps import STEPS  # noqa: E402
from fabriclib.system.relaxed_settings import relaxed_settings  # noqa: E402

POLICY = {"minimum_length": 14, "complexity": True, "history": 24, "minimum_age_days": 0, "maximum_age_days": 0,
          "lockout_threshold": 10, "lockout_minutes": 15, "lockout_window_minutes": 15}
mv = yaml.safe_load(jinja_env(JINJA).get_template("vars.yaml.j2").render(
    domain="lan.test", hostname="fab1", host_ip="10.0.0.5", lan_cidr="10.0.0.0/24", lan_gateway="10.0.0.1",
    ad_domain="ad.test", ad_password_policy=POLICY, site_name="hq"))
off = yaml.safe_load(jinja_env(JINJA).get_template("vars.yaml.j2").render(
    domain="lan.test", hostname="fab1", host_ip="10.0.0.5", lan_cidr="10.0.0.0/24", lan_gateway="10.0.0.1",
    ad_domain="ad.test", ad_password_policy=POLICY, host_join_domain=False))
# covers: setting:host_join_domain +
check("host_join_domain: true by default, false when set (a JSON boolean)",
      mv["host_join_domain"] is True and off["host_join_domain"] is False, (mv["host_join_domain"], off))
check_samba_settings(mv)
msg = ""
try:
    check_samba_settings({**mv, "host_join_domain": "maybe"})
except Exception as e:      # ValidationError
    msg = str(e)
# covers: setting:host_join_domain -
check("negative: a host_join_domain that is not true or false is refused, saying so", "must be true or false" in msg,
      msg)
# covers: setting:host_machine_password_renew_days +
check("host_machine_password_renew_days: 0 (off) by default, a whole number from 0 to 999 accepted (1.6.11.12)",
      mv["host_machine_password_renew_days"] == 0
      and all(check_samba_settings({**mv, "host_machine_password_renew_days": d}) is None for d in (0, 1, 30, 999)),
      mv.get("host_machine_password_renew_days"))
bad_days = []
for d in (-1, 1000, 1.5, "30", True, None, [30]):
    try:
        check_samba_settings({**mv, "host_machine_password_renew_days": d})
    except Exception as e:      # ValidationError
        if "whole number from 0" in str(e):
            bad_days.append(d)
# covers: setting:host_machine_password_renew_days -
check("negative: a renewal that is not a whole number from 0 to 999 (negative, too large, a fraction, text, true, "
      "empty, a list) is refused, saying so", bad_days == [-1, 1000, 1.5, "30", True, None, [30]], bad_days)
names = [n for n, _, _ in STEPS]
check("the group `member` is recommended, asked after the time service; its step comes right after `start`",
      GROUPS["member"]["level"] == "recommended" and list(GROUPS)[-1] == "member"
      and GROUPS["member"]["step"] == "member" and names.index("member") == names.index("start") + 1, names)
_real_missing = pm.missing_packages
pm.missing_packages = lambda pkgs: ["sssd-ad", "krb5-user"]
planned = plan_host_changes(mv, "/opt", cfg, JINJA, ["member"]).get("member", [])
check("planned when on: the missing packages, the host's own account FAB1$ placed in OU=fabric-hosts and "
      "hq-fabric-machines (never renewed by default) and its keytab only (never the DC's), krb5.conf, sssd.conf, NSS "
      "and PAM (2.1.6.48, 2.1.6.49)",
      planned[:2] == ["apt: install sssd-ad", "apt: install krb5-user"]
      and any("FAB1$" in x and "OU=fabric-hosts" in x and "hq-fabric-machines" in x and "never renewed" in x
              and x.startswith("the domain:") for x in planned)
      and any("own computer account FAB1$" in x and "/etc/krb5.keytab" in x for x in planned)
      and not any("DC-FAB1" in x for x in planned)
      and any("hq-fabric-admins" in x and "/etc/sssd/sssd.conf" in x for x in planned)
      and any(x.startswith("PAM: pam-auth-update") for x in planned), planned)
check("…and fabric's management of the host while it is in hq-fabric-machines: Kerberos for SSH with local accounts "
      "unchanged (checked by sshd -t), a domain password refused over SSH, the domain's names from fabric's DNS "
      "(1.6.11.11)",
      any("10-fabric.conf" in x and "local accounts' sign-in unchanged" in x and "sshd -t" in x
          and "pam_localuser" in x for x in planned)
      and any("resolved.conf.d/fabric.conf" in x and "10.0.0.5" in x for x in planned), planned)
renew = {**mv, "host_machine_password_renew_days": 30}
pm.missing_packages = lambda pkgs: [p for p in pkgs if p == "adcli"]
renew_plan = pm.plan_member(renew)
check("with host_machine_password_renew_days set: adcli planned and the renewal named (1.6.11.12); off, neither",
      "apt: install adcli" in renew_plan and any("every 30 days" in x for x in renew_plan)
      and "apt: install adcli" not in pm.plan_member(mv), renew_plan)
check("with use_host_dns false the resolver is left alone (no DNS drop-in planned)",
      not any("resolved.conf.d/fabric.conf" in x for x in pm.plan_member({**mv, "use_host_dns": False})))
check("negative: not planned when host_join_domain is false (nothing asked, nothing changed)",
      "member" not in plan_host_changes(off, "/opt", cfg, JINJA, ["member"]), off.get("host_join_domain"))
pm.missing_packages = _real_missing
files = render_member_files(mv)
sssd = files["/etc/sssd/sssd.conf"]
check("sssd.conf: the host's own name, the OU's log-on policy (GPO access enforcing) as the one gate, no access "
      "filter of fabric's own (2.1.6.53), sudo from the domain, this host's own DC, no dynamic DNS (2.1.6.48)",
      "access_provider = ad\n" in sssd and "ad_gpo_access_control = enforcing\n" in sssd
      and "ad_access_filter" not in sssd
      and "ad_hostname = fab1.ad.test\n" in sssd and "simple_allow" not in sssd
      and "sudo_provider = ad\n" in sssd and "ad_server = dc-0001.ad.test\n" in sssd and "dyndns_update = false" in sssd
      and sssd.startswith("# fabric"), sssd)
renew_sssd = render_member_files(renew)["/etc/sssd/sssd.conf"]
rodc_sssd = render_member_files({**renew, "ad_dc_type": "rodc"})["/etc/sssd/sssd.conf"]
check("sssd.conf: the machine password never renewed by default (age 0), renewed at the age set, at a read-only "
      "DC's site too (the host's own account there, 2.1.6.52) (1.6.11.12)",
      "ad_maximum_machine_account_password_age = 0\n" in sssd
      and "ad_maximum_machine_account_password_age = 30\n" in renew_sssd
      and "ad_maximum_machine_account_password_age = 30\n" in rodc_sssd, (sssd, renew_sssd))
check("its sudo search bases: the site's OU=sudoers, then the organisation's (as the Linux join builds them)",
      "ldap_sudo_search_base = OU=sudoers,OU=hq,OU=sites,DC=ad,DC=test?onelevel??"
      "OU=sudoers,OU=organisation,OU=hq,OU=sites,DC=ad,DC=test?onelevel?\n" in sssd, sssd)
nested = render_member_files({**mv, "ad_site_ou": "OU=edge,OU=hq,OU=sites"})["/etc/sssd/sssd.conf"]
check("a nested site's host also reads the rules of each site above it",
      "OU=sudoers,OU=edge,OU=hq,OU=sites,DC=ad,DC=test?onelevel??OU=sudoers,OU=hq,OU=sites,DC=ad,DC=test?onelevel??"
      in nested, nested)
check("krb5.conf: the realm, its KDC this host's DC",
      "default_realm = AD.TEST" in files["/etc/krb5.conf"] and "kdc = dc-0001.ad.test" in files["/etc/krb5.conf"])
nss = "passwd:         files systemd\ngroup:          files systemd\nshadow:         files\nhosts: files dns\n"
once = jh._with_sss(nss)
check("nsswitch: sss after the files for passwd and group, a sudoers line added; a second pass changes nothing",
      "passwd:         files systemd sss\n" in once and "sudoers:        files sss\n" in once
      and "hosts: files dns\n" in once and jh._with_sss(once) == once, once)


def _entry(principal, stamp, kvno, key):
    name, realm = principal.split("@")
    body = struct.pack(">H", len(name.split("/"))) + struct.pack(">H", len(realm)) + realm.encode()
    for part in name.split("/"):
        body += struct.pack(">H", len(part)) + part.encode()
    body += struct.pack(">II", 1, stamp) + bytes([kvno]) + struct.pack(">HH", 18, len(key)) + key
    return struct.pack(">i", len(body)) + body


kt1 = b"\x05\x02" + _entry("DC-FAB1$@AD.TEST", 100, 1, b"k" * 32)
kt2 = b"\x05\x02" + _entry("DC-FAB1$@AD.TEST", 200, 1, b"k" * 32)
kt3 = b"\x05\x02" + _entry("DC-FAB1$@AD.TEST", 200, 2, b"n" * 32)
check("the keytab compares by its keys, not the time of the export: a re-export of the same keys changes nothing",
      jh._keys(kt1) == jh._keys(kt2) == {("DC-FAB1$@AD.TEST", 1, 18, b"k" * 32)} and jh._keys(kt1) != jh._keys(kt3)
      and jh._keys(None) == set() and jh._keys(b"junk") == set())

# the step: off, or declined, leaves the host as it is
mcfg = tempfile.mkdtemp()
jh.export_keytab = lambda principals: (_ for _ in ()).throw(AssertionError("exported"))
jh.find_computer = lambda account: (_ for _ in ()).throw(AssertionError("looked up"))
out = io.StringIO()
with contextlib.redirect_stdout(out):
    jh.run(type("C", (), {"vars": off, "config_dir": mcfg, "offline": False})())
check("host_join_domain false: the step says so and touches nothing (not even the DC)",
      "stays out of its domain" in out.getvalue() and not os.listdir(mcfg), out.getvalue())
with contextlib.redirect_stdout(io.StringIO()):
    ask_consent(mcfg, {"member": ["x"]}, interactive=False, decline=["member"])
jh.find_computer = lambda account: None                    # the host's own account not made yet
jh.add_machine = lambda *a, **k: (_ for _ in ()).throw(AssertionError("account created"))
jh.missing_packages = lambda pkgs: []
jh._sssd_on = lambda: False
out = io.StringIO()
with contextlib.redirect_stdout(out):
    jh.run(type("C", (), {"vars": mv, "config_dir": mcfg, "offline": False, "secrets": {}})())
# covers: cli:setup -
check("declined: the step warns what that means and changes nothing (no account made in the domain, no copy kept, "
      "no record)",
      "not approved" in out.getvalue() and "not a member of its domain" in out.getvalue()
      and sorted(os.listdir(mcfg)) == ["consent.yaml"], (out.getvalue(), os.listdir(mcfg)))
row = next(r for r in consent_status(mcfg) if r["group"] == "member")
check("status shows the declined membership as a relaxation", row["state"] == "declined"
      and "not a member" in row["relaxation"], row)
check("host_join_domain false is a relaxed setting in status; the default is not",
      any(r["setting"] == "host_join_domain: false" for r in relaxed_settings(off, mcfg))
      and not any("host_join_domain" in r["setting"] for r in relaxed_settings(mv, mcfg)))

# the undo: each kept file back, the keytab gone, the record used
uhost = tempfile.mkdtemp()
paths = {p: os.path.join(uhost, p.strip("/").replace("/", "_")) for p in pm.KEPT_FILES}
open(paths["/etc/nsswitch.conf"], "w").write(nss)
um.KEPT_FILES, um.KEYTAB = tuple(paths.values()), paths["/etc/krb5.keytab"]
for p in paths.values():
    keep_original(p, mcfg, marker="# fabric")
open(paths["/etc/nsswitch.conf"], "w").write(once)
open(paths["/etc/krb5.keytab"], "wb").write(kt1)
open(paths["/etc/sssd/sssd.conf"], "w").write(sssd)
with open(os.path.join(mcfg, pm.RECORD), "w") as f:
    f.write('{"pam": [], "sssd_enabled": false, "sudo": null}')
done = um.undo_member(mcfg, manage_units=False)
check("undo: nsswitch.conf put back, the keytab and sssd.conf removed (fabric added them), the record used",
      open(paths["/etc/nsswitch.conf"]).read() == nss and not os.path.exists(paths["/etc/krb5.keytab"])
      and not os.path.exists(paths["/etc/sssd/sssd.conf"]) and not os.path.exists(os.path.join(mcfg, pm.RECORD))
      and any("put back" in d for d in done), done)
check("negative: a second undo has nothing to do", um.undo_member(mcfg, manage_units=False) == [])
check("negative: `setup --undo member` unattended without --yes changes nothing",
      "--yes" in refused(lambda: undo_group(Ctx(mcfg, mv), "member", False, False)))
answers = iter(["maybe", "n"])
builtins.input = lambda prompt="": next(answers)
msg = refused(lambda: undo_group(Ctx(mcfg, mv), "member", True, False))
builtins.input = real_input
# covers: ask:undo.* -
check("negative: asked whether to undo, an answer that is not y or n is asked again, and no changes nothing",
      "nothing changed" in msg and next(answers, None) is None
      and yaml.safe_load(open(os.path.join(mcfg, "consent.yaml")))["groups"]["member"]["changes"] == ["x"], msg)

print("--- the host's own computer account, not the DC's (2.1.6.48, manual 1.6.11.8)")
import json  # noqa: E402

import fabriclib.undo.remove_host_account as rha  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.setup.common.host_identity import host_identity  # noqa: E402

ident = host_identity(mv)
check("the host's identity: its own account FAB1$, its host/ names under the AD domain, never the DC's",
      not ident["refused"] and ident["write_server"] is None and ident["account"] == "FAB1" and ident["fqdn"] == "fab1.ad.test"
      and ident["principals"] == ["FAB1$", "host/fab1.ad.test", "host/FAB1"], ident)
long_name = host_identity({**mv, "hostname": "kitchen-server-0-x"})
check("a host name past 15 characters is cut as Windows and adcli cut it, without a dash left at the end",
      long_name["account"] == "KITCHEN-SERVER" and not long_name["refused"], long_name)
old = host_identity({**mv, "dc_name": "fab1", "hostname_dc": "fab1.ad.test"})
rodc = host_identity({**mv, "ad_dc_type": "rodc", "ad_join_server": "10.0.9.5"})
lost = host_identity({**mv, "ad_dc_type": "rodc", "ad_join_server": ""})
check("negative: a DC with the host's name is refused, saying why (2.1.6.51: no install from before 0.7.0 to keep)",
      old["refused"] and "domain controller has this host's name" in old["refused"] and not host_identity(mv)["refused"],
      old)
check("a read-only DC's site: the host's own account too, written at the writable DC it replicates from (2.1.6.52); "
      "negative: with no writable DC known, refused, saying why",
      rodc["account"] == "FAB1" and rodc["write_server"] == "10.0.9.5" and not rodc["refused"]
      and "no writable domain controller" in lost["refused"], (rodc, lost))
rodc_vars = {**mv, "ad_dc_type": "rodc", "ad_join_server": "10.0.9.5"}
rodc_sssd = render_member_files(rodc_vars)["/etc/sssd/sssd.conf"]
rodc_plan = pm.plan_member(rodc_vars)
check("…its sssd as any member's (the OU's policy, its own name) and the plan says where the account is made and that "
      "the read-only DC caches it",
      "access_provider = ad\n" in rodc_sssd and "ad_hostname = fab1.ad.test\n" in rodc_sssd
      and any(x.startswith("the domain:") and "writable domain controller 10.0.9.5" in x and "hq-rodc-cache" in x
              for x in rodc_plan), (rodc_sssd, rodc_plan))

# the step on a scratch tree: the host's files in a folder of their own, the DC and the directory faked
host = tempfile.mkdtemp()
jcfg = tempfile.mkdtemp()
krb_path, sssd_path = os.path.join(host, "krb5.conf"), os.path.join(host, "sssd.conf")
jh.KEYTAB, jh.NSSWITCH, jh.HOSTS, jh.SSSD_CONF = (os.path.join(host, "krb5.keytab"), os.path.join(host, "nsswitch"),
                                                  os.path.join(host, "hosts"), sssd_path)
open(jh.NSSWITCH, "w").write(once)
jh.render_member_files = lambda v: {krb_path: "# fabric krb5\n", sssd_path: "# fabric sssd\n"}
jh._resolves, jh._pam_on, jh._sudo_rs = (lambda name, address: True), (lambda: ["sss", "mkhomedir"]), (lambda: False)
jh._sssd_on = lambda: True
jh.subprocess = types.SimpleNamespace(run=lambda *a, **k: types.SimpleNamespace(returncode=1, stdout="", stderr=""))
kt_own = b"\x05\x02" + _entry("FAB1$@AD.TEST", 300, 1, b"o" * 32)
calls, directory = [], {}


def fake_add(v, actor, name, source="cli", secrets=None, container="samba", os=None, managed=True, server=None):
    calls.append(("add", name, os, managed) + ((server,) if server else ()))
    directory[name.upper()] = {"dn": f"CN={name.upper()},OU=linux,OU=machines,OU=hq,OU=sites,DC=ad,DC=test",
                               "description": "fabric: unmanaged (manual 1.6.11.6)"}
    return "one-time"


def fake_remove(v, actor, name, source="web", secrets=None, container="samba", server=None):
    calls.append(("remove", name) + ((server,) if server else ()))
    if directory.pop(name.upper(), None) is None:
        raise ValidationError("no such entry")
    return {"name": name}


def fake_place(v, actor, name, source="setup", secrets=None, container="samba", server=None):
    calls.append(("place", name) + ((server,) if server else ()))
    entry = directory[name.upper()]
    moved = "OU=fabric-hosts," not in entry["dn"]
    entry["dn"] = f"CN={name.upper()},OU=fabric-hosts,OU=hq,OU=sites,DC=ad,DC=test"
    entry["member_of"] = ["CN=hq-fabric-machines,OU=groups,OU=hq,OU=sites,DC=ad,DC=test"]
    return {"name": name.lower(), "dn": entry["dn"], "moved": moved, "joined": True}


managed_calls = []


def fake_managed(v, managed, dry=False):
    if not dry:
        managed_calls.append(managed)
    return [] if managed_state.get("on") == managed else [f"managed {managed}"] if dry else (
        managed_state.update(on=managed) or [f"managed {managed}"])


managed_state = {}
jh.add_machine, jh.remove_machine, rha.remove_machine = fake_add, fake_remove, fake_remove
jh.place_fabric_host, jh.apply_host_managed = fake_place, fake_managed
jh.find_computer = lambda account: directory.get(account)
jh.export_keytab = lambda principals: kt_own if principals[0] == "FAB1$" else kt1
jctx = type("C", (), {"vars": mv, "config_dir": jcfg, "offline": False, "secrets": {"ad_agent_password": "x"}})()
directory["FAB1"] = {"dn": "CN=FAB1,CN=Computers,DC=ad,DC=test", "description": ""}
msg = refused(lambda: jh.run(jctx))
# covers: cli:setup -
check("negative: a computer of the host's name that fabric did not make for it is refused, named, nothing changed "
      "(no account made, no keytab written, no record)",
      "already has a computer named FAB1" in msg and "CN=Computers" in msg and not calls
      and not os.path.exists(jh.KEYTAB) and not os.path.exists(os.path.join(jcfg, pm.RECORD)), (msg, calls))
directory.clear()
with contextlib.redirect_stdout(io.StringIO()):
    ask_consent(jcfg, {"member": pm.plan_member(mv)}, interactive=False, approve=["member"])
out = io.StringIO()
with contextlib.redirect_stdout(out):
    jh.run(jctx)
record = json.load(open(os.path.join(jcfg, pm.RECORD)))
# covers: cli:setup +
check("approved: the host's own account made as add-machine makes one, then placed once as the site's fabric host "
      "(OU=fabric-hosts, hq-fabric-machines), recorded, its keys (only) in the keytab, 0600; fabric's management "
      "applied (2.1.6.49)",
      calls == [("add", "fab1", "linux", False), ("place", "FAB1")] and record.get("account") == "FAB1"
      and record.get("placed") == "FAB1" and managed_calls == [True]
      and open(jh.KEYTAB, "rb").read() == kt_own and oct(os.stat(jh.KEYTAB).st_mode & 0o777) == "0o600"
      and "own computer account FAB1$" in out.getvalue() and "OU=fabric-hosts" in out.getvalue(),
      (calls, record, out.getvalue()))
out = io.StringIO()
with contextlib.redirect_stdout(out):
    jh.run(jctx)
check("a second run changes nothing (the account is the host's and placed: recorded)",
      "nothing to change" in out.getvalue() and calls == [("add", "fab1", "linux", False), ("place", "FAB1")]
      and managed_calls == [True], (out.getvalue(), calls))
# an admin takes the host out of hq-fabric-machines (or moves it): setup keeps it so, and removes the management
directory["FAB1"]["member_of"] = []
out = io.StringIO()
with contextlib.redirect_stdout(out):
    jh.run(jctx)
check("taken out of hq-fabric-machines by an admin: the next setup does not put it back (placed once), and removes "
      "fabric's management",
      calls == [("add", "fab1", "linux", False), ("place", "FAB1")] and managed_calls == [True, False],
      (calls, managed_calls, out.getvalue()))
directory["FAB1"]["member_of"] = ["CN=hq-fabric-machines,OU=groups,OU=hq,OU=sites,DC=ad,DC=test"]
with contextlib.redirect_stdout(io.StringIO()):
    jh.run(jctx)
# an account of 0.7.1's first build: in OU=linux, unmanaged, never placed (the record has no "placed")
directory["FAB1"] = {"dn": "CN=FAB1,OU=linux,OU=machines,OU=hq,OU=sites,DC=ad,DC=test",
                     "description": "fabric: unmanaged (manual 1.6.11.6)", "member_of": []}
rec = json.load(open(os.path.join(jcfg, pm.RECORD)))
rec.pop("placed")
json.dump(rec, open(os.path.join(jcfg, pm.RECORD), "w"))
calls.clear()
out = io.StringIO()
with contextlib.redirect_stdout(out):
    jh.run(jctx)
out2 = io.StringIO()
with contextlib.redirect_stdout(out2):
    jh.run(jctx)
check("an account of 0.7.1's first build (OU=linux, unmanaged) is moved into OU=fabric-hosts at the next setup, once; "
      "a second run changes nothing",
      calls == [("place", "FAB1")] and "moved into OU=fabric-hosts" in out.getvalue()
      and "nothing to change" in out2.getvalue()
      and json.load(open(os.path.join(jcfg, pm.RECORD))).get("placed") == "FAB1", (calls, out.getvalue()))
calls[:] = [("add", "fab1", "linux", False), ("place", "FAB1")]
# an upgrade: the keytab still holds the DC's account (2.1.6.34), the record knows no account
open(jh.KEYTAB, "wb").write(kt1)
directory.clear()
json.dump({"pam": [], "sssd_enabled": False, "sudo": None}, open(os.path.join(jcfg, pm.RECORD), "w"))
calls.clear()
out = io.StringIO()
with contextlib.redirect_stdout(out):
    jh.run(jctx)
check("an install whose keytab holds the DC's account moves to the host's own: made, recorded, the keytab replaced",
      calls == [("add", "fab1", "linux", False), ("place", "FAB1")] and open(jh.KEYTAB, "rb").read() == kt_own
      and json.load(open(os.path.join(jcfg, pm.RECORD))).get("account") == "FAB1"
      and "held another account's: replaced" in out.getvalue(), (calls, out.getvalue()))
# the host renamed: its account under the new name, the old one (fabric's, recorded) removed
renamed = {**mv, "hostname": "fab2"}
kt_new = b"\x05\x02" + _entry("FAB2$@AD.TEST", 400, 1, b"t" * 32)
jh.export_keytab = lambda principals: kt_new if principals[0] == "FAB2$" else kt_own
with contextlib.redirect_stdout(io.StringIO()):
    ask_consent(jcfg, {"member": pm.plan_member(renamed)}, interactive=False, approve=["member"])
calls.clear()
with contextlib.redirect_stdout(io.StringIO()):
    jh.run(type("C", (), {"vars": renamed, "config_dir": jcfg, "offline": False, "secrets": {}})())
check("the host renamed: its own account under the new name (placed), the one fabric made under the old name removed",
      calls == [("add", "fab2", "linux", False), ("place", "FAB2"), ("remove", "fab1")] and set(directory) == {"FAB2"}
      and json.load(open(os.path.join(jcfg, pm.RECORD))).get("account") == "FAB2", (calls, directory))

# the undo's part in the domain
done = rha.remove_host_account(jcfg, renamed, lambda: {})
# covers: cli:setup +
check("undo: the host's own account removed from the domain, the record forgets it",
      done == ["the domain: this host's computer account FAB2$ removed"] and not directory
      and json.load(open(os.path.join(jcfg, pm.RECORD))).get("account") is None, (done, directory))
check("negative: a second undo removes nothing; no record, nothing either",
      rha.remove_host_account(jcfg, renamed, lambda: {}) == [] and rha.remove_host_account(fresh, mv, None) == [])
json.dump({"account": "FAB2"}, open(os.path.join(jcfg, pm.RECORD), "w"))
check("an account already gone is fine (said so)",
      rha.remove_host_account(jcfg, renamed, lambda: {}) == ["the domain: this host's computer account FAB2$ was "
                                                              "already gone"])
json.dump({"account": "FAB2"}, open(os.path.join(jcfg, pm.RECORD), "w"))
rha.remove_machine = lambda *a, **k: (_ for _ in ()).throw(ValidationError("the directory is not reachable"))
done = rha.remove_host_account(jcfg, renamed, lambda: {})
# covers: cli:setup -
check("negative: the DC refusing (or down) is said, with where to remove it, and the record keeps the account",
      "NOT removed (the directory is not reachable)" in done[0] and "Directory → Machines" in done[0]
      and json.load(open(os.path.join(jcfg, pm.RECORD))).get("account") == "FAB2", done)

# a read-only DC's site (2.1.6.52): the account at the writable DC, cached by the read-only one; refused when that
# DC does not answer
rcfg2 = tempfile.mkdtemp()
with contextlib.redirect_stdout(io.StringIO()):
    ask_consent(rcfg2, {"member": pm.plan_member(rodc_vars)}, interactive=False, approve=["member"])
directory.clear()
calls.clear()
preloads, answering = [], {"up": False}
jh._answers = lambda server: answering["up"]
jh._preload = lambda account, server: preloads.append((account, server))
jh.export_keytab = lambda principals: kt_own
jh.find_computer = lambda account: directory.get(account)
open(jh.KEYTAB, "wb").write(b"")
rctx = type("C", (), {"vars": rodc_vars, "config_dir": rcfg2, "offline": False, "secrets": {"ad_agent_password": "x"}})()
msg = refused(lambda: jh.run(rctx))
# covers: cli:setup -
check("negative: a read-only DC's site whose writable DC does not answer: refused, saying why and what to do, before "
      "anything changes (no account, no record, no fallback to the DC's account)",
      "does not answer" in msg and "10.0.9.5" in msg and "host_join_domain: false" in msg and not calls
      and not preloads and not os.path.exists(os.path.join(rcfg2, pm.RECORD)), (msg, calls))
answering["up"] = True
out = io.StringIO()
with contextlib.redirect_stdout(out):
    jh.run(rctx)
# covers: cli:setup +
check("a read-only DC's site: the host's account made and placed at the writable DC (in hq-rodc-cache), cached by the "
      "read-only DC, its keys exported there; recorded",
      calls == [("add", "fab1", "linux", False, "10.0.9.5"), ("place", "FAB1", "10.0.9.5")]
      and preloads == [("FAB1", "10.0.9.5")] and open(jh.KEYTAB, "rb").read() == kt_own
      and json.load(open(os.path.join(rcfg2, pm.RECORD))).get("placed") == "FAB1"
      and "hq-rodc-cache" in out.getvalue(), (calls, preloads, out.getvalue()))
answering["up"] = False
out = io.StringIO()
with contextlib.redirect_stdout(out):
    jh.run(rctx)
check("…a second run, with the writable DC down, changes nothing and needs nothing from it (the read-only DC caches "
      "the account)", "nothing to change" in out.getvalue() and len(calls) == 2 and len(preloads) == 1, out.getvalue())
removed_at = []
rha.remove_machine = lambda v, actor, name, source="web", secrets=None, container="samba", server=None: \
    removed_at.append((name, server)) or {"name": name}
check("undo at a read-only DC's site: the account removed at the writable DC (its rodc-cache membership with it)",
      rha.remove_host_account(rcfg2, rodc_vars, lambda: {})[0].endswith("removed")
      and removed_at == [("fab1", "10.0.9.5")], removed_at)

# the menu's membership item
answers = iter(["maybe", "n"])
builtins.input = lambda prompt="": next(answers)
pc = SetupContext(deploy_base=tempfile.mkdtemp())
with contextlib.redirect_stdout(io.StringIO()) as out:
    ask_host_change(pc, "member")
builtins.input = real_input
# covers: ask:setup.host_join_domain +-
check("the menu asks whether this host joins its domain: refuses an answer that is not y or n, then takes n and says "
      "what that means", pc.vars.get("host_join_domain") is False and out.getvalue().count("answer y or n") == 1
      and "If no: this host is not a member" in out.getvalue(), (pc.vars, out.getvalue()))
builtins.input = lambda prompt="": ""
pc = SetupContext(deploy_base=tempfile.mkdtemp())
with contextlib.redirect_stdout(io.StringIO()):
    ask_host_change(pc, "member")
builtins.input = real_input
check("…and Enter keeps the default: a member", pc.vars.get("host_join_domain") is True, pc.vars)

print("--- the fabric host as a machine fabric manages (2.1.6.49, 2.1.6.51, manual 1.6.11.11)")
import fabriclib.samba.run_domain_command as m_rdc  # noqa: E402
import fabriclib.setup.common.apply_host_managed as ahm  # noqa: E402
import fabriclib.setup.common.sync_host_managed as shm  # noqa: E402

# the member step refuses a DC named as the host before anything changes (no lookup, no record, nothing written)
rcfg = tempfile.mkdtemp()
calls.clear()
jh.find_computer = lambda account: (_ for _ in ()).throw(AssertionError("looked up"))
msg = refused(lambda: jh.run(type("C", (), {"vars": {**mv, "dc_name": "fab1", "hostname_dc": "fab1.ad.test"},
                                            "config_dir": rcfg, "offline": False, "secrets": {}})()))
# covers: cli:setup -
check("negative: the member step refuses a domain controller named as the host, saying what to do, before anything "
      "changes (2.1.6.51)",
      "domain controller has this host's name" in msg and "host_join_domain: false" in msg and "dc_name" in msg
      and not calls and not os.listdir(rcfg), (msg, calls))

# fabric's management of the host, on a scratch tree: every host path its own, sshd and systemctl faked
mhost = tempfile.mkdtemp()
ahm.SSHD_DIR = os.path.join(mhost, "sshd_config.d")
ahm.SSHD_DROPIN = os.path.join(ahm.SSHD_DIR, "10-fabric.conf")
ahm.PAM_SSHD = os.path.join(mhost, "pam.d-sshd")
ahm.RESOLVED_DROPIN = os.path.join(mhost, "resolved.conf.d", "fabric.conf")
ahm.RESOLVED_RUN = os.path.join(mhost, "run-resolve")
ahm.PAM_MODULES = (os.path.join(mhost, "pam_localuser.so"),)
open(ahm.PAM_MODULES[0], "w").close()
os.makedirs(ahm.SSHD_DIR)
os.makedirs(ahm.RESOLVED_RUN)
PAM_ORIG = ("# PAM configuration for the Secure Shell service\n\n# Standard Un*x authentication.\n"
            "@include common-auth\n\naccount    required     pam_nologin.so\n@include common-account\n")
open(ahm.PAM_SSHD, "w").write(PAM_ORIG)
reloads, sshd_says = [], {"before": "", "after": ""}
ahm._reload = lambda what: reloads.append(what)
ahm._sshd_check = lambda: sshd_says["after"] if os.path.exists(ahm.SSHD_DROPIN) else sshd_says["before"]
done = ahm.apply_host_managed(mv, True)
dropin, pam_now = open(ahm.SSHD_DROPIN).read(), open(ahm.PAM_SSHD).read()
check("managed: sshd gets Kerberos (GSSAPI, the strict acceptor check off, PAM) and never PasswordAuthentication, so "
      "local accounts sign in as before (the host's exception to 2.1.6.39); sshd reloaded",
      "GSSAPIAuthentication yes\n" in dropin and "GSSAPIStrictAcceptorCheck no\n" in dropin
      and "UsePAM yes\n" in dropin and "PasswordAuthentication" not in dropin.replace("PasswordAuthentication is", "")
      and reloads.count("ssh") == 1, (dropin, reloads))
check("…a domain account's password is refused over SSH: pam_localuser before common-auth, under fabric's mark",
      pam_now.index(ahm.PAM_LINE) < pam_now.index("@include common-auth") and ahm.PAM_MARK in pam_now
      and pam_now.replace(ahm.PAM_MARK + "\n" + ahm.PAM_LINE + "\n", "") == PAM_ORIG, pam_now)
check("…and the domain's names from fabric's DNS (the host's address; other names untouched)",
      open(ahm.RESOLVED_DROPIN).read().endswith("[Resolve]\nDNS=10.0.0.5\nDomains=~ad.test ~lan.test\n")
      and "resolved" in reloads and len(done) == 3, (done, reloads))
reloads.clear()
check("a second pass changes nothing and reloads nothing", ahm.apply_host_managed(mv, True) == [] and not reloads)
done = ahm.apply_host_managed(mv, False)
check("taken out of the group: the drop-ins and fabric's PAM lines removed, PAM as it was",
      not os.path.exists(ahm.SSHD_DROPIN) and not os.path.exists(ahm.RESOLVED_DROPIN)
      and open(ahm.PAM_SSHD).read() == PAM_ORIG and "ssh" in reloads and len(done) == 3, done)
check("dry: says what would change, changes nothing",
      len(ahm.apply_host_managed(mv, True, dry=True)) == 3 and not os.path.exists(ahm.SSHD_DROPIN)
      and open(ahm.PAM_SSHD).read() == PAM_ORIG)
# sshd refusing: before fabric changes anything, or with fabric's drop-in
sshd_says["before"] = "line 3: Bad configuration option: Bogus"
reloads.clear()
msg = refused(lambda: ahm.apply_host_managed(mv, True))
check("negative: sshd already refusing its configuration: setup stops, saying so, and nothing is changed or reloaded",
      "refuses its configuration as it is" in msg and not os.path.exists(ahm.SSHD_DROPIN)
      and open(ahm.PAM_SSHD).read() == PAM_ORIG and not reloads, msg)
sshd_says.update(before="", after="Unsupported option GSSAPIStrictAcceptorCheck")
msg = refused(lambda: ahm.apply_host_managed(mv, True))
check("negative: sshd refusing fabric's drop-in: it is put back (none), PAM untouched, nothing reloaded, so SSH works "
      "as before (never a configuration sshd refuses)",
      "put back as it was and nothing reloaded" in msg and not os.path.exists(ahm.SSHD_DROPIN)
      and open(ahm.PAM_SSHD).read() == PAM_ORIG and "ssh" not in reloads, (msg, reloads))
sshd_says.update(after="")
os.remove(ahm.PAM_MODULES[0])
msg = refused(lambda: ahm.apply_host_managed(mv, True))
check("negative: without pam_localuser nothing is changed (a domain password would be taken over SSH)",
      "pam_localuser.so" in msg and not os.path.exists(ahm.SSHD_DROPIN), msg)
open(ahm.PAM_MODULES[0], "w").close()
open(ahm.SSHD_DROPIN, "w").write("# the owner's own file\nPasswordAuthentication no\n")
ahm.apply_host_managed(mv, True)
check("an owner's own 10-fabric.conf (without fabric's mark) is left alone; removal leaves it too",
      open(ahm.SSHD_DROPIN).read() == "# the owner's own file\nPasswordAuthentication no\n"
      and ahm.apply_host_managed(mv, False) and open(ahm.SSHD_DROPIN).read().startswith("# the owner's"))
os.remove(ahm.SSHD_DROPIN)
nodns = ahm.apply_host_managed({**mv, "use_host_dns": False}, True)
check("use_host_dns false: the resolver is left alone (no DNS drop-in)",
      not os.path.exists(ahm.RESOLVED_DROPIN) and len(nodns) == 2, nodns)
ahm.apply_host_managed(mv, False)
os.rmdir(ahm.SSHD_DIR)
check("no SSH server on the host (no sshd_config.d): nothing for SSH, PAM untouched",
      not any("10-fabric.conf" in x or "pam.d-sshd" in x for x in ahm.apply_host_managed(mv, True))
      and open(ahm.PAM_SSHD).read() == PAM_ORIG)
ahm.apply_host_managed(mv, False)
os.makedirs(ahm.SSHD_DIR)

# `fabricctl domain host-managed`: in step with the group, as the DC says
m_rdc.INSTALL_DIR = tempfile.mkdtemp()
scfg = os.path.join(m_rdc.INSTALL_DIR, "config")
os.makedirs(scfg)
dc_says = {"FAB1": {"dn": "CN=FAB1,OU=fabric-hosts,OU=hq,OU=sites,DC=ad,DC=test", "description": "",
                    "member_of": ["CN=hq-fabric-machines,OU=groups,OU=hq,OU=sites,DC=ad,DC=test"]}}
shm.find_computer = lambda account: dc_says.get(account)


def domain_cmd(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = m_rdc.run_domain_command(mv, list(argv))
    return code, out.getvalue()


code, text = domain_cmd("host-managed")
# covers: cli:domain.host-managed -
check("negative: on a host that is not a member of its domain, `domain host-managed` refuses, saying so; nothing "
      "changes", code == 1 and "not a member of its domain" in text and not os.path.exists(ahm.SSHD_DROPIN),
      (code, text))
code, text = domain_cmd("host-managed", "--scheduled")
check("…the timer's run then has nothing to do (exit 0)", code == 0 and "nothing to do" in text, (code, text))
check("negative: an unknown option is a usage error", domain_cmd("host-managed", "--now")[0] == 2)
json.dump({"account": "FAB1", "placed": "FAB1"}, open(os.path.join(scfg, pm.RECORD), "w"))
code, text = domain_cmd("host-managed")
# covers: cli:domain.host-managed +
check("in hq-fabric-machines: `domain host-managed` applies fabric's management and says what it found and changed",
      code == 0 and "FAB1$ is in hq-fabric-machines" in text and os.path.exists(ahm.SSHD_DROPIN)
      and ahm.PAM_LINE in open(ahm.PAM_SSHD).read(), (code, text))
code, text = domain_cmd("host-managed")
check("…a second run: nothing to change", code == 0 and "nothing to change" in text, text)
dc_says["FAB1"]["member_of"] = []
code, text = domain_cmd("host-managed", "--scheduled")
check("taken out of the group: the timer's run removes it", code == 0 and "not in hq-fabric-machines" in text
      and not os.path.exists(ahm.SSHD_DROPIN) and open(ahm.PAM_SSHD).read() == PAM_ORIG, (code, text))
dc_says.clear()
code, text = domain_cmd("host-managed")
check("negative: the account gone from the domain: refused, saying how to make it again; nothing changed",
      code == 1 and "setup --step member" in text, (code, text))
shm.find_computer = lambda account: (_ for _ in ()).throw(SetupError("the domain controller's directory could not be "
                                                                      "read"))
code, text = domain_cmd("host-managed", "--scheduled")
check("negative: the DC not answering: refused (exit 1), nothing changed", code == 1 and "could not be read" in text,
      (code, text))

print("--- setup's start, its menu of every setting and the plan's one yes (manual 1.2.9.11, 2.1.2.17-2.1.2.19)")
import getpass  # noqa: E402
import ipaddress  # noqa: E402

import fabriclib.setup.advanced.ask_network as m_net  # noqa: E402
import fabriclib.setup.advanced.menu_items as m_items  # noqa: E402
import fabriclib.setup.advanced.setup_menu as m_menu  # noqa: E402
from fabriclib.consent.initial_host_choices import TOGGLED, initial_host_choices  # noqa: E402
from fabriclib.consent.save_consent import save_consent  # noqa: E402
from fabriclib.setup.advanced.ask_dhcp_settings import ask_dhcp_settings  # noqa: E402
from fabriclib.setup.advanced.ask_memory import ask_memory  # noqa: E402
from fabriclib.setup.choose_mode import choose_mode  # noqa: E402

# the test's addresses are not this machine's: the check of the three together is the network item's own test below
m_items.network_problem = m_menu.network_problem = lambda data: ""
NETS = {"eth0": [ipaddress.IPv4Interface("10.0.0.5/24")]}


def drive(fn, answers, secrets=()):
    """Run fn with these answers typed (and these secrets at hidden prompts): (its result or the exception it raised,
    what it printed, the answers left over)."""
    queue, hidden = list(answers), list(secrets)
    real_in, real_pw = builtins.input, getpass.getpass
    builtins.input = lambda prompt="": queue.pop(0)
    getpass.getpass = lambda prompt="": hidden.pop(0)
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            result = fn()
    except (SystemExit, SetupError, IndexError) as e:
        result = e
    finally:
        builtins.input, getpass.getpass = real_in, real_pw
    return result, out.getvalue(), queue + hidden


def new_ctx(**extra):
    """A new install's context in a scratch folder, its settings as collect_vars leaves them without questions."""
    c = SetupContext(deploy_base=tempfile.mkdtemp())
    c.vars = {"domain": "lan.test", "hostname": "fab1", "host_ip": "10.0.0.5", "lan_cidr": "10.0.0.0/24",
              "lan_gateway": "10.0.0.1", "install_keycloak": True, "install_webui": True, "dns_filter": "bind",
              "host_ram_capacity": 4, "ad_password_policy": POLICY, **extra}
    c.fresh_install = True
    return c


# the start: [G]uided / [A]dvanced / [Q]uit, only on a new install with someone there
c = new_ctx()
got, out, left = drive(lambda: choose_mode(c), ["x", ""])
# covers: ask:setup.mode +-
check("the start: an answer that is not g, a or q refused, saying which; Enter takes Guided",
      got == "guided" and "answer g (guided), a (advanced) or q (quit)" in out and "[A]dvanced - a menu of every "
      "setting" in out and not left, (got, out))
got, _, _ = drive(lambda: choose_mode(c), ["a"])
quit_, _, _ = drive(lambda: choose_mode(c), ["q"])
check("…a takes Advanced; q quits, changing nothing", got == "advanced" and isinstance(quit_, SystemExit), (got, quit_))
os.makedirs(c.config_dir, exist_ok=True)
open(c.vars_file, "w").write("domain: lan.test\n")
got, out, left = drive(lambda: choose_mode(c), ["a"])
check("negative: an upgrade or a re-run (the settings exist) is not asked: straight to the plan",
      got == "guided" and left == ["a"] and not out, (got, out))

# the menu, from the start's Advanced: every item asked with guided mode's question, refusals said, Proceed waits
c = new_ctx()
got, out, left = drive(lambda: m_menu.setup_menu(c, NETS), [
    "99", "p",
    "3", 'a"quote', "Acme",
    "7", "root", "",
    "4", "",
    "5", "dc_1", "DC-Office",
    "8", "0", "5",
    "10", "maybe", "y",
    "9", "y", "eth9", "", "", "",
    "9", "y", "", "", "", "",
    "11", "y", "http://siem.lan", "siem.lan:99999", "siem.lan",
    "12", "n",
    "13", "2", "4",
    "15", "n",
    "17", "y",
    "14", "n",
    "20", "n",
    "p"], secrets=["short", "Good-Pass-12345", "Good-Pass-12345"])
v = c.vars
# covers: ask:setup.menu +-
check("the menu: three parts, 20 numbered items with their values; something not on the list refused naming the "
      "numbers; Proceed waits for the required items without a value, naming them",
      got is None and "Required (setup cannot proceed until each has a value):" in out
      and "Changes to this host (recommended; each can be declined):" in out
      and "'99' is not on the list: a number from 1 to 20" in out and "not yet: 3, 7 need an answer" in out
      and "(needs an answer)" in out and not left, (got, out[-3000:], left))
# covers: ask:setup.vars.* ask:setup.admin_password ask:setup.admin_password_again +-
check("required items ask guided mode's questions with its checks: the organisation, the first admin (a reserved name "
      "refused, Enter its default) and their password (too short refused, typed twice)",
      v["friendly_name"] == "Acme" and v["webui_admin_user"] == "fabric-admin" and c.admin_password == "Good-Pass-12345"
      and "not a valid friendly_name" in out and "not a valid webui_admin_user" in out, (v.get("friendly_name"), out))
check("the AD domain: Enter takes the suggestion (ad.lan.test); the CA's lifetime 5 years after 0 refused",
      v["ad_domain"] == "ad.lan.test" and v["cert_root_ca_days"] == 5 * 365 and "a whole number of years" in out, v)
# covers: ask:setup.dc_name +-
check("the DC's name item: dc-0001 suggested; a name the DC cannot have refused and asked again, then kept in "
      "lower case", v["dc_name"] == "dc-office" and "dc-0001 (suggested)" in out and "1-15 letters" in out, v)
# covers: ask:setup.part.* +-
check("the parts: 802.1X on (an answer that is not y or n refused first), the DNS filter off",
      v["install_freeradius"] is True and v["dns_filter"] == "none" and "'maybe': answer y or n" in out, v)
# covers: ask:setup.dhcp.interface ask:setup.dhcp.subnet ask:setup.dhcp.pool ask:setup.dhcp.router +
# covers: ask:setup.dhcp.interface -
check("DHCP on asks what `fabricctl dhcp on` needs, checked the same way: an interface this host lacks refused (DHCP "
      "stays off), then the offered ones taken",
      v["install_kea"] is True and v["dhcp"]["interfaces"] == ["eth0"]
      and v["dhcp"]["subnets"][0]["subnet"] == "10.0.0.0/24" and v["dhcp"]["subnets"][0]["pools"] == [
          "10.0.0.128 - 10.0.0.245"] and "no interface 'eth9'" in out and "DHCP stays off" in out, v.get("dhcp"))
# covers: ask:setup.logs.target +-
check("log forwarding on asks its destination: a URL that is not https and a port over 65535 refused, then syslog "
      "over TLS on 6514", v["install_fluentbit"] is True
      and v["log_forwarding"] == {"syslog": {"host": "siem.lan", "port": 6514}}
      and "starts https://" in out and "optionally :port (1-65535)" in out, v.get("log_forwarding"))
# covers: ask:setup.memory +-
check("memory: 2 GB refused (4 at least), 4 taken", v["host_ram_capacity"] == 4 and "'2': a whole number of GB" in out,
      v["host_ram_capacity"])
# covers: ask:setup.consent.* +-
check("host changes: the ports turned off show what that means and take securing and the host's own rules along; "
      "the host's own rules turned on bring back what they need; Docker's hardening and membership off",
      {g: c.host_choices.get(g, True) for g in TOGGLED} == {"runtime": False, "ports": True, "firewall": True,
                                                            "own_rules": True, "trust": True, "time": True}
      and v["host_join_domain"] is False
      and "If no: ufw is not told about fabric's ports" in out and "also off: Secure this host" in out
      and "also off: The host's own firewall rules" in out and "also on: Ports fabric needs" in out
      and "also on: Secure this host" in out, (c.host_choices, out[-2500:]))
c = new_ctx()
got, out, left = drive(lambda: m_menu.setup_menu(c, NETS), ["3", "Acme", "7", "", "p"],
                       secrets=["Good-Pass-12345", "Good-Pass-12345"])
check("Proceed with the DC's name item left alone saves its suggestion, dc-0001 (the 0.7.1 candidate's install "
      "left it unset and the DC took the host's name, 2.3.1.21.2)",
      got is None and not left and c.vars.get("dc_name") == "dc-0001", (c.vars.get("dc_name"), left, out[-1500:]))
got, _, _ = drive(lambda: m_menu.setup_menu(new_ctx(), NETS), ["q"])
check("negative: Quit in the menu changes nothing and stops setup", isinstance(got, SystemExit), got)

# the network item: the three checked together, refused and asked again until they fit
_problems = iter(["the gateway 10.0.1.1 is not in the subnet 10.0.0.0/24", ""])
m_net.network_problem = lambda data: next(_problems)
c2 = new_ctx()
got, out, left = drive(lambda: m_net.ask_network(c2), ["999.1.1.1", "10.0.0.5", "", "10.0.1.1", "", "", "10.0.0.1"])
check("the network item: an impossible address refused; answers that do not fit together refused, saying why, and "
      "asked again", c2.vars["lan_gateway"] == "10.0.0.1" and "not a valid host_ip" in out
      and "not in the subnet" in out and not left, (out, left))

# DHCP's questions alone: each refusal says why and leaves DHCP off
for bad, why in ((["eth0", "nope", "", ""], "subnet"), (["eth0", "", "10.9.9.1 - 10.9.9.9", ""], "must lie inside"),
                 (["eth0", "", "", "300.1.1.1"], "300.1.1.1")):
    c3 = new_ctx()
    got, out, _ = drive(lambda: ask_dhcp_settings(c3, NETS), bad)
    # covers: ask:setup.dhcp.subnet ask:setup.dhcp.pool ask:setup.dhcp.router -
    check(f"negative: DHCP refused ({why}), nothing saved", got is False and why in out and "dhcp" not in c3.vars,
          (bad, out))
c3 = new_ctx(memory_floors={"keycloak": 3000})
got, out, _ = drive(lambda: ask_memory(c3, have=16), ["5", "8"])
check("negative: a size whose memory plan does not fit is refused with the plan's reason, a larger one taken",
      c3.vars["host_ram_capacity"] == 8 and "refused: memory: the installed services need" in out, out)

# the plan: settings, the memory split, every host change; Proceed is the one yes; Menu opens the menu
pc = new_ctx(friendly_name="Acme", webui_admin_user="fabric-admin", ad_domain="ad.lan.test")
pc.admin_password = "Good-Pass-12345"             # chosen already (the first admin item)
pc.host_choices = {"runtime": False, "ports": True, "firewall": True, "own_rules": True, "trust": True, "time": True}
os.makedirs(pc.config_dir, exist_ok=True)
save_consent(pc.config_dir, {"packages": {"answer": "yes", "changes": ["apt: install x"], "when": "t", "by": "x"}})
changes = {"packages": ["apt: install x", "apt: install y"], "runtime": ["restart Docker"], "ports": ["p"],
           "firewall": ["f"], "own_rules": ["o"]}
got, out, left = drive(lambda: choose_plan(pc, lambda: (mv, changes)), ["", "x", "m", "p", "p"])
# covers: ask:setup.plan +-
check("the plan: no default (Enter and 'x' refused), [M]enu opens the menu and shows the plan again, Proceed allows "
      "every change listed and declines the one turned off",
      got == {"packages": True, "runtime": False, "ports": True, "firewall": True, "own_rules": True}
      and out.count("'': answer p, m or q") == 1 and "'x': answer p, m or q" in out
      and out.count("fabricctl setup will:") == 2 and "fabric setup: every setting" in out and not left, (got, left))
check("…it lists the memory split and every host change on, with its changes; a group changed since it was allowed is "
      "marked, its new line with +; the one turned off under Not made, with what that means",
      "kept for the host" in out and "Packages (required)  changed since it was allowed" in out
      and "+ apt: install y" in out and "- apt: install x" in out and "Not made (declined; [M]enu to change):" in out
      and "Docker daemon settings: the Docker daemon is not hardened" in out, out[-2500:])
check("…the host's own firewall rules it removes said apart, one by one, with how to keep them (2.1.2.24)",
      "Firewall rules of this host's own that fabric will REMOVE (1):" in out and "x o" in out
      and "--decline own_rules" in out, out[-2500:])
check("…and the menu's changes were saved with the settings (fabric.yaml)",
      os.path.exists(os.path.join(pc.config_dir, "fabric.yaml")))


def no_fit():
    raise SetupError("memory: the installed services need 4936 MB at least … Turn off DHCP (install_kea: false)")


got, out, _ = drive(lambda: choose_plan(pc, no_fit), ["p", "q"])
check("negative: a plan setup cannot take (the memory does not fit) is said, Proceed refused: only Menu or Quit",
      isinstance(got, SystemExit) and "setup cannot proceed: memory" in out and "'p': answer m or q" in out, out[-600:])
pc.non_interactive = True
got, out, left = drive(lambda: choose_plan(pc, lambda: (mv, changes)), ["p"])
check("unattended: the plan and its host changes shown, nothing asked (--approve / --decline answer)",
      got is None and left == ["p"] and "Packages (required)" in out, (got, left))
pc.host_choices = {**pc.host_choices, "own_rules": False}
pc.non_interactive = False
got, out, left = drive(lambda: choose_plan(pc, lambda: (mv, changes)), ["p"])
check("negative: the host's own rules turned off: no REMOVE block; they show under Not made, kept",
      "will REMOVE" not in out and "the host's own rules stay" in out and got["own_rules"] is False, (got, out[-1500:]))
pc.host_choices = {**pc.host_choices, "own_rules": True}
pc.non_interactive = True
pc.non_interactive = False

# where the menu's host changes start: earlier answers, --approve, --decline; what needs a declined one is off too
hc = tempfile.mkdtemp()
save_consent(hc, {"firewall": {"answer": "no", "changes": ["f"], "when": "t", "by": "x"}})
check("a host change declined before starts off, what needs it too; the others on",
      initial_host_choices(hc) == {"runtime": True, "ports": True, "firewall": False, "own_rules": False,
                                   "trust": True, "time": True}, initial_host_choices(hc))
check("--approve turns one back on; --decline ports takes securing and the host's own rules along",
      initial_host_choices(hc, approve=["firewall"])["firewall"] is True
      and not any(initial_host_choices(hc, decline=["ports"])[g] for g in ("ports", "firewall", "own_rules")))

print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
