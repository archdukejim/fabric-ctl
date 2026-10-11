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
      len(_seen) == 1 and "Ports fabric needs" in _out.getvalue() and _ans.get("ports") == "yes"
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
names = [n for n, _, _ in STEPS]
check("the group `member` is recommended, asked after the time service; its step comes right after `start`",
      GROUPS["member"]["level"] == "recommended" and list(GROUPS)[-1] == "member"
      and GROUPS["member"]["step"] == "member" and names.index("member") == names.index("start") + 1, names)
_real_missing = pm.missing_packages
pm.missing_packages = lambda pkgs: ["sssd-ad", "krb5-user"]
planned = plan_host_changes(mv, "/opt", cfg, JINJA, ["member"]).get("member", [])
check("planned when on: the missing packages, the keytab of FAB1$ only, krb5.conf, sssd.conf, NSS and PAM",
      planned[:2] == ["apt: install sssd-ad", "apt: install krb5-user"]
      and any("FAB1$" in x and "/etc/krb5.keytab" in x for x in planned)
      and any("hq-fabric-admins" in x and "/etc/sssd/sssd.conf" in x for x in planned)
      and any(x.startswith("PAM: pam-auth-update") for x in planned), planned)
check("negative: not planned when host_join_domain is false (nothing asked, nothing changed)",
      "member" not in plan_host_changes(off, "/opt", cfg, JINJA, ["member"]), off.get("host_join_domain"))
pm.missing_packages = _real_missing
files = render_member_files(mv)
sssd = files["/etc/sssd/sssd.conf"]
check("sssd.conf: the fabric admins only (simple access), sudo from the domain, this host's own DC, no dynamic DNS",
      "access_provider = simple\n" in sssd and "simple_allow_groups = fabric-admins, hq-fabric-admins\n" in sssd
      and "sudo_provider = ad\n" in sssd and "ad_server = fab1.ad.test\n" in sssd and "dyndns_update = false" in sssd
      and sssd.startswith("# fabric"), sssd)
check("its sudo search bases: the site's OU=sudoers, then the organisation's (as the Linux join builds them)",
      "ldap_sudo_search_base = OU=sudoers,OU=hq,OU=sites,DC=ad,DC=test?onelevel??"
      "OU=sudoers,OU=organisation,OU=hq,OU=sites,DC=ad,DC=test?onelevel?\n" in sssd, sssd)
nested = render_member_files({**mv, "ad_site_ou": "OU=edge,OU=hq,OU=sites"})["/etc/sssd/sssd.conf"]
check("a nested site's host also reads the rules of each site above it",
      "OU=sudoers,OU=edge,OU=hq,OU=sites,DC=ad,DC=test?onelevel??OU=sudoers,OU=hq,OU=sites,DC=ad,DC=test?onelevel??"
      in nested, nested)
check("krb5.conf: the realm, its KDC this host's DC",
      "default_realm = AD.TEST" in files["/etc/krb5.conf"] and "kdc = fab1.ad.test" in files["/etc/krb5.conf"])
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


kt1 = b"\x05\x02" + _entry("FAB1$@AD.TEST", 100, 1, b"k" * 32)
kt2 = b"\x05\x02" + _entry("FAB1$@AD.TEST", 200, 1, b"k" * 32)
kt3 = b"\x05\x02" + _entry("FAB1$@AD.TEST", 200, 2, b"n" * 32)
check("the keytab compares by its keys, not the time of the export: a re-export of the same keys changes nothing",
      jh._keys(kt1) == jh._keys(kt2) == {("FAB1$@AD.TEST", 1, 18, b"k" * 32)} and jh._keys(kt1) != jh._keys(kt3)
      and jh._keys(None) == set() and jh._keys(b"junk") == set())

# the step: off, or declined, leaves the host as it is
mcfg = tempfile.mkdtemp()
jh.export_dc_keytab = lambda v: (_ for _ in ()).throw(AssertionError("exported"))
out = io.StringIO()
with contextlib.redirect_stdout(out):
    jh.run(type("C", (), {"vars": off, "config_dir": mcfg, "offline": False})())
check("host_join_domain false: the step says so and touches nothing (not even the DC)",
      "stays out of its domain" in out.getvalue() and not os.listdir(mcfg), out.getvalue())
with contextlib.redirect_stdout(io.StringIO()):
    ask_consent(mcfg, {"member": ["x"]}, interactive=False, decline=["member"])
jh.export_dc_keytab = lambda v: kt1
jh.missing_packages = lambda pkgs: []
jh._sssd_on = lambda: False
out = io.StringIO()
with contextlib.redirect_stdout(out):
    jh.run(type("C", (), {"vars": mv, "config_dir": mcfg, "offline": False})())
check("declined: the step warns what that means and changes nothing (no copy kept, no record)",
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
from fabriclib.setup.choose_plan import choose_plan  # noqa: E402

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
    "6", "root", "",
    "4", "",
    "7", "0", "5",
    "9", "maybe", "y",
    "8", "y", "eth9", "", "", "",
    "8", "y", "", "", "", "",
    "10", "y", "http://siem.lan", "siem.lan:99999", "siem.lan",
    "11", "n",
    "12", "2", "4",
    "14", "n",
    "16", "y",
    "13", "n",
    "19", "n",
    "p"], secrets=["short", "Good-Pass-12345", "Good-Pass-12345"])
v = c.vars
# covers: ask:setup.menu +-
check("the menu: three parts, 19 numbered items with their values; something not on the list refused naming the "
      "numbers; Proceed waits for the required items without a value, naming them",
      got is None and "Required (setup cannot proceed until each has a value):" in out
      and "Changes to this host (recommended; each can be declined):" in out
      and "'99' is not on the list: a number from 1 to 19" in out and "not yet: 3, 6 need an answer" in out
      and "(needs an answer)" in out and not left, (got, out[-3000:], left))
# covers: ask:setup.vars.* ask:setup.admin_password ask:setup.admin_password_again +-
check("required items ask guided mode's questions with its checks: the organisation, the first admin (a reserved name "
      "refused, Enter its default) and their password (too short refused, typed twice)",
      v["friendly_name"] == "Acme" and v["webui_admin_user"] == "fabric-admin" and c.admin_password == "Good-Pass-12345"
      and "not a valid friendly_name" in out and "not a valid webui_admin_user" in out, (v.get("friendly_name"), out))
check("the AD domain: Enter takes the suggestion (ad.lan.test); the CA's lifetime 5 years after 0 refused",
      v["ad_domain"] == "ad.lan.test" and v["cert_root_ca_days"] == 5 * 365 and "a whole number of years" in out, v)
# covers: ask:setup.part.* +-
check("the parts: 802.1X on (an answer that is not y or n refused first), the DNS filter off",
      v["install_freeradius"] is True and v["dns_filter"] == "none" and "'maybe': answer y or n" in out, v)
# covers: ask:setup.dhcp.interface ask:setup.dhcp.subnet ask:setup.dhcp.pool ask:setup.dhcp.router +
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
