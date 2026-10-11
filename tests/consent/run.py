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

print("--- interactive")
cfg2 = tempfile.mkdtemp()
answers = iter(["", "maybe", "y", "n"])
real_input = builtins.input
builtins.input = lambda prompt="": next(answers)
try:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        got = ask_consent(cfg2, {"packages": PLAN["packages"], "runtime": ["restart Docker"]}, interactive=True)
finally:
    builtins.input = real_input
# covers: ask:consent.* +
check("each group is one question listing its changes and what no means; there is no default answer",
      got == {"packages": "yes", "runtime": "no"} and "If no:" in out.getvalue()
      and "apt: install docker.io" in out.getvalue(), got)

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
_asked = []
_orig_ask = ask_consent_mod._ask
ask_consent_mod._ask = lambda group, changes, new: (_asked.append(group), group != "ports")[1]
_ans = ask_consent_mod.ask_consent(os.path.join(cfg, "needs"), {"ports": ["p"], "firewall": ["f"], "own_rules": ["o"]},
                                   interactive=True)
ask_consent_mod._ask = _orig_ask
check("the ports declined: securing and the host's own rules are not asked", _asked == ["ports"]
      and _ans == {"ports": "no", "firewall": "skipped", "own_rules": "skipped"}, (_asked, _ans))
_asked.clear()
ask_consent_mod._ask = lambda group, changes, new: (_asked.append(group), True)[1]
_ans = ask_consent_mod.ask_consent(os.path.join(cfg, "needs"), {"ports": ["p"], "firewall": ["f"], "own_rules": ["o"]},
                                   interactive=True, stops={"ports"})
ask_consent_mod._ask = _orig_ask
check("a declined question that stops setup is asked again in the next interactive run (never stuck with the no)",
      _asked[:1] == ["ports"] and _ans.get("ports") == "yes", (_asked, _ans))
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
from fabriclib.setup import choose_plan  # noqa: E402
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

# Advanced: the question
answers = iter(["maybe", "n"])
builtins.input = lambda prompt="": next(answers)
pc = type("P", (), {"vars": {}})()
with contextlib.redirect_stdout(io.StringIO()) as out:
    choose_plan._ask_host_join_domain(pc)
builtins.input = real_input
# covers: ask:setup.host_join_domain +-
check("Advanced asks whether this host joins its domain: refuses an answer that is not y or n, then takes n",
      pc.vars.get("host_join_domain") is False and out.getvalue().count("answer y or n") == 1, (pc.vars, out.getvalue()))
builtins.input = lambda prompt="": ""
pc = type("P", (), {"vars": {}})()
choose_plan._ask_host_join_domain(pc)
builtins.input = real_input
check("…and Enter keeps the default: a member", pc.vars.get("host_join_domain") is True, pc.vars)

print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
