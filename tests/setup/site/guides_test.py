"""The finish's commands are copies of the manual's topics (manual 1.3.6.6, global 5.3): each command in finish_guides is
in Volume 4's 4.3.6, placeholders and all; every picture a guide names exists; site_wanted's cases; ask()'s front end;
the listener imports nothing but the standard library and itself (1.3.6.3); the plan names the site's port; the site's
own firewall rule is never taken for one of the host's.
    python3 tests/setup/site/guides_test.py"""
import ast
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import REPO, check, finish  # noqa: E402

from fabriclib.common import ask as ask_module  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402
from fabriclib.setup.site.close_site_port import close_site_port  # noqa: E402
from fabriclib.setup.site.finish_guides import DNS, TRUST, finish_guides  # noqa: E402
from fabriclib.setup.site.keep_site_port import keep_site_port  # noqa: E402
from fabriclib.setup.site.new_code import new_code  # noqa: E402
from fabriclib.setup.site.open_site_port import open_site_port  # noqa: E402
from fabriclib.setup.site.host_addresses import host_addresses  # noqa: E402
from fabriclib.setup.site.site_rule import site_rule  # noqa: E402
from fabriclib.setup.site.site_wanted import site_wanted  # noqa: E402
from fabriclib.setup.site.take_snapshot import take_snapshot  # noqa: E402
from fabriclib.setup.site.restore_snapshot import restore_snapshot  # noqa: E402
from fabriclib.setup.site.write_port_record import write_port_record  # noqa: E402
from fabriclib.setup.site.read_port_record import read_port_record  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402
import fabriclib.security.host_own_rules as hor  # noqa: E402
import fabriclib.consent.plan_firewall as pf  # noqa: E402

with open(os.path.join(REPO, "docs/volume_4_operations/4.3.6-web-guided-setup.md"), encoding="utf-8") as f:
    MANUAL = f.read()
for guide in TRUST + DNS:
    for command in guide["commands"]:
        check(f"in the manual: {guide['os']}: {command[:50]}", command in MANUAL, command)
    check(f"the picture exists: {guide['picture']}", os.path.exists(os.path.join(REPO, "static/setup-site", guide["picture"])))
trust, dns = finish_guides("10.0.0.5", "lan.example", "http://10.0.0.5/certs/", "fabric-ctl.lan.example")
text = repr(trust + dns)
check("the values are filled in everywhere", "<" not in text.replace("<domain>", "!") and "10.0.0.5" in text and "lan.example" in text, text[:400])
check("the guides cover Windows, macOS and Ubuntu, both ways", [g["os"] for g in trust] == [g["os"] for g in dns] == ["Windows", "macOS", "Ubuntu"])

# the listener: Python's standard library only (1.3.6.3)
folder = os.path.join(REPO, "src/fabriclib/setup/site/listener")
allowed = set(sys.stdlib_module_names)
for name in sorted(os.listdir(folder)):
    if name.endswith(".py"):
        with open(os.path.join(folder, name), encoding="utf-8") as f:
            tree = ast.parse(f.read())
        mods = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
        mods += [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module]
        bad = [m for m in mods if m.split(".")[0] not in allowed and not m.startswith("fabriclib.setup.site.listener")]
        check(f"listener/{name} imports the standard library and itself only", not bad, bad)

# who gets the site
with tempfile.TemporaryDirectory() as d:
    ctx = SetupContext(deploy_base=d)
    yes = lambda: True    # noqa: E731
    check("Guided on a new install, someone there: the site", site_wanted(ctx, "guided", False, yes))  # covers: cli:setup +
    check("Advanced stays in the terminal", not site_wanted(ctx, "advanced", False, yes))
    check("--terminal stays in the terminal", not site_wanted(ctx, "guided", True, yes))
    ctx.non_interactive = True
    check("unattended stays in the terminal", not site_wanted(ctx, "guided", False, yes))
    ctx.non_interactive, ctx.assume_yes = False, True
    check("--yes stays in the terminal", not site_wanted(ctx, "guided", False, yes))
    ctx.assume_yes = False
    saved_out, sys.stdout = sys.stdout, open(os.devnull, "w")
    no_systemd = site_wanted(ctx, "guided", False, lambda: False)
    sys.stdout = saved_out
    check("a host without systemd stays in the terminal", not no_systemd)
    os.makedirs(ctx.config_dir)
    open(ctx.vars_file, "w").close()
    check("an upgrade or a re-run stays in the terminal", not site_wanted(ctx, "guided", False, yes))

    # the install folder put back
    top = os.path.join(d, "tree")
    os.makedirs(os.path.join(top, "a"))
    keep = os.path.join(top, "a", "keep")
    with open(keep, "w") as f:
        f.write("before")
    snap = take_snapshot(top)
    with open(keep, "w") as f:
        f.write("after")
    os.makedirs(os.path.join(top, "b", "c"))
    with open(os.path.join(top, "b", "c", "new"), "w") as f:
        f.write("new")
    restore_snapshot(top, snap)
    check("a cancelled setup leaves the folder as found: new files and folders gone, a changed file put back",
          not os.path.exists(os.path.join(top, "b")) and open(keep).read() == "before")

    # the port's record: a killed run's record does not count
    record = os.path.join(d, "run", "site-port")
    write_port_record(record, 8443, "10.0.0.0/24")
    check("a running site's record is read", read_port_record(record) == {"port": 8443, "cidr": "10.0.0.0/24", "pid": os.getpid()})
    check("the record is root's alone", oct(os.stat(record).st_mode)[-3:] == "600" and oct(os.stat(os.path.dirname(record)).st_mode)[-3:] == "700")
    with open(record, "w") as f:
        f.write('{"port": 8443, "cidr": null, "pid": 999999999}')
    check("a record left by a killed process does not count", read_port_record(record) is None)

    # the firewall, with ufw's calls recorded (the real ufw: tests/sandbox/web_guided.sh)
    calls = []

    class R:
        returncode, stdout, stderr = 0, "", ""

    def fake(cmd, **k):
        calls.append(cmd)
        return R()

    answers = []
    saved_read = ask_module._read
    ask_module._read = lambda qid, prompt, secret=False: answers.pop(0)
    answers.append("y")
    check("ufw off: nothing is asked, nothing added", open_site_port(8443, "10.0.0.0/24", active=lambda: False, run=fake) is False and not calls)
    check("ufw on, yes: its rule added, from the LAN, carrying its comment", open_site_port(8443, "10.0.0.0/24", active=lambda: True, run=fake) is True  # covers: ask:setup.site_port +
          and calls[-1] == ["ufw", "allow", "from", "10.0.0.0/24", "to", "any", "port", "8443", "proto", "tcp", "comment", "fabric-setup-site"], calls)
    calls.clear()
    answers.append("n")
    try:
        open_site_port(8443, "10.0.0.0/24", active=lambda: True, run=fake)
        check("ufw on, no", False)
    except SetupError as e:  # covers: ask:setup.site_port -
        check("ufw on, no: refused, nothing added, saying what to do", "--terminal" in str(e) and "Nothing was changed" in str(e) and not calls, e)
    answers.append("what")
    answers.append("y")
    calls.clear()
    open_site_port(8443, None, active=lambda: True, run=fake)
    check("no LAN found: the rule says from any", calls[-1][3] == "any" and not answers, calls)
    ask_module._read = saved_read

    # the firewall step keeps a running site's port; close removes only what carries the comment
    write_port_record(record, 8444, "10.0.0.0/24")
    calls.clear()
    check("setup's firewall step keeps a running site's port", keep_site_port(record, fake) == 8444 and calls[-1][:3] == ["ufw", "allow", "from"], calls)
    os.remove(record)
    calls.clear()
    check("no site: the firewall step adds nothing", keep_site_port(record, fake) is None and not calls)

    class Added(R):
        stdout = ("Added user rules (see 'ufw status' for running firewall):\nufw allow 22/tcp\n"
                  "ufw allow from 10.0.0.0/24 to any port 8444 proto tcp comment 'fabric-setup-site'\n"
                  "ufw allow 8445/tcp comment 'mine'\n")

    deleted = []

    def fake_added(cmd, **k):
        if cmd[1] == "show":
            return Added()
        deleted.append(cmd)
        return R()

    write_port_record(record, 8444, None)
    removed = close_site_port(record, fake_added)
    check("close removes the site's rule, by its comment, and no other", len(removed) == 1 and "8444" in removed[0] and len(deleted) == 1 and deleted[0][:3] == ["ufw", "delete", "allow"], deleted)
    check("close removes the record", not os.path.exists(record))
    saved_run = hor.subprocess.run
    hor.subprocess.run = lambda cmd, **k: Added()
    own = hor.host_own_rules(d)
    hor.subprocess.run = saved_run
    check("the site's rule is not one of the host's own: the firewall step will not remove it", not any("8444" in r for r in own) and any("22/tcp" in r for r in own), own)

    # the plan says so
    pf.firewall_rules = lambda v, c: {"ssh": ["10.0.0.0/24"]}
    pf.ssh_ports = lambda: [22]
    pf.read_port_record = lambda: {"port": 8444, "cidr": None, "pid": 1}
    lines = pf.plan_firewall({}, d, active=False)
    check("the plan lists the site's port among the firewall's changes", any("8444/tcp (this setup's temporary site)" in x for x in lines), lines)
    pf.read_port_record = lambda: None
    check("no site: the plan does not mention one", not any("temporary site" in x for x in pf.plan_firewall({}, d, active=False)))

# the code; ask()'s front end
codes = {new_code() for _ in range(50)}
check("codes differ, in a readable alphabet", len(codes) == 50 and not any(c in "".join(codes) for c in "01OIL"), codes)


class Front:
    def __init__(self, *answers):
        self.answers, self.asked = list(answers), []

    def ask(self, qid, prompt, secret):
        self.asked.append((qid, prompt, secret))
        return self.answers.pop(0)


front = Front("  typed  ", "s3 cret ", "maybe", "y", "")
ask_module.use_front_end(front)
check("ask() goes to the front end, its answer stripped as on the terminal", ask_module.ask("a.b", "P: ") == "typed")
check("ask_secret() goes to it too, marked secret, the answer as typed", ask_module.ask_secret("a.c", "S: ") == "s3 cret " and front.asked[-1][2] is True)
check("ask_yes_no() goes to it too, a bad answer asked again", ask_module.ask_yes_no("a.d", "Sure", False) is True and len(front.answers) == 1)
check("Enter takes ask()'s default", ask_module.ask("a.e", "P [x]: ", "x") == "x")
ask_module.use_front_end(None)
check("back to the terminal", ask_module._front_end is None)

# real addresses, from a stand-in `ip`


class Ip:
    returncode = 0
    stdout = ("1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet 192.168.5.9/24 brd x\n3: docker0    inet 172.17.0.1/16\n"
              "4: br-abc    inet 10.255.0.1/24\n5: eth1    inet 10.1.1.1/24\n")


check("a host's addresses: the detected first, then others, no loopback or containers' bridges",
      host_addresses("10.1.1.1", lambda *a, **k: Ip()) == ["10.1.1.1", "192.168.5.9"], host_addresses("10.1.1.1", lambda *a, **k: Ip()))
check("the rule's words", site_rule(8443, None)[:2] == ["from", "any"])
check("(the shell can run ufw's words)", isinstance(subprocess.list2cmdline(site_rule(8443, "10.0.0.0/8")), str))

sys.exit(finish("guides_test"))
