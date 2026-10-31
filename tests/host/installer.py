"""The installer test (manual 3.1.2): `sudo fabricctl setup` driven through a real terminal on a test host, as a
person who gets things wrong would — every question first given answers it must refuse, each refusal checked by its
message, then the good answer. Two runs (setup's start, menu and plan: manual 1.2.9.11):
  1. a fresh host with ufw already on, Guided: every refusal, then the plan's Menu, where the ports fabric needs are
     turned off (securing and the host's own rules go with them), and Proceed — setup must stop before any step,
     saying why (2.1.2.12), with nothing started;
  2. the same host again, Advanced: the menu (Proceed refused until the required items have values; the ports turned
     back on, the host's own rules kept), the plan's one yes — setup must finish, then doctor, and the checks a person
     would make (the domain on IPv4 only, 2.1.6.29; the landing page at the host's own name; the host's own ufw rules
     kept beside fabric's).
Then a dropped connection (2.1.2.26): setup run again, its SSH connection killed in the certificates step — the work
goes on as fabric-setup.service, and `sudo fabricctl setup` re-attaches, asking nothing, and ends with its result.
The host is left installed for a person to look at. Run from a Linux machine that reaches the host with a key:
    TARGET=tempuser@192.168.5.57 KEY=~/.ssh/fabric-test_ed25519 HOST_IP=192.168.5.57 DOMAIN=home.arpa \\
        python3 tests/host/installer.py
The host needs fabricctl installed (apt) and nothing of fabric's set up (the script uninstalls a previous install).
"""
import os
import pty
import re
import select
import subprocess
import sys
import time

import yaml

TARGET, KEY = os.environ["TARGET"], os.path.expanduser(os.environ["KEY"])
HOST_IP, DOMAIN = os.environ["HOST_IP"], os.environ.get("DOMAIN", "home.arpa")
FOREIGN_IP = os.environ.get("FOREIGN_IP", "192.168.7.250")    # in the host's subnet, but not one of its addresses
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "src"))
from fabriclib.samba.suggested_ad_domain import suggested_ad_domain  # noqa: E402
from fabriclib.samba.suggested_dc_name import suggested_dc_name  # noqa: E402
AD = suggested_ad_domain(DOMAIN)        # what Enter takes (2.1.6.11: a sibling of a domain of three labels or more)
ADMIN = "rehearse.admin"                # the first Directory Administrator, named (2.1.6.69: no default)
OUT = os.environ.get("OUT", "/tmp/fabric-tests/installer")
SSH = ["ssh", "-o", "BatchMode=yes", "-i", KEY, TARGET]
PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[-600:]}"), flush=True)


def R(cmd):
    """A command on the host as root; its output."""
    return subprocess.run(SSH + [f"sudo -n bash -lc {subprocess.list2cmdline([cmd])}"], capture_output=True,
                          text=True).stdout


# (question, the end of its prompt) — matched against the last characters on the screen
PROMPTS = [
    ("domain", r"DNS domain \(e\.g\. home\.arpa\).*\]: $"),
    ("hostname", r"This host's name.*\]: $"),
    ("host_ip", r"This host's LAN address.*\]: $"),
    ("lan_cidr", r"LAN subnet \(CIDR\).*\]: $"),
    ("lan_gateway", r"LAN gateway \(router\).*\]: $"),
    ("friendly_name", r"Organisation's name.*\]: $"),
    ("admin", r"First Directory Administrator's user name.*\]: $"),     # 2.1.6.69: their own, never fabric-admin
    ("first", r"Their first name.*\]: $"),
    ("last", r"Their last name.*\]: $"),
    ("email", r"Their e-mail address.*\]: $"),
    ("ad_domain", r"Windows \(AD\) domain.*: $"),
    ("min_length", r"Minimum password length.*: $"),
    ("history", r"Previous passwords remembered.*: $"),
    ("min_age", r"Days before a new password may be changed.*: $"),
    ("max_age", r"Days a password is valid.*: $"),
    ("threshold", r"Lock an account after how many failed sign-ins.*: $"),
    ("window", r"counting the failures over how many minutes.*: $"),
    ("lock", r"then keep it locked for how many minutes.*: $"),
    ("complexity", r"\(complexity\) \[y/n\].*: $"),
    ("memory", r"GB of memory fabric may use \[\d+\]: $"),
    ("kerberos", r"Turn it on now\? \[y/N\]: $"),
    ("admin_pw", r"Password for [^\n]+\(web console sign-in, not shown\): $"),
    ("admin_pw2", r"The same again: $"),
    ("mode", r"Guided, Advanced or Quit\? \[G/a/q\] $"),
    ("menu", r"\[P\]roceed.*a number to change it, or \[Q\]uit: $"),
    ("plan", r"\[P\]roceed.*\[Q\]uit\? $"),
    ("yesno", r"\? \[[Yy]/[nN]\] $"),
]


def drive(answers, log, drop_at=None):
    """Run `sudo fabricctl setup` in a terminal, answering each question from answers[name] in turn ("" = Enter
    when a list runs out); with drop_at, the SSH client is killed once the screen shows it (the connection drops).
    Returns (exit status, transcript, the questions in the order asked)."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("ssh", ["ssh", "-tt", "-o", "BatchMode=yes", "-i", KEY, TARGET, "sudo fabricctl setup"])
    screen, transcript, asked, last = "", "", [], time.time()
    with open(log, "w") as out:
        while True:
            r, _, _ = select.select([fd], [], [], 1)
            if r:
                try:
                    data = os.read(fd, 4096).decode("utf-8", "replace")
                except OSError:
                    break
                if not data:
                    break
                screen += data
                transcript += data
                out.write(data)
                out.flush()
                last = time.time()
                if drop_at and drop_at in transcript:
                    os.kill(pid, 9)
                    break
                tail = re.sub(r"\x1b\[[0-9;]*m", "", screen[-500:])
                for name, pattern in PROMPTS:
                    if re.search(pattern, tail):
                        queue = answers.get(name, [])
                        answer = queue.pop(0) if queue else ""
                        asked.append((name, answer))
                        os.write(fd, (answer + "\r").encode())
                        screen = ""
                        break
            elif time.time() - last > 900:
                print("no output for 15 minutes: stopped", flush=True)
                os.kill(pid, 9)
                break
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), re.sub(r"\x1b\[[0-9;]*m", "", transcript), asked


os.makedirs(OUT, exist_ok=True)
print("--- the host: a previous install removed, ufw on with the owner's own rules, fabricctl installed", flush=True)
R("fabricctl uninstall --yes --no-export >/dev/null 2>&1; apt-get update -qq; "
  "apt-get install -y -qq fabricctl >/dev/null 2>&1")
own_rules = R("ufw status | grep -iE 'ALLOW|DENY' | grep -v '(v6)'")
check("the host is clean and ufw is on with rules of its own",
      "Status: active" in R("ufw status") and own_rules.strip()
      and not R("ls /opt/fabric/config/vars.yaml 2>/dev/null"),
      own_rules)
guess_host = R("hostname -s").strip()
guess_net = R("ip -4 route show default").split()

# ---- run 1: every wrong answer refused, then the firewall declined
bad = {
    "domain": ["lan", "home.local", "bad_name.arpa", "-x.arpa", DOMAIN],
    "hostname": ["has.dot", "a" * 64, "localhost", "bad_name", ""],
    "host_ip": ["999.1.1.1", "abc", FOREIGN_IP, "", ""],
    "lan_cidr": ["192.168.4.0/33", "nope", "", "", ""],
    "lan_gateway": ["300.1.1.1", "", HOST_IP, ""],
    "friendly_name": ['a"quote', "<b>", "x" * 41, "Fabric Installer Test"],
    "admin": ["administrator", "root", "fabric-agent", "Bad User", "fabric-admin", "", ADMIN],
    "first": ["", "<b>", "Rehearse"],
    "last": ["", "Admin"],
    "email": ["nope", ""],
    "ad_domain": [DOMAIN, DOMAIN.split(".")[-1], "ad.local", "ad_x." + DOMAIN, ""],
    # too short (the default policy: 12), containing the user name, then two that differ, then a good one twice
    "admin_pw": ["short", "x" + ADMIN.title() + "-9", "Good-Pass-1234", "Good-Pass-1234"],
    "admin_pw2": ["nope", "Good-Pass-1234"],
    "mode": ["x", "g"],
    # the plan: no choice, then the menu (a number not on the list, the ports turned off), then Proceed
    "plan": ["x", "m", "p"],
    "menu": ["99", "14", "p"],          # 14: the ports fabric needs
    "yesno": ["n"],
}
code, text, asked = drive(bad, f"{OUT}/run1.log")
EXPECT = [
    ("a single label, .local, an underscore, a leading hyphen: refused as a domain", "not a valid domain", 4),
    ("a dot, 64 characters (over a DNS label's 63), localhost, an underscore: refused as the host name",
     "not a valid hostname", 4),
    ("an impossible address, text: refused as the host's address", "not a valid host_ip", 2),
    ("a /33, text: refused as the subnet", "not a valid lan_cidr", 2),
    ("an impossible gateway: refused", "not a valid lan_gateway", 1),
    ("an address this machine does not have: the network asked again", "is not an address of this machine", 1),
    ("the gateway given as the host's own address: the network asked again", "are both", 1),
    ("a quote, <>, 41 characters: refused as the organisation's name", "not a valid friendly_name", 3),
    ("administrator, root, a fabric- name, a capital and a space, fabric-admin (break glass, 2.1.6.69) and none: "
     "refused as the first admin", "not a valid webui_admin_user", 6),
    ("the first admin's first name: none, <b>: refused", "not a valid webui_admin_first_name", 2),
    ("...their last name: none, refused", "not a valid webui_admin_last_name", 1),
    ("...their e-mail address: not one, refused; none taken (it is optional, 2.1.6.93)",
     "not a valid webui_admin_email", 1),
    ("fabric's own domain, its parent, .local, an underscore: refused as the AD domain",
     "a domain of two labels or more", 4),
    ("the first admin's password: shorter than the default policy (12), refused", "at least 12 characters", 1),
    ("...containing the user name, refused", "not containing your user name", 1),
    ("...typed differently the second time, asked again", "the two differ", 1),
]
for name, needle, count in EXPECT:
    # covers: ask:setup.vars.* ask:setup.ad_domain ask:setup.admin_password ask:setup.admin_password_again -
    # covers: setting:domain setting:hostname setting:host_ip setting:lan_cidr setting:lan_gateway -
    # covers: setting:friendly_name setting:webui_admin_user setting:ad_domain -
    check(name, text.count(needle) >= count, (text.count(needle), needle))
names = [n for n, _ in asked]
check("only what cannot change later is asked (2.1.2.16): no password policy, memory or Kerberos question",
      not {"min_length", "history", "min_age", "max_age", "threshold", "window", "lock", "complexity", "memory",
           "kerberos"} & set(names) and "password policy: fabric's default" in text, names)
# covers: ask:setup.mode ask:setup.plan ask:setup.menu ask:setup.consent.* -
check("the start, the plan and the menu ask again after an answer that is no choice, saying which",
      names.count("mode") == 2 and "answer g (guided), a (advanced) or q (quit)" in text
      and names.count("plan") == 3 and "'x': answer p, m or q" in text
      and "'99' is not on the list: a number from 1 to" in text, names)
check("no separate consent question: the plan lists every host change and Proceed is the one yes (2.1.2.18)",
      "consent" not in names and "Packages (required)" in text and "[P]roceed allows all of these" in text, names)
check(f"the Enter defaults: the suggested AD domain ({AD}) and the host name it found",
      f"[{AD}]" in text and guess_host in text, (AD, guess_host))
# covers: cli:setup -
check("declining the ports fabric needs in the menu with ufw on stops setup before any step, saying why "
      "(2.1.2.12, 2.1.2.13)",
      code != 0 and "ufw is on, and without fabric's firewall rules it blocks" in text and "[preflight]" not in text,
      (code, text[-800:]))
check("…the menu said what declining them means, and took securing and the host's own rules along (they need the "
      "ports)", "If no: ufw is not told about fabric's ports" in text and "also off: Secure this host" in text
      and "also off: The host's own firewall rules" in text, text[-1500:])
check("…and nothing was started or changed: no containers, ufw's rules as they were",
      R("docker ps -q | wc -l").strip() == "0"
      and R("ufw status | grep -iE 'ALLOW|DENY' | grep -v '(v6)'") == own_rules)

# ---- run 2: valid answers, everything allowed; the install finished and looked at
good = {
    "mode": ["a"],
    # Proceed before the required items have values (refused), the domain, the organisation, the first admin; the host's
    # own rules turned on (the ports and securing come back with them), then off again (kept beside fabric's)
    "menu": ["p", "1", "3", "6", "16", "16", "p"],    # 6: the first admin; 16: the host's own rules
    "yesno": ["y", "n"],
    "domain": [DOMAIN], "friendly_name": ["Fabric Installer Test"], "admin": [ADMIN], "first": ["Rehearse"],
    "last": ["Admin"], "email": [""], "plan": ["p"],
    "admin_pw": ["Good-Pass-1234"], "admin_pw2": ["Good-Pass-1234"],
}
code, text, asked = drive(good, f"{OUT}/run2.log")
check("Advanced: the menu's Proceed waits for the organisation and the first admin's password, naming them",
      "not yet: 3, 6 need an answer" in text, text[:3000])
check("the plan lists the ports and securing, in order, and the host's own rules under Not made (kept)",
      0 <= text.rfind("Ports fabric needs (recommended)") < text.rfind("Secure this host (recommended)")
      and "The host's own firewall rules: the host's own rules stay" in text, text[-3000:])
# covers: cli:setup ask:setup.mode ask:setup.menu ask:setup.consent.* ask:setup.vars.* ask:setup.ad_domain +
# covers: ask:setup.admin_password ask:setup.admin_password_again ask:setup.plan +
check("with everything allowed, setup finishes (fabric is ready)", code == 0 and "fabric is ready" in text,
      (code, text[-1500:]))
names, first, signin = (text.find("FIRST point the computer"), text.find("install fabric's root certificate"),
                        text.find("then sign in"))
fingerprint = R("openssl x509 -in /opt/nginx/www/certs/root-ca.crt -noout -fingerprint -sha256 | cut -d= -f2")
check("setup's last words: FIRST fabric's names (its DNS at the host's address, or the hosts-file line naming info, "
      "fabric-ctl and sso), then the root certificate over plain HTTP by address (its fingerprint), then sign in",
      0 <= names < first < signin and "set its DNS server to" in text[names:first]
      and f"info.{DOMAIN}" in text[names:first] and f"sso.{DOMAIN}" in text[names:first]
      and "/certs/" in text[first:signin]
      and fingerprint.strip() and fingerprint.strip() in text[first:signin]
      and f"https://fabric-ctl.{DOMAIN}" in text[signin:], text[-1500:])
saved = yaml.safe_load(R("cat /opt/fabric/config/vars.yaml")) or {}
# covers: setting:webui_admin_user +
check("the first admin as named, never fabric-admin (2.1.6.69); the console's role is fabric-console-admin; "
      "Kerberos off; the default policy; all the memory (2.1.2.16, 2.1.6.32, 2.1.6.33, 2.1.6.35)",
      saved.get("webui_admin_user") == ADMIN and saved.get("webui_admin_first_name") == "Rehearse"
      and saved.get("webui_admin_last_name") == "Admin" and saved.get("webui_admin_role") == "fabric-console-admin"
      and saved.get("signin_kerberos") is False and (saved.get("ad_password_policy") or {}).get("minimum_length") == 12
      and (saved.get("ad_password_policy") or {}).get("lockout_threshold") == 10
      and int(saved.get("host_ram_capacity") or 0) >= 4,
      {k: saved.get(k) for k in ("webui_admin_user", "webui_admin_first_name", "webui_admin_last_name", "webui_admin_role", "signin_kerberos", "ad_password_policy",
                                 "host_ram_capacity")})
check("Advanced: no question or menu item names the DC; it is dc-0001 (2.1.6.65), never the host's own name "
      "(2.3.1.21.2)", saved.get("dc_name") == suggested_dc_name() != guess_host and "Domain controller's name" not in text,
      saved.get("dc_name"))
check("the first admin was created with the chosen password; none written to the login kit",
      "created in the directory with the password chosen in setup" in text
      and not R("find /home /root -path '*/fabric-admin/initial-password.txt' -newer /opt/fabric/config/fabric.yaml "
                "2>/dev/null"), text[-1500:])
doctor = R("fabricctl doctor 2>&1")
check("doctor passes", "✗" not in doctor and "✓" in doctor, doctor[-1500:])
aaaa = R(f"dig +short AAAA {AD} @{HOST_IP}; dig +short AAAA $(hostname -s).{AD} @{HOST_IP}")
check("the domain on IPv4 only: no AAAA for the AD domain or its DC, though the host has IPv6 (2.1.6.29)",
      aaaa.strip() == "" and R(f"dig +short A {AD} @{HOST_IP}").strip() == HOST_IP,
      (aaaa, R("ip -6 addr show scope global | grep inet6")))
landing = R(f"curl -sL --resolve {guess_host}.{DOMAIN}:443:{HOST_IP} --resolve info.{DOMAIN}:443:{HOST_IP} "
            f"https://{guess_host}.{DOMAIN}/ --cacert /opt/stepca/data/certs/root_ca.crt")
check("the host's own name leads to the info page, trusted (2.1.4.3; not a bare 404)",
      "Fabric Landing Portal" in landing, landing[:300])
plain = R(f"curl -s --resolve info.{DOMAIN}:80:{HOST_IP} -o /dev/null -w '%{{http_code}}' http://info.{DOMAIN}/; "
          f"curl -s --resolve info.{DOMAIN}:80:{HOST_IP} http://info.{DOMAIN}/certs/root-ca.pem | head -1")
check("the info page over plain HTTP, no redirect, with the root CA to download (2.1.4.3)",
      plain.startswith("200") and "BEGIN CERTIFICATE" in plain, plain[:200])
after = R("ufw status | grep -iE 'ALLOW|DENY' | grep -v '(v6)'")
check("the host's own ufw rules kept beside fabric's (answered no)", all(line in after for line in own_rules.splitlines()),
      after)
check("secured: ufw on, incoming denied by default", "Default: deny (incoming)" in R("ufw status verbose"))

# ---- the host's own rules removed (yes), then put back by undoing the firewall
own_added = [ln for ln in R("ufw show added").splitlines() if ln.startswith("ufw ")]
R("fabricctl setup --step firewall --non-interactive --approve own_rules >/tmp/own-rules.log 2>&1")
added = [ln for ln in R("ufw show added").splitlines() if ln.startswith("ufw ")]
# the host's own rules are whatever it had (rehearsal 3 found a host without the OpenSSH rule a check had assumed)
removed = [ln for ln in own_added if ln not in added]
check("own rules removed (yes): only fabric's ports and SSH left, the host's own rules gone",
      removed and not any(ln in added for ln in removed), (removed, added))
check("…and SSH still works (fabric's SSH rule from the LAN)", R("echo ok").strip() == "ok")
R("fabricctl setup --undo firewall --yes >/tmp/undo-firewall.log 2>&1")
back = [ln for ln in R("ufw show added").splitlines() if ln.startswith("ufw ")]
check("undoing the firewall puts the host's own rules back, every one removed", removed
      and all(ln in back for ln in removed), (removed, back))
R("fabricctl setup --step firewall --non-interactive --approve ports,firewall --decline own_rules >/dev/null 2>&1")
check("the firewall set up again for the person to use (own rules kept)",
      "Default: deny (incoming)" in R("ufw status verbose")
      and all(ln in R("ufw show added").splitlines() for ln in removed))

# ---- a dropped connection (2.1.2.26): the work goes on; setup again re-attaches and ends with the result
code, text, asked = drive({"plan": ["p"]}, f"{OUT}/run3-dropped.log", drop_at="[certs]")
time.sleep(3)
check("the connection dropped in the certificates step: the console is gone, fabric-setup.service goes on",
      "[certs]" in text and "runs as fabric-setup.service" in text
      and R("systemctl is-active fabric-setup.service").strip() == "active", text[-1500:])
code, text, asked = drive({}, f"{OUT}/run4-reattach.log")
# covers: cli:setup +
check("sudo fabricctl setup re-attaches: no question, the run from its start to fabric is ready, exit 0",
      code == 0 and not asked and "a setup is already running" in text and "fabric is ready" in text,
      (code, asked, text[-1500:]))
check("…and the unit is gone once it ended (--collect), the run recorded done",
      R("systemctl is-active fabric-setup.service").strip() != "active"
      and "state: done" in R("cat /opt/fabric/config/setup-run.yaml"))
print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
