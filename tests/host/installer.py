"""The installer test (manual 3.1.2): `sudo fabricctl setup` driven through a real terminal on a test host, as a
person who gets things wrong would — every question first given answers it must refuse, each refusal checked by its
message, then the good answer. Two runs:
  1. a fresh host with ufw already on: every refusal, then the host firewall declined — setup must stop before any
     step, saying why (2.1.2.12), with nothing started;
  2. the same host again: valid answers (an invalid plan choice and consent answer first), everything allowed —
     setup must finish, then doctor, and the checks a person would make (the domain on IPv4 only, 2.1.6.29; the landing
     page at the host's own name; the host's own ufw rules kept beside fabric's).
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
AD = suggested_ad_domain(DOMAIN)        # what Enter takes (2.1.6.11: a sibling of a domain of three labels or more)
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
    ("domain", r"DNS domain for this network.*\]: $"),
    ("hostname", r"Name of this host.*\]: $"),
    ("host_ip", r"LAN IP address of this host.*\]: $"),
    ("lan_cidr", r"LAN subnet \(CIDR\).*\]: $"),
    ("lan_gateway", r"LAN gateway \(router\) IP.*\]: $"),
    ("friendly_name", r"Organisation / network name.*\]: $"),
    ("admin", r"Username of the first web UI admin.*\]: $"),
    ("ad_domain", r"AD domain( \[[^\]]*\])?: $"),
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
    ("admin_pw", r"Password for [^:\n]+: $"),
    ("admin_pw2", r"The same again: $"),
    ("plan", r"\[P\]roceed.*\[Q\]uit\? $"),
    ("consent", r"Allow these changes\? \[y/n\] $"),
]


def drive(answers, consent, log):
    """Run `sudo fabricctl setup` in a terminal, answering each question from answers[name] in turn ("" = Enter
    when a list runs out; consent(title) for the host-change questions). Returns (exit status, transcript, the
    questions in the order asked)."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("ssh", ["ssh", "-tt", "-o", "BatchMode=yes", "-i", KEY, TARGET, "sudo fabricctl setup"])
    screen, transcript, asked, last, last_title = "", "", [], time.time(), ""
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
                tail = re.sub(r"\x1b\[[0-9;]*m", "", screen[-500:])
                for name, pattern in PROMPTS:
                    if re.search(pattern, tail):
                        if name == "consent":
                            title = re.findall(r"\n  (\S[^\n(]*?) \((?:required|recommended|optional|choice)",
                                               re.sub(r"\x1b\[[0-9;]*m", "", screen))
                            if title:
                                last_title = title[-1].strip()      # a question asked again shows no title
                            answer = consent(last_title)
                        else:
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
    "hostname": ["has.dot", "averyveryverylonghostname", "localhost", "bad_name", ""],
    "host_ip": ["999.1.1.1", "abc", FOREIGN_IP, "", ""],
    "lan_cidr": ["192.168.4.0/33", "nope", "", "", ""],
    "lan_gateway": ["300.1.1.1", "", HOST_IP, ""],
    "friendly_name": ['a"quote', "<b>", "x" * 41, "Fabric Installer Test"],
    "admin": ["administrator", "root", "fabric-agent", "Bad User", ""],
    "ad_domain": [DOMAIN, DOMAIN.split(".")[-1], "ad.local", "ad_x." + DOMAIN, ""],
    # too short (the default policy: 12), containing the user name, then two that differ, then a good one twice
    "admin_pw": ["short", "xFabric-Admin-9", "Good-Pass-1234", "Good-Pass-1234"],
    "admin_pw2": ["nope", "Good-Pass-1234"],
    "plan": ["x", "p"],
}
consent_seen = []


def decline_firewall(title):
    consent_seen.append(title)
    if len(consent_seen) == 1:
        return "maybe"                 # not y or n: asked again
    return "n" if title == "Ports fabric needs" else "y"


code, text, asked = drive(bad, decline_firewall, f"{OUT}/run1.log")
EXPECT = [
    ("a single label, .local, an underscore, a leading hyphen: refused as a domain", "not a valid domain", 4),
    ("a dot, 25 characters (over NetBIOS's 15), localhost, an underscore: refused as the host name",
     "not a valid hostname", 4),
    ("an impossible address, text: refused as the host's address", "not a valid host_ip", 2),
    ("a /33, text: refused as the subnet", "not a valid lan_cidr", 2),
    ("an impossible gateway: refused", "not a valid lan_gateway", 1),
    ("an address this machine does not have: the network asked again", "is not an address of this machine", 1),
    ("the gateway given as the host's own address: the network asked again", "are both", 1),
    ("a quote, <>, 41 characters: refused as the organisation's name", "not a valid friendly_name", 3),
    ("administrator, root, a fabric- name, a capital and a space: refused as the first admin",
     "not a valid webui_admin_user", 4),
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
check("the plan asked again after an answer that is no choice", names.count("plan") == 2, names.count("plan"))
check("a consent question asked again after an answer that is not y or n",
      len(consent_seen) >= 2 and consent_seen[0] == consent_seen[1], consent_seen[:3])
check(f"the Enter defaults: the suggested AD domain ({AD}) and the host name it found",
      f"[{AD}]" in text and guess_host in text, (AD, guess_host))
# covers: cli:setup ask:consent.* -
check("declining the ports fabric needs with ufw on stops setup before any step, saying why (2.1.2.12, 2.1.2.13)",
      code != 0 and "ufw is on, and without fabric's firewall rules it blocks" in text and "[preflight]" not in text,
      (code, text[-800:]))
check("…and securing and the host's own rules were not asked (they need the ports)",
      "Secure this host" not in consent_seen and "The host's own firewall rules" not in consent_seen, consent_seen)
check("…and nothing was started or changed: no containers, ufw's rules as they were",
      R("docker ps -q | wc -l").strip() == "0"
      and R("ufw status | grep -iE 'ALLOW|DENY' | grep -v '(v6)'") == own_rules)

# ---- run 2: valid answers, everything allowed; the install finished and looked at
good = {
    "domain": [DOMAIN], "friendly_name": ["Fabric Installer Test"], "plan": ["p"], "admin_pw": ["Good-Pass-1234"],
    "admin_pw2": ["Good-Pass-1234"],
}
seen2 = []


def keep_own(title):
    seen2.append(title)
    return "n" if title == "The host's own firewall rules" else "y"


code, text, asked = drive(good, keep_own, f"{OUT}/run2.log")
check("the three firewall questions, in order: the ports, securing, then the host's own rules (they exist here)",
      [t for t in seen2 if t in ("Ports fabric needs", "Secure this host", "The host's own firewall rules")]
      == ["Ports fabric needs", "Secure this host", "The host's own firewall rules"], seen2)
# covers: cli:setup ask:consent.* ask:setup.vars.* ask:setup.ad_domain ask:setup.admin_password ask:setup.admin_password_again ask:setup.plan +
check("with everything allowed, setup finishes (fabric is ready)", code == 0 and "fabric is ready" in text,
      (code, text[-1500:]))
first, signin = text.find("FIRST install fabric's root certificate"), text.find("then sign in")
fingerprint = R("openssl x509 -in /opt/nginx/www/certs/root-ca.crt -noout -fingerprint -sha256 | cut -d= -f2")
check("setup's last words: FIRST the root certificate from the landing page (plain HTTP, its fingerprint), "
      "then sign in at the console", 0 <= first < signin and f"http://info.{DOMAIN}/" in text[first:signin]
      and fingerprint.strip() and fingerprint.strip() in text[first:signin]
      and f"https://fabric.{DOMAIN}" in text[signin:], text[-1500:])
saved = yaml.safe_load(R("cat /opt/fabric/config/vars.yaml")) or {}
# covers: setting:webui_admin_user +
check("Enter took fabric-admin as the first admin; the console's role is fabric-console-admin; Kerberos off; the "
      "default policy; all the memory (2.1.2.16, 2.1.6.32, 2.1.6.33, 2.1.6.35)",
      saved.get("webui_admin_user") == "fabric-admin" and saved.get("webui_admin_role") == "fabric-console-admin"
      and saved.get("signin_kerberos") is False and (saved.get("ad_password_policy") or {}).get("minimum_length") == 12
      and (saved.get("ad_password_policy") or {}).get("lockout_threshold") == 10
      and int(saved.get("host_ram_capacity") or 0) >= 4,
      {k: saved.get(k) for k in ("webui_admin_user", "webui_admin_role", "signin_kerberos", "ad_password_policy",
                                 "host_ram_capacity")})
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
check("own rules removed (yes): only fabric's ports and SSH left, the 9090 and OpenSSH rules gone",
      len(added) < len(own_added) and not any("9090" in ln or "OpenSSH" in ln for ln in added), added)
check("…and SSH still works (fabric's SSH rule from the LAN)", R("echo ok").strip() == "ok")
R("fabricctl setup --undo firewall --yes >/tmp/undo-firewall.log 2>&1")
back = [ln for ln in R("ufw show added").splitlines() if ln.startswith("ufw ")]
check("undoing the firewall puts the host's own rules back", any("9090" in ln for ln in back)
      and any("OpenSSH" in ln for ln in back), back)
R("fabricctl setup --step firewall --non-interactive --approve ports,firewall --decline own_rules >/dev/null 2>&1")
check("the firewall set up again for the person to use (own rules kept)",
      "Default: deny (incoming)" in R("ufw status verbose") and any("9090" in ln for ln in
                                                                    R("ufw show added").splitlines()))
print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
