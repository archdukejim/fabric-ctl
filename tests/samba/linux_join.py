"""The `samba` suite, Linux machines joining AD (manual 1.6.7, 1.6.5.19, S6): real Ubuntu 24.04 and 26.04
containers run fabric's join-linux.sh as rendered against a converged test DC. Proves: the installer refuses a wrong
root-CA fingerprint and changes nothing; a join with a site admin's password and one with a one-time join password
(`fabricctl domain add-machine`); `id` with fabric's own ids; a password logon through PAM and a Kerberos ticket;
sudo for a site admin (2.1.9.13's rule) and none for a person; a person of another site refused by the site's log-on
GPO; cached logons with the DC stopped; then a log-on policy on OU=machines (manual 1.6.11.4) naming a group adam is in
and alice is not: adam logs on, alice is refused; and a sudo rule on a host group (1.6.11.7) holding the 24.04 machine:
it applies there and not on the 26.04 one. The containers have no systemd: a stand-in `systemctl` starts sssd.
    sudo python3 tests/samba/linux_join.py
"""
import json
import os
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.dirname(os.path.abspath(__file__))]
from start_dc import POLICY, start_dc  # noqa: E402
import fabriclib.directory.add_machine as m_add_machine  # noqa: E402
from fabriclib.directory.run_op import run_op  # noqa: E402
from fabriclib.samba.converge_domain import converge_domain  # noqa: E402
from fabriclib.secrets.random_password import random_password  # noqa: E402

W = os.path.join(os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests"), "samba-linux-join")
NET, SUBNET, IP, WEB_IP = "linuxjoin_net", "10.254.33.0/24", "10.254.33.10", "10.254.33.20"
DC, WEB = "ljdc", "lj-certs"
# release -> (container image, machine name): Ubuntu, and Debian (what Proxmox VE 8 and 9 are built on)
IMAGES = {"24.04": "ubuntu:24.04", "26.04": "ubuntu:26.04", "debian-12": "debian:12", "debian-13": "debian:13"}
RELEASES = {"24.04": "ws2404", "26.04": "ws2604", "debian-12": "wsdeb12", "debian-13": "wsdeb13"}
PW = "Correct-Horse-9-" + random_password(8)
FAILED = 0
m_add_machine.write_audit = lambda *a, **k: None


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[-700:]}"))


def sh(cmd, ok=True, **kw):
    res = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if ok and res.returncode:
        raise SystemExit(f"failed: {cmd[:6]}\n{res.stdout[-1500:]}{res.stderr[-1500:]}")
    return res


def on(box, script, stdin=None):
    """Run a shell script in a client container as root; the output is stdout + stderr."""
    res = sh(["docker", "exec", "-i", box, "bash", "-c", script], ok=False, input=stdin)
    return res.returncode, res.stdout + res.stderr


def dc_healthy():
    return sh(["docker", "inspect", "-f", "{{.State.Health.Status}}", DC], ok=False).stdout.strip() == "healthy"


def cleanup():
    sh(["docker", "rm", "-f", DC, WEB, *[f"lj-{r}" for r in RELEASES.values()]], ok=False)
    sh(["docker", "network", "rm", NET], ok=False)


cleanup()
dc = start_dc(os.path.join(W, "dc"), DC, NET, SUBNET, IP)
V, SECRETS = dc["v"], dc["secrets"]
check("a converged DC (its site's sudo rule included)", dc_healthy())
sudo_rule = sh(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb", "(objectClass=sudoRole)",
                "sudoUser", "sudoHost", "sudoCommand"], ok=False).stdout
check("the site's sudo rule: its fabric-admins and, at the root, the organisation's may run anything; the console's "
      "admin group and the old linux-sudo role are not in it (1.6.11.3, 2.1.6.37, 2.1.6.41)",
      "sudoUser: %lan-fabric-admins" in sudo_rule and "sudoUser: %fabric-admins" in sudo_rule
      and "sudoCommand: ALL" in sudo_rule and "%admins" not in sudo_rule and "linux-sudo" not in sudo_rule, sudo_rule)

# people: alice (a person of lan), adam (a lan admin and one of its fabric-admins), lara (a person of another site, lab)
lab = {"site": "lab", "root": False, "parent": "lan", "password_policy": POLICY, "networks": [],
       "root_ca_pem": open(dc["root_ca"]).read(), "id_range": "200001-300000", "groups": [], "admin_group": "admins",
       "accounts": {f"fabric-{k}-lab": random_password() for k in ("agent", "keycloak", "radius")}, "radius_gid": 610}
sh(["docker", "exec", "-i", DC, "python3", "/fabric/converge.py"], input=json.dumps(lab))
lab_v = {**V, "site_name": "lab"}
lab_s = {**SECRETS, "ad_agent_password": lab["accounts"]["fabric-agent-lab"]}
ids = {}
for uid, site_v, sec in (("alice", V, SECRETS), ("adam", V, SECRETS), ("lara", lab_v, lab_s)):
    made = run_op(site_v, sec, "create_person", {"uid": uid, "first": uid.title(), "last": "Test",
                                                  "email": f"{uid}@lan.test", "password": "Ot-" + random_password(20),
                                                  "gid": 5000, "home_base": "/home", "shell": "/bin/bash"}, DC)
    ids[uid] = made["uidNumber"]
run_op(V, SECRETS, "add_group_member", {"group": "lan-admins", "uid": "adam"}, DC)
run_op(V, SECRETS, "add_group_member", {"group": "lan-fabric-admins", "uid": "adam"}, DC)   # sudo (1.6.11.3)
set_pw = f"""
import sys
sys.path.insert(0, "/fabric")
from open_samdb import open_samdb
samdb, lp = open_samdb("/data/etc/smb.conf")
for uid in ("alice", "adam", "lara"):          # as Keycloak's first sign-in would: their own password
    samdb.setpassword("(sAMAccountName=%s)" % uid, {PW!r}, force_change_at_next_login=False)
print("set")
"""
check("people in the domain: alice and adam (lan; adam a site admin), lara (lab)",
      "set" in sh(["docker", "exec", "-i", DC, "python3", "-"], input=set_pw, ok=False).stdout, ids)

# info.<domain>/certs/: the root CA served over plain HTTP, as nginx serves it (1.5.1.5)
os.makedirs(os.path.join(W, "www", "certs"), exist_ok=True)
with open(os.path.join(W, "www", "certs", "root-ca.crt"), "w") as f:
    f.write(open(dc["root_ca"]).read())
sh(["docker", "run", "-d", "--name", WEB, "--network", NET, "--ip", WEB_IP, "-v", f"{W}/www:/srv:ro",
    "--entrypoint", "python3", "fabric/samba:test", "-m", "http.server", "80", "--directory", "/srv"])
fp = sh(["openssl", "x509", "-in", dc["root_ca"], "-noout", "-fingerprint", "-sha256"]).stdout.strip().split("=")[1]
# as on a site with Keycloak (Kerberos sign-in on): the join also sets the browsers' policies (2.1.6.28)
script = dc["env"].get_template("nginx/www/certs/join-linux.sh.j2").render(
    **{**V, "install_keycloak": True, "signin_kerberos": True})      # Kerberos sign-in is off by default (2.1.6.32)
with open(os.path.join(W, "join-linux.sh"), "w") as f:
    f.write(script)
SHIM = r"""#!/bin/bash
# A stand-in for systemctl in a container without systemd: (re)start sssd the way its packaged unit does (its
# ExecStartPre steps, then as its User with its capabilities: SSSD 2.12 on 26.04 runs as sssd), ignore the rest.
case "$1 $2" in
    "restart sssd"|"start sssd") ;;
    *) exit 0 ;;
esac
unit=/usr/lib/systemd/system/sssd.service
pkill -x sssd 2>/dev/null; sleep 1; rm -f /var/lib/sss/db/cache_* /run/sssd.pid /run/sssd/sssd.pid
grep '^ExecStartPre=' "$unit" | sed 's/^ExecStartPre=[+-]*//' | while read -r line; do sh -c "$line" 2>/dev/null; done
if grep -q '^User=sssd' "$unit"; then
    mkdir -p /run/sssd && chown sssd:sssd /run/sssd && chmod 775 /run/sssd
    capsh --caps="cap_setgid,cap_setuid,cap_dac_read_search+eip cap_setpcap+ep" --keep=1 --user=sssd         --addamb=cap_setgid,cap_setuid,cap_dac_read_search -- -c "/usr/sbin/sssd -D"
else
    /usr/sbin/sssd -D
fi
exit 0
"""
with open(os.path.join(W, "systemctl"), "w") as f:
    f.write(SHIM)
os.chmod(os.path.join(W, "systemctl"), 0o755)
hosts = [f"--add-host={V['hostname_dc']}:{IP}", f"--add-host={V['hostname_landing']}:{WEB_IP}",
         f"--add-host={V['hostname_ntp']}:{IP}"]


def client(release, name):
    box = f"lj-{name}"
    # DAC_READ_SEARCH: what SSSD's own unit grants it (Docker's default set lacks it); the client is a test stand-in
    sh(["docker", "run", "-d", "--name", box, "--hostname", name, "--network", NET, *hosts,
        "--cap-add", "DAC_READ_SEARCH",
        "-v", f"{W}/join-linux.sh:/root/join-linux.sh:ro", "-v", f"{W}/systemctl:/usr/local/sbin/systemctl:ro",
        IMAGES[release], "sleep", "infinity"])
    code, out = on(box, "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && "
                        "apt-get install -y -qq pamtester sudo procps libcap2-bin >/dev/null"
                        + ("; apt-get install -y -qq openssh-server >/dev/null; mkdir -p /run/sshd" if release == "24.04" else ""))
    return box, code == 0


def logon(box, uid, password):
    """A logon through PAM (authenticate + the account check: the log-on GPO), as login does."""
    return on(box, f"pamtester login {uid} authenticate acct_mgmt", stdin=password + "\n")


def checks(box, release):
    code, out = on(box, "cat /etc/firefox/policies/policies.json /etc/chromium/policies/managed/fabric-sso.json "
                        f"/etc/opt/chrome/policies/managed/fabric-sso.json; grep -c '.{V['domain']} = ' /etc/krb5.conf")
    check(f"{release}: browsers may use Kerberos for {V['hostname_keycloak']} (Firefox, Chromium, Chrome); fabric's "
          "domain maps to the AD realm (2.1.6.28)", code == 0 and out.count(V["hostname_keycloak"]) == 3
          and '"SPNEGO"' in out, out)
    code, out = on(box, "id -u alice; id -u adam")
    check(f"{release}: id gives fabric's own ids (from the site's block, not id mapping)",
          out.split() == [str(ids["alice"]), str(ids["adam"])], out)
    code, out = logon(box, "alice", PW)
    check(f"{release}: a person of the site logs on with their domain password (PAM, log-on GPO)",
          code == 0 and "successfully" in out, out)
    code, out = logon(box, "alice", "wrong-password")
    check(f"{release}: a wrong password is refused", code != 0, out)
    code, out = logon(box, "lara", PW)
    check(f"{release}: a person of another site is refused by the site's log-on rights (GPO access control)",
          code != 0, out)
    code, out = on(box, "kinit alice >/dev/null && klist", stdin=PW + "\n")
    check(f"{release}: a Kerberos ticket from the domain (kinit)", code == 0 and f"alice@{V['ad_realm']}" in out, out)
    code, out = on(box, "sudo -l -U adam; echo ---; sudo -l -U alice")
    admin, person = out.split("---", 1)
    check(f"{release}: sudo for one of the site's fabric-admins from the site's rule, none for a person",
          "(ALL) ALL" in admin and "not allowed" in person, out)


# 24.04: a wrong fingerprint refused, then a join with a site admin's password
box, ok = client("24.04", RELEASES["24.04"])
check("24.04: the client container is ready", ok)
code, out = on(box, f"bash /root/join-linux.sh {'00' * 32} --user adam", stdin=PW + "\n")
gone, _ = on(box, "test ! -e /usr/local/share/ca-certificates/fabric-root-ca.crt && ! dpkg -s adcli >/dev/null 2>&1")
check("24.04: a wrong root-CA fingerprint is refused and nothing is trusted or installed",
      code != 0 and "not trusting it" in out and gone == 0, out)
# a local user whose rootless-container ids (subordinate ids) overlap the domain's (manual 1.6.3.17)
on(box, "printf 'safeuser:100000:65536\\nolduser:1000000:65536\\n' >> /etc/subuid")
code, out = on(box, f"bash /root/join-linux.sh {fp} --user adam", stdin=PW + "\n")
check("24.04: joins with a site admin's password (on stdin) into the site's OU=machines/OU=linux",
      code == 0 and "joined" in out, out)
check("24.04: a local user whose subordinate ids overlap a site's block is named, and left as it was (2.1.6.46)",
      "olduser" in out and "overlap" in out and "olduser:1000000:65536" in on(box, "cat /etc/subuid")[1], out[-800:])
join_out = out
code, defs = on(box, "grep -E '^SUB_(UID|GID)_(MIN|MAX)' /etc/login.defs; useradd -m newbie && grep '^newbie:' /etc/subuid")
new_start = int(defs.strip().splitlines()[-1].split(":")[1]) if "newbie:" in defs else 0
check("24.04: local users made after the join get subordinate ids above AD's (SUB_UID_MIN, SUB_GID_MIN 2147483648)",
      code == 0 and "SUB_UID_MIN\t\t2147483648" in defs and "SUB_GID_MIN\t\t2147483648" in defs
      and new_start >= 2147483648, defs)
check("negative: a local user whose subordinate ids overlap no block is not named", "safeuser" not in join_out,
      join_out[-800:])
where = sh(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb", f"(sAMAccountName={RELEASES['24.04']}$)",
            "distinguishedName", "operatingSystem", "operatingSystemVersion"], ok=False).stdout
check("24.04: its computer account is in OU=linux,OU=machines,OU=lan, recording its OS (1.6.11.5, 2.1.6.36)",
      "OU=linux,OU=machines,OU=lan,OU=sites" in where and "operatingSystem: Ubuntu" in where
      and "operatingSystemVersion: 24.04" in where, where)
time.sleep(5)
checks(box, "24.04")

# managed by fabric (manual 1.6.11.6): the join configured SSH (an SSH server is on this one) and DNS for the domain;
# the sort makes the admin-joined machine a member; fabric-managed's hourly check keeps it, and undoes it once taken out
import tempfile  # noqa: E402
from fabriclib.directory import sort_machines as m_sort  # noqa: E402
m_sort.write_audit = lambda *a, **k: None
code, out = on(box, "sshd -T 2>/dev/null | grep -Ei '^(gssapiauthentication|passwordauthentication) '; "
                    "cat /etc/systemd/resolved.conf.d/fabric.conf")
# covers: setting:host_ip +
check("24.04: managed: sshd takes Kerberos and no passwords (its drop-in first), resolved sends the domain's names to "
      "fabric", "gssapiauthentication yes" in out and "passwordauthentication no" in out
      and f"DNS={V['host_ip']}" in out and f"~{V['ad_domain']}" in out, out)
record = tempfile.mktemp()
placed = m_sort.sort_machines(V, secrets=SECRETS, container=DC, record=record)
code, out = on(box, "fabric-managed check; echo rc=$?; ls /etc/ssh/sshd_config.d/10-fabric.conf")
check("24.04: the sort adopts it (lan-fabric-machines) and its hourly check keeps the configuration",
      RELEASES["24.04"] in placed["adopted"] and "rc=0" in out and "10-fabric.conf" in out, (placed, out))
sh(["docker", "exec", DC, "samba-tool", "group", "removemembers", "lan-fabric-machines", f"{RELEASES['24.04'].upper()}$",
    "-s", "/data/etc/smb.conf"])
code, out = on(box, "fabric-managed check; ls /etc/ssh/sshd_config.d/ /etc/systemd/resolved.conf.d/ 2>&1")
check("24.04: taken out of lan-fabric-machines, its next check removes fabric's SSH and DNS configuration",
      "removed" in out and "10-fabric.conf" not in out and "fabric.conf" not in out, out)

# 26.04: pre-created by fabricctl domain add-machine, joined with the one-time password
box, ok = client("26.04", RELEASES["26.04"])
check("26.04: the client container is ready (ubuntu:26.04)", ok)
one_time = m_add_machine.add_machine(V, "test", RELEASES["26.04"], secrets=SECRETS, container=DC, os="linux")
code, out = on(box, f"bash /root/join-linux.sh {fp} --one-time", stdin=one_time + "\n")
check("26.04: joins with a one-time join password, no admin password on the machine", code == 0 and "joined" in out,
      out)
where = sh(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb", f"(sAMAccountName={RELEASES['26.04']}$)",
            "distinguishedName", "operatingSystem"], ok=False).stdout
# the OS is not recorded here: a one-time join signs in as the computer, which AD does not let write it (1.6.11.5)
check("26.04: it stays where add-machine --os linux put it (OU=linux)",
      "OU=linux,OU=machines,OU=lan,OU=sites" in where, where)
time.sleep(5)
checks(box, "26.04")
code, out = on(box, "fabric-managed check; echo rc=$?; cat /etc/systemd/resolved.conf.d/fabric.conf")
check("26.04: pre-created managed (add-machine's default), its check finds it a member and keeps the configuration",
      "rc=0" in out and f"DNS={V['host_ip']}" in out, out)

# Debian 12 and 13 (Proxmox VE 8, 9): joined with a site admin's password
for release in ("debian-12", "debian-13"):
    box_d, ok = client(release, RELEASES[release])
    check(f"{release}: the client container is ready ({IMAGES[release]})", ok)
    flag = " --unmanaged" if release == "debian-12" else ""
    code, out = on(box_d, f"bash /root/join-linux.sh {fp} --user adam{flag}", stdin=PW + "\n")
    check(f"{release}: joins with a site admin's password{flag} (sudo installed with it: Debian has none)",
          code == 0 and "joined" in out and on(box_d, "command -v sudo")[0] == 0, out[-600:])
    if flag:
        desc = sh(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb",
                   f"(sAMAccountName={RELEASES[release]}$)", "description"], ok=False).stdout
        check(f"{release}: --unmanaged: fabric configures neither SSH nor DNS, and the account says unmanaged",
              on(box_d, "test -e /etc/systemd/resolved.conf.d/fabric.conf")[0] != 0
              and "description: fabric: unmanaged (manual 1.6.11.6)" in desc, desc)
    time.sleep(5)
    checks(box_d, release)

# the DC away: a person who logged on before still can (cached credentials)
sh(["docker", "stop", DC])
time.sleep(5)
code, out = logon(box, "alice", PW)
check("with the DC stopped, a person who logged on before still logs on (cached credentials)",
      code == 0 and "successfully" in out, out)
sh(["docker", "start", DC])

# who may sign in, per OU (manual 1.6.11.4): a policy on OU=machines naming a group adam is in and alice is not
for _ in range(60):
    if dc_healthy():
        break
    time.sleep(5)
policy = {"machines": {"console": ["lan-fabric-admins"], "remote": ["lan-fabric-admins"]}}
done = converge_domain({**V, "logon_policies": policy}, os.path.join(W, "dc", "federation.yaml"), SECRETS,
                       container=DC)
check("a log-on policy on OU=machines replaces the site's legacy one (fabric: lan log-on machines; rights removed)",
      any("GPO fabric: lan log-on machines linked to OU=machines" in c for c in done)
      and any(c == "GPO fabric: lan log-on rights removed" for c in done), done)
for name in (RELEASES["24.04"], RELEASES["26.04"]):
    lbox = f"lj-{name}"
    on(lbox, "systemctl restart sssd")              # its GPO cache and its offline state from the DC's stop
    time.sleep(8)
    code, out = logon(lbox, "adam", PW)
    check(f"{name}: one of the groups OU=machines names (lan-fabric-admins: adam) logs on (sssd GPO access control)",
          code == 0 and "successfully" in out, out)
    code, out = logon(lbox, "alice", PW)
    check(f"{name}: a person of the site outside those groups (alice) is refused by OU=machines' policy",
          code != 0, out)

# a sudo rule on a host group (manual 1.6.11.7): alice may run uptime on the machines of lan-hosts-web, which holds the
# 24.04 machine only; sssd matches the rule's sudoHost (each member's names) against the machine's own name
made = [run_op(V, SECRETS, "create_host_group", {"name": "web"}, DC),
        run_op(V, SECRETS, "set_host_group_member", {"name": "web", "machine": RELEASES["24.04"], "member": True}, DC),
        run_op(V, SECRETS, "add_sudo_rule", {"name": "web-uptime", "users": ["alice"], "commands": ["/usr/bin/uptime"],
                                             "run_as": ["root"], "hosts": "lan-hosts-web"}, DC)]
check("a host group lan-hosts-web holding the 24.04 machine, and a sudo rule for alice on it (its hosts: that "
      "machine's names)", RELEASES["24.04"] in made[2]["hosts"] and RELEASES["26.04"] not in made[2]["hosts"], made)
for name, applies in ((RELEASES["24.04"], True), (RELEASES["26.04"], False)):
    lbox = f"lj-{name}"
    on(lbox, "systemctl restart sssd")              # sssd's sudo rules fetched anew (else its next refresh)
    time.sleep(8)
    code, out = on(lbox, "sudo -l -U alice")
    check(f"{name}: the host group's sudo rule " + ("applies on its member: alice may run /usr/bin/uptime"
                                                    if applies else "does not apply on a machine outside it"),
          ("/usr/bin/uptime" in out) == applies and (applies or "not allowed" in out), out)

if not os.environ.get("FABRIC_TEST_KEEP"):         # FABRIC_TEST_KEEP=1 leaves the containers for a look
    cleanup()
print(f"\n{FAILED and 'FAILED' or 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
