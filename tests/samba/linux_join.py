"""The `samba` suite, Linux machines joining AD (manual 1.6.7, 1.6.5.19, S6): real Ubuntu 24.04 and 26.04
containers run fabric's join-linux.sh as rendered against a converged test DC. Proves: the installer refuses a wrong
root-CA fingerprint and changes nothing; a join with a site admin's password and one with a one-time join password
(`fabricctl domain add-machine`); `id` with fabric's own ids; a password logon through PAM and a Kerberos ticket;
sudo for a site admin (2.1.9.13's rule) and none for a person; a person of another site refused by the site's log-on
GPO; cached logons with the DC stopped. The containers have no systemd: a stand-in `systemctl` starts sssd.
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
check("the site's sudo rule: its linux-sudo role (lan-admins is in it) and, at the root, the admin group may run "
      "anything (2.1.9.13)", "sudoUser: %lan-linux-sudo" in sudo_rule and "sudoUser: %admins" in sudo_rule
      and "sudoCommand: ALL" in sudo_rule and "%lan-admins" not in sudo_rule, sudo_rule)

# people: alice (a person of lan), adam (a lan admin), lara (a person of another site, lab)
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
                        "apt-get install -y -qq pamtester sudo procps libcap2-bin >/dev/null")
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
    check(f"{release}: sudo for a site admin from the site's rule, none for a person",
          "(ALL) ALL" in admin and "not allowed" in person, out)


# 24.04: a wrong fingerprint refused, then a join with a site admin's password
box, ok = client("24.04", RELEASES["24.04"])
check("24.04: the client container is ready", ok)
code, out = on(box, f"bash /root/join-linux.sh {'00' * 32} --user adam", stdin=PW + "\n")
gone, _ = on(box, "test ! -e /usr/local/share/ca-certificates/fabric-root-ca.crt && ! dpkg -s adcli >/dev/null 2>&1")
check("24.04: a wrong root-CA fingerprint is refused and nothing is trusted or installed",
      code != 0 and "not trusting it" in out and gone == 0, out)
code, out = on(box, f"bash /root/join-linux.sh {fp} --user adam", stdin=PW + "\n")
check("24.04: joins with a site admin's password (on stdin) into the site's OU=machines",
      code == 0 and "joined" in out, out)
where = sh(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb", f"(sAMAccountName={RELEASES['24.04']}$)",
            "distinguishedName"], ok=False).stdout
check("24.04: its computer account is in OU=machines,OU=lan", "OU=machines,OU=lan,OU=sites" in where, where)
time.sleep(5)
checks(box, "24.04")

# 26.04: pre-created by fabricctl domain add-machine, joined with the one-time password
box, ok = client("26.04", RELEASES["26.04"])
check("26.04: the client container is ready (ubuntu:26.04)", ok)
one_time = m_add_machine.add_machine(V, "test", RELEASES["26.04"], secrets=SECRETS, container=DC)
code, out = on(box, f"bash /root/join-linux.sh {fp} --one-time", stdin=one_time + "\n")
check("26.04: joins with a one-time join password, no admin password on the machine", code == 0 and "joined" in out,
      out)
time.sleep(5)
checks(box, "26.04")

# Debian 12 and 13 (Proxmox VE 8, 9): joined with a site admin's password
for release in ("debian-12", "debian-13"):
    box_d, ok = client(release, RELEASES[release])
    check(f"{release}: the client container is ready ({IMAGES[release]})", ok)
    code, out = on(box_d, f"bash /root/join-linux.sh {fp} --user adam", stdin=PW + "\n")
    check(f"{release}: joins with a site admin's password (sudo installed with it: Debian has none)",
          code == 0 and "joined" in out and on(box_d, "command -v sudo")[0] == 0, out[-600:])
    time.sleep(5)
    checks(box_d, release)

# the DC away: a person who logged on before still can (cached credentials)
sh(["docker", "stop", DC])
time.sleep(5)
code, out = logon(box, "alice", PW)
check("with the DC stopped, a person who logged on before still logs on (cached credentials)",
      code == 0 and "successfully" in out, out)
sh(["docker", "start", DC])

if not os.environ.get("FABRIC_TEST_KEEP"):         # FABRIC_TEST_KEEP=1 leaves the containers for a look
    cleanup()
print(f"\n{FAILED and 'FAILED' or 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
