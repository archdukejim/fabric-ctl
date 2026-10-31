"""The `samba` suite, Linux machines joining AD (manual 1.6.7, 1.6.5.19, S6): real Ubuntu 24.04 and 26.04
containers run fabric's join-linux.sh as rendered against a converged test DC. Proves: the installer refuses a wrong
root-CA fingerprint and changes nothing; a join with a Directory Administrator's password (`--type server|desktop`:
the type's OU and group, and the site's group, 1.6.13.3) and one with a one-time join password (`fabricctl domain
add-machine`); the refusals of a type it does not take and a site the domain does not have; `id` with fabric's own ids;
a password logon through PAM and a Kerberos ticket; who signs in from the shipped grants (1.6.13.5): at a server its
administrators (sudo of every command there) and nobody else, a person of another site and the Directory
Administrator refused; at a desktop every person, with no sudo;
cached logons with the DC stopped; and a sudo rule on a host group (1.6.11.7) holding the 24.04 machine: it applies
there and not on the 26.04 one. The containers have no systemd: a stand-in `systemctl` starts sssd. Then 24.04 and
Debian 12 with systemd as PID 1 (2.1.6.95): after a reboot no sssd unit failed (its socket units masked beside
`services =`), sign-in and sudo work; again after the script runs a second time, and after it runs on a machine an
older join left with the socket units enabled (negative: those fail at boot first); renaming (2.1.6.96): polkit
refuses a person's hostnamectl (the rule's refusal: without it polkit would ask for a password), root's own rename is
warned of by the hourly check. The admin-joined machine is in fabric-managed from its join (2.1.6.97), the sort
records it, an admin's removal holds, and the guard keeps a join that could not add itself for 2 hours.
    sudo python3 tests/samba/linux_join.py
"""
import json
import os
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.dirname(os.path.abspath(__file__)), os.path.join(REPO, "tests", "common")]
import test_run as testrun  # noqa: E402
from start_dc import IMAGE as SAMBA_IMAGE  # noqa: E402
from start_dc import POLICY, start_dc  # noqa: E402
import fabriclib.directory.add_machine as m_add_machine  # noqa: E402
from fabriclib.directory.run_op import run_op  # noqa: E402
import fabriclib.grants.sync_grants as m_sync  # noqa: E402
from fabriclib.secrets.random_password import random_password  # noqa: E402

W = os.path.join(os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests"), "samba-linux-join")
NET, SUBNET, IP, WEB_IP = testrun.name("linuxjoin_net"), f"{testrun.PREFIX}.33.0/24", f"{testrun.PREFIX}.33.10", f"{testrun.PREFIX}.33.20"
DC, WEB = testrun.name("ljdc"), testrun.name("lj-certs")      # per run (manual 3.1.2.6)
# release -> (container image, machine name): Ubuntu, and Debian (what Proxmox VE 8 and 9 are built on)
IMAGES = {"24.04": "ubuntu:24.04", "26.04": "ubuntu:26.04", "debian-12": "debian:12", "debian-13": "debian:13"}
RELEASES = {"24.04": "ws2404", "26.04": "ws2604", "debian-12": "wsdeb12", "debian-13": "wsdeb13"}
BOOTS = {"24.04": "bt2404", "debian-12": "btdeb12"}       # the same, with systemd as PID 1 (2.1.6.95)
PW = "Correct-Horse-9-" + random_password(8)
FAILED = 0
m_add_machine.write_audit = lambda *a, **k: None
m_sync.write_audit = lambda *a, **k: None


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
    testrun.remove("container", DC, WEB, *[testrun.name(f"lj-{r}") for r in [*RELEASES.values(), *BOOTS.values()]])
    testrun.remove("network", NET)                                                   # this run's only
    for name in BOOTS.values():                                                      # the systemd clients' images
        sh(["docker", "rmi", "-f", testrun.name(f"fabric-ljboot-{name}")], ok=False)


cleanup()
dc = start_dc(os.path.join(W, "dc"), DC, NET, SUBNET, IP)
V, SECRETS = dc["v"], dc["secrets"]
check("a converged DC", dc_healthy())
sudo_rule = sh(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb", "(objectClass=sudoRole)", "cn"],
               ok=False).stdout
check("negative: no sudo rule in the domain but the shipped grants' (the site default rule is retired, 2.1.6.80; 1.6.13.5)",
      sorted(x.split("cn: ")[1] for x in sudo_rule.splitlines() if x.startswith("cn: ")) == [
          "grant-desktop-administrators", "grant-network-administrators", "grant-server-administrators"], sudo_rule)
BASE = V["ad_base_dn"]

# people: alice (a person of lan), adam (a Directory Administrator, 1.6.12.2), lara (a person of another site, lab)
lab = {"site": "lab", "dc": "dc-0002", "dc_type": "writable", "root": False, "parent": "lan", "password_policy": POLICY,
       "networks": [], "root_ca_pem": open(dc["root_ca"]).read(), "groups": [],
       "accounts": {f"fabric-{k}-dc-0002": random_password() for k in ("agent", "keycloak", "radius")}, "radius_gid": 610}
sh(["docker", "exec", "-i", DC, "python3", "/fabric/converge.py"], input=json.dumps(lab))
lab_v = {**V, "site_name": "lab", "dc_name": "dc-0002"}
lab_s = {**SECRETS, "ad_agent_password": lab["accounts"]["fabric-agent-dc-0002"]}
ids = {}
for uid, site_v, sec in (("alice", V, SECRETS), ("adam", V, SECRETS), ("lara", lab_v, lab_s)):
    made = run_op(site_v, sec, "create_person", {"uid": uid, "first": uid.title(), "last": "Test",
                                                  "email": f"{uid}@lan.test", "password": "Ot-" + random_password(20),
                                                  "gid": 5000, "home_base": "/home", "shell": "/bin/bash"}, DC)
    ids[uid] = made["uidNumber"]
run_op(V, SECRETS, "add_group_member", {"group": "directory-admins", "uid": "adam"}, DC)
run_op(V, SECRETS, "add_group_member", {"group": "server-admins", "uid": "alice"}, DC)     # the servers' grant
set_pw = f"""
import sys
sys.path.insert(0, "/fabric")
from open_samdb import open_samdb
samdb, lp = open_samdb("/data/etc/smb.conf")
for uid in ("alice", "adam", "lara"):          # as Keycloak's first sign-in would: their own password
    samdb.setpassword("(sAMAccountName=%s)" % uid, {PW!r}, force_change_at_next_login=False)
print("set")
"""
check("people in the domain: alice and adam (lan; adam a Directory Administrator), lara (lab)",
      "set" in sh(["docker", "exec", "-i", DC, "python3", "-"], input=set_pw, ok=False).stdout, ids)

# ca.<domain>/certs/: the root CA served over plain HTTP, as nginx serves it; the join script fetches it there (1.5.1.6)
os.makedirs(os.path.join(W, "www", "certs"), exist_ok=True)
with open(os.path.join(W, "www", "certs", "root-ca.crt"), "w") as f:
    f.write(open(dc["root_ca"]).read())
sh(["docker", "run", "-d", "--name", WEB, *testrun.labels(), "--network", NET, "--ip", WEB_IP, "-v", f"{W}/www:/srv:ro",
    "--entrypoint", "python3", SAMBA_IMAGE, "-m", "http.server", "80", "--directory", "/srv"])
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
hosts = [f"--add-host={V['hostname_dc']}:{IP}", f"--add-host={V['hostname_stepca']}:{WEB_IP}",
         f"--add-host={V['hostname_ntp']}:{IP}"]


def client(release, name):
    box = testrun.name(f"lj-{name}")
        # DAC_READ_SEARCH: what SSSD's own unit grants it (Docker's default set lacks it); the client is a test stand-in
    sh(["docker", "run", "-d", "--name", box, *testrun.labels(), "--hostname", name, "--network", NET, *hosts,
        "--cap-add", "DAC_READ_SEARCH",
        "-v", f"{W}/join-linux.sh:/root/join-linux.sh:ro", "-v", f"{W}/systemctl:/usr/local/sbin/systemctl:ro",
        IMAGES[release], "sleep", "infinity"])
    code, out = on(box, "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && "
                        "apt-get install -y -qq pamtester sudo procps libcap2-bin >/dev/null"
                        + ("; apt-get install -y -qq openssh-server >/dev/null; mkdir -p /run/sshd" if release == "24.04" else ""))
    return box, code == 0


def logon(box, uid, password):
    """A logon through PAM (authenticate + the account check), as login does."""
    return on(box, f"pamtester login {uid} authenticate acct_mgmt", stdin=password + "\n")


def checks(box, release, desktop=False):
    """The member's checks once it joined; its type's grants compiled first (the join changed groups outside fabric:
    the fabric-grants timer's run, here at once): a server lets in its administrators (alice, in server-admins), a
    desktop every person at the keyboard (1.6.13.5)."""
    m_sync.sync_grants(V, "test", "timer", DC)
    on(box, "systemctl restart sssd")              # sssd fetches the compiled rules anew (its sudo rules: else
    time.sleep(8)                                   # its 15-minute refresh)
    code, out = on(box, "cat /etc/firefox/policies/policies.json /etc/chromium/policies/managed/fabric-sso.json "
                        f"/etc/opt/chrome/policies/managed/fabric-sso.json; grep -c '.{V['domain']} = ' /etc/krb5.conf")
    check(f"{release}: browsers may use Kerberos for {V['hostname_keycloak']} (Firefox, Chromium, Chrome); fabric's "
          "domain maps to the AD realm (2.1.6.28)", code == 0 and out.count(V["hostname_keycloak"]) == 3
          and '"SPNEGO"' in out, out)
    code, out = on(box, "id -u alice; id -u adam")
    check(f"{release}: id gives fabric's own ids (from the DC's range, not id mapping)",
          out.split() == [str(ids["alice"]), str(ids["adam"])], out)
    code, out = logon(box, "alice", PW)
    check(f"{release}: " + ("every person logs on at a desktop (the shipped desktops grant)" if desktop else
                            "a server administrator (alice) logs on with their domain password (PAM, the grant)"),
          code == 0 and "successfully" in out, out)
    code, out = logon(box, "alice", "wrong-password")
    check(f"{release}: a wrong password is refused", code != 0, out)
    code, out = logon(box, "lara", PW)
    if desktop:
        check(f"{release}: a person of another site logs on at a desktop too (every person's, 2.1.6.77)",
              code == 0 and "successfully" in out, out)
    else:
        check(f"negative: {release}: a person of another site, in no grant on servers, is refused (GPO access control)",
              code != 0, out)
        code, out = logon(box, "adam", PW)
        check(f"negative: {release}: the Directory Administrator, in no grant on servers, is refused (1.6.13.5)",
              code != 0, out)
    code, out = on(box, "kinit alice >/dev/null && klist", stdin=PW + "\n")
    check(f"{release}: a Kerberos ticket from the domain (kinit)", code == 0 and f"alice@{V['ad_realm']}" in out, out)
    code, out = on(box, "sudo -l -U adam; echo ---; sudo -l -U alice")
    admin, person = out.split("---", 1)
    if desktop:
        check(f"negative: {release}: no sudo at a desktop for a server administrator or the Directory Administrator",
              "not allowed" in admin and "not allowed" in person, out)
    else:
        check(f"{release}: the server administrator has sudo of every command (the grant's rule); the Directory "
              "Administrator none", "not allowed" in admin and "(root) ALL" in person, out)


# 24.04: a wrong fingerprint refused, a type it does not take refused, then a join with an admin's password
box, ok = client("24.04", RELEASES["24.04"])
check("24.04: the client container is ready", ok)
code, out = on(box, f"bash /root/join-linux.sh {'00' * 32} --user adam", stdin=PW + "\n")
gone, _ = on(box, "test ! -e /usr/local/share/ca-certificates/fabric-root-ca.crt && ! dpkg -s adcli >/dev/null 2>&1")
check("24.04: a wrong root-CA fingerprint is refused and nothing is trusted or installed",
      code != 0 and "not trusting it" in out and gone == 0, out)
code, out = on(box, f"bash /root/join-linux.sh {fp} --user adam --type network", stdin=PW + "\n")
gone, _ = on(box, "! dpkg -s adcli >/dev/null 2>&1")
check("24.04: refused: --type network (a network machine is pre-created), saying so, before anything is installed",
      code != 0 and "--type is server or desktop" in out and gone == 0, out)
# a local user whose rootless-container ids (subordinate ids) overlap the domain's (manual 1.6.3.17)
on(box, "printf 'safeuser:100000:65536\\nolduser:1000000:65536\\n' >> /etc/subuid")
code, out = on(box, f"bash /root/join-linux.sh {fp} --user adam", stdin=PW + "\n")
check("24.04: joins with a Directory Administrator's password (on stdin), a server by default",
      code == 0 and "joined" in out, out)
check("24.04: a local user whose subordinate ids overlap a DC's range is named, and left as it was (2.1.6.46)",
      "olduser" in out and "overlap" in out and "olduser:1000000:65536" in on(box, "cat /etc/subuid")[1], out[-800:])
join_out = out
code, defs = on(box, "grep -E '^SUB_(UID|GID)_(MIN|MAX)' /etc/login.defs; useradd -m newbie && grep '^newbie:' /etc/subuid")
new_start = int(defs.strip().splitlines()[-1].split(":")[1]) if "newbie:" in defs else 0
check("24.04: local users made after the join get subordinate ids above AD's (SUB_UID_MIN, SUB_GID_MIN 2147483648)",
      code == 0 and "SUB_UID_MIN\t\t2147483648" in defs and "SUB_GID_MIN\t\t2147483648" in defs
      and new_start >= 2147483648, defs)
check("negative: a local user whose subordinate ids overlap no range is not named", "safeuser" not in join_out,
      join_out[-800:])
where = sh(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb", f"(sAMAccountName={RELEASES['24.04']}$)",
            "distinguishedName", "operatingSystem", "operatingSystemVersion", "memberOf"], ok=False).stdout.replace("\n ", "")
check("24.04: its computer account is in OU=servers,OU=machines, in machines-servers and site-lan, recording its OS "
      "(1.6.13.3)", f"CN={RELEASES['24.04'].upper()},OU=servers,OU=machines,{BASE}" in where
      and f"memberOf: CN=machines-servers,OU=groups,{BASE}" in where and f"memberOf: CN=site-lan,OU=groups,{BASE}"
      in where and "operatingSystem: Ubuntu" in where and "operatingSystemVersion: 24.04" in where, where)
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
check("24.04: in fabric-managed from its join (2.1.6.97), before any sort",
      "memberOf: CN=fabric-managed," in where and on(box, "grep -x MANAGED_PENDING=0 /etc/fabric/managed.env")[0] == 0,
      where)
code, out = on(box, "fabric-managed check; echo rc=$?; ls /etc/ssh/sshd_config.d/10-fabric.conf")
check("24.04: its own check right after the join keeps the configuration (finding 11: it removed it before the sort)",
      "rc=0" in out and "10-fabric.conf" in out and "removed" not in out, out)
record = tempfile.mktemp()
placed = m_sort.sort_machines(V, secrets=SECRETS, container=DC, record=record)
guid = sh(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb", f"(sAMAccountName={RELEASES['24.04']}$)",
           "objectGUID"], ok=False).stdout.split("objectGUID: ")[-1].split()[0]
check("24.04: the sort records it (a member already: not adopted again, nothing audited)",
      RELEASES["24.04"] not in placed["adopted"] and guid in json.load(open(record))["adopted"], (placed, guid))
sh(["docker", "exec", DC, "samba-tool", "group", "removemembers", "fabric-managed", f"{RELEASES['24.04'].upper()}$",
    "-s", "/data/etc/smb.conf"])
code, out = on(box, "fabric-managed check; ls /etc/ssh/sshd_config.d/ /etc/systemd/resolved.conf.d/ 2>&1")
check("24.04: taken out of fabric-managed, its next check removes fabric's SSH and DNS configuration",
      "removed" in out and "10-fabric.conf" not in out and "fabric.conf" not in out, out)
again = m_sort.sort_machines(V, secrets=SECRETS, container=DC, record=record)
check("negative: 24.04: taken out by an admin, the next sort leaves it out", RELEASES["24.04"] not in again["adopted"]
      and "fabric-managed" not in sh(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb",
                                      f"(sAMAccountName={RELEASES['24.04']}$)", "memberOf"], ok=False).stdout, again)
# the guard (2.1.6.97): a join that could not add itself keeps the configuration 2 hours for the sort, no longer
on(box, "fabric-managed apply; sed -i 's/^MANAGED_PENDING=0$/MANAGED_PENDING=1/' /etc/fabric/managed.env")
code, out = on(box, "fabric-managed check; ls /etc/ssh/sshd_config.d/")
check("24.04: the guard: a join that could not add itself, not a member yet, under 2 hours: the configuration kept",
      "kept" in out and "10-fabric.conf" in out, out)
on(box, "sed -i 's/^JOINED=.*/JOINED=0/' /etc/fabric/managed.env")
code, out = on(box, "fabric-managed check; ls /etc/ssh/sshd_config.d/")
check("negative: 24.04: the guard ends after 2 hours: not a member, the configuration removed",
      "removed" in out and "10-fabric.conf" not in out, out)
on(box, "sed -i 's/^MANAGED_PENDING=1$/MANAGED_PENDING=0/' /etc/fabric/managed.env")

# a service's keytab (manual 1.6.12.17.8): the command the console shows, run by the machine's administrator
from fabriclib.domain.keytab_command import keytab_command  # noqa: E402
NAME = RELEASES["24.04"]
shown = keytab_command(V, NAME, "HTTP", "www-data", secrets=SECRETS, container=DC)
code, out = on(box, shown["command"].removeprefix("sudo ") + " && stat -c 'owner=%U mode=%a' /etc/krb5-http.keytab "
                    "&& klist -k /etc/krb5-http.keytab | awk 'NR>3 {print $2}' | sort -u")
spns = sh(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb", f"(sAMAccountName={NAME}$)",
           "servicePrincipalName"], ok=False).stdout.lower()
keys = [ln for ln in out.splitlines() if "@" in ln]
check("24.04: fabric-keytab as the console shows it: HTTP/<its names> on its own computer account, the keytab "
      "/etc/krb5-http.keytab owned by www-data, 0600, holding HTTP's keys only",
      code == 0 and "owner=www-data mode=600" in out and f"serviceprincipalname: http/{NAME}\n" in spns
      and keys and all(k.lower().startswith("http/") for k in keys),
      (shown, out, spns))
for args, words in (("--machine other --service HTTP --user www-data", "run it on other"),
                    (f"--machine {NAME} --service host --user www-data", "the machine's own name"),
                    (f"--machine {NAME} --service HTTP --user nobody-here", "no user nobody-here"),
                    (f"--machine {NAME} --service HTTP --user www-data --path /etc/krb5.keytab", "--path is an"),
                    (f"--machine {NAME} --frob x", "usage")):
    code, out = on(box, f"fabric-keytab {args}")
    check(f"negative: 24.04: fabric-keytab {args} refused ({words})", code != 0 and words in out, out)
code, out = on(box, f"setpriv --reuid=65534 --regid=65534 --clear-groups /usr/local/sbin/fabric-keytab --machine {NAME} "
                    "--service HTTP --user www-data")
check("negative: 24.04: fabric-keytab without sudo refused", code != 0 and "run it with sudo" in out, out)

# 26.04: pre-created by fabricctl domain add-machine, joined with the one-time password
box, ok = client("26.04", RELEASES["26.04"])
check("26.04: the client container is ready (ubuntu:26.04)", ok)
one_time = m_add_machine.add_machine(V, "test", RELEASES["26.04"], secrets=SECRETS, container=DC, type="server")
code, out = on(box, f"bash /root/join-linux.sh {fp} --one-time", stdin=one_time + "\n")
check("26.04: joins with a one-time join password, no admin password on the machine", code == 0 and "joined" in out,
      out)
where = sh(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb", f"(sAMAccountName={RELEASES['26.04']}$)",
            "distinguishedName", "operatingSystem"], ok=False).stdout
# the OS is not recorded here: a one-time join signs in as the computer, which AD does not let write it (1.6.11.5)
check("26.04: it stays where add-machine --type server put it (OU=servers)",
      f"OU=servers,OU=machines,{BASE}" in where, where)
time.sleep(5)
checks(box, "26.04")
code, out = on(box, "fabric-managed check; echo rc=$?; cat /etc/systemd/resolved.conf.d/fabric.conf")
check("26.04: pre-created managed (add-machine's default), its check finds it a member and keeps the configuration",
      "rc=0" in out and f"DNS={V['host_ip']}" in out, out)

# Debian 12 and 13 (Proxmox VE 8, 9): joined with an admin's password; 13 as a desktop
for release in ("debian-12", "debian-13"):
    box_d, ok = client(release, RELEASES[release])
    check(f"{release}: the client container is ready ({IMAGES[release]})", ok)
    if release == "debian-12":
        code, out = on(box_d, f"bash /root/join-linux.sh {fp} --user adam --site nosuch", stdin=PW + "\n")
        check(f"{release}: refused: a site the domain does not have (no DC record names it), not joined",
              code != 0 and "no site nosuch" in out and on(box_d, "test -e /etc/krb5.keytab")[0] != 0, out[-400:])
    flag = " --unmanaged" if release == "debian-12" else " --type desktop"
    code, out = on(box_d, f"bash /root/join-linux.sh {fp} --user adam{flag}", stdin=PW + "\n")
    check(f"{release}: joins with an admin's password{flag} (sudo installed with it: Debian has none)",
          code == 0 and "joined" in out and on(box_d, "command -v sudo")[0] == 0, out[-600:])
    if release == "debian-13":
        where = sh(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb",
                    f"(sAMAccountName={RELEASES[release]}$)", "distinguishedName", "memberOf"], ok=False).stdout.replace("\n ", "")
        check(f"{release}: --type desktop: in OU=desktops,OU=machines and machines-desktops (1.6.13.3)",
              f"OU=desktops,OU=machines,{BASE}" in where and f"CN=machines-desktops,OU=groups,{BASE}" in where
              and "machines-servers" not in where, where)
    if release == "debian-12":
        desc =sh(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb",
                   f"(sAMAccountName={RELEASES[release]}$)", "description"], ok=False).stdout
        check(f"{release}: --unmanaged: fabric configures neither SSH nor DNS, and the account says unmanaged",
              on(box_d, "test -e /etc/systemd/resolved.conf.d/fabric.conf")[0] != 0
              and "description: fabric: unmanaged (manual 1.6.11.6)" in desc, desc)
    time.sleep(5)
    checks(box_d, release, desktop=release == "debian-13")


# with systemd (2.1.6.95): the packages enable SSSD's socket units and the join masks them, so the machine boots with
# no failed sssd unit, sign-in and sudo work after the reboot, and running the script again changes neither
BOOT_DOCKERFILE = """FROM {image}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq systemd systemd-sysv dbus polkitd pamtester sudo procps >/dev/null \\
 && apt-get clean
CMD ["/sbin/init"]
"""


def booted(box):
    """Wait for the container's systemd to finish starting; its state ("running", "degraded", ...)."""
    state = ""
    for _ in range(60):
        state = on(box, "systemctl is-system-running")[1].strip()
        if state in ("running", "degraded"):
            break
        time.sleep(2)
    return state


def failed_sssd(box):
    """The sssd units systemd lists as failed."""
    return [u for u in on(box, "systemctl --failed --no-legend --plain | awk '{print $1}'")[1].split() if "sssd" in u]


def boot_client(release, name):
    """A joined machine with systemd as PID 1, as a real one boots (privileged: its own cgroup tree, like the sandbox)."""
    box, image = testrun.name(f"lj-{name}"), testrun.name(f"fabric-ljboot-{name}")
    sh(["docker", "build", "-q", "-t", image, "-"], input=BOOT_DOCKERFILE.format(image=IMAGES[release]))
    sh(["docker", "run", "-d", "--name", box, *testrun.labels(), "--hostname", name, "--network", NET, *hosts,
        "--privileged", "--cgroupns=private", "--tmpfs", "/run", "--tmpfs", "/run/lock",
        "-v", f"{W}/join-linux.sh:/root/join-linux.sh:ro", image])
    return box, booted(box) in ("running", "degraded")


def after_boot(box, release, when):
    """Reboot the machine; then no sssd unit failed, sssd runs, alice (a server administrator) logs on and has sudo."""
    sh(["docker", "restart", box])
    state = booted(box)
    for _ in range(30):                     # sssd online again (its first lookups after the boot)
        if on(box, "id -u alice")[0] == 0:
            break
        time.sleep(2)
    failed = failed_sssd(box)
    masked = on(box, "systemctl is-enabled sssd-nss.socket sssd-pam.socket sssd-sudo.socket sssd-pac.socket")[1]
    check(f"{release} with systemd, {when}: after a reboot no sssd unit failed, sssd runs its responders "
          "(services = nss, pam, sudo), the packages' socket units masked",
          state in ("running", "degraded") and failed == [] and on(box, "systemctl is-active sssd")[1].strip()
          == "active" and masked.split() == ["masked"] * 4
          and on(box, "grep -qx 'services = nss, pam, sudo' /etc/sssd/sssd.conf")[0] == 0,
          (state, failed, on(box, "systemctl --failed --no-legend --plain; systemctl status 'sssd*' --no-pager "
                                  "| tail -40")[1]))
    code, out = logon(box, "alice", PW)
    check(f"{release} with systemd, {when}: a server administrator (alice) logs on", code == 0
          and "successfully" in out, out)
    on(box, "sss_cache -E")                 # sssd's cached sudo rules (from before the grants' sync) dropped (4.6.6.8)
    for _ in range(15):
        code, out = on(box, "sudo -l -U alice; echo ---; sudo -l -U lara")
        if "(root) ALL" in out.split("---")[0]:
            break
        time.sleep(2)
    check(f"{release} with systemd, {when}: alice has sudo (the grant's rule); negative: lara has none",
          "(root) ALL" in out.split("---")[0] and "not allowed" in out.split("---")[-1], out)


for release, name in BOOTS.items():
    box_b, ok = boot_client(release, name)
    check(f"{release} with systemd: the container boots ({IMAGES[release]})", ok)
    code, out = on(box_b, f"bash /root/join-linux.sh {fp} --user adam", stdin=PW + "\n")
    check(f"{release} with systemd: joins", code == 0 and "joined" in out, out[-600:])
    code, out = on(box_b, "head -2 /etc/hostname")
    check(f"{release} with systemd: /etc/hostname says the name is the domain account's and names the procedure "
          "(a rename breaks the join, 2.1.6.96)", f"domain account {name.upper()}$" in out and "4.6.6.11" in out, out)
    m_sync.sync_grants(V, "test", "timer", DC)
    after_boot(box_b, release, "joined")
    # renaming (2.1.6.96): polkit refuses hostnamed's rename to everyone it asks; root's own rename is warned of
    ask = ("su probeu -s /bin/bash -c 'hostnamectl set-hostname renamed 2>&1; "
           "pkcheck --action-id org.freedesktop.hostname1.set-static-hostname --process $$ >/dev/null 2>&1; "
           "echo pk=$?'; hostname")
    code, out = on(box_b, "useradd -m probeu 2>/dev/null; " + ask)
    check(f"{release} with systemd: a person's hostnamectl rename is refused by fabric's polkit rule (Access denied; "
          "polkit says not authorized), the name kept", "Access denied" in out and "pk=1" in out
          and out.split()[-1] == name, out)
    code, out = on(box_b, "mv /etc/polkit-1/rules.d/10-fabric-hostname.rules /root/; sleep 3; " + ask
                   + "; mv /root/10-fabric-hostname.rules /etc/polkit-1/rules.d/; sleep 3")
    check(f"negative: {release} with systemd: without the rule polkit would ask for an administrator's password "
          "instead (the refusal is the rule's)", "pk=2" in out and out.split()[-1] == name, out)
    code, out = on(box_b, f"hostname renamed-by-root; /usr/local/sbin/fabric-managed check 2>&1; hostname {name}; "
                          "/usr/local/sbin/fabric-managed check 2>&1")
    check(f"{release} with systemd: root's own rename is not stopped (polkit is not asked), and the hourly check "
          "warns of it, naming the procedure; named back, no warning",
          "now named renamed-by-root, but it joined the domain as " + name in out and "4.6.6.11" in out
          and out.count("warning:") == 1, out)
    code, out = on(box_b, f"bash /root/join-linux.sh {fp} --user adam", stdin=PW + "\n")
    check(f"{release} with systemd: running the script again on the joined machine succeeds",
          code == 0 and "joined" in out, out[-600:])
    after_boot(box_b, release, "joined again")
    # a machine as an older script left it (services in sssd.conf, the socket units enabled): what the owner saw
    on(box_b, "s=$(systemctl list-unit-files 'sssd-*.socket' --no-legend | awk '{print $1}'); "
              "systemctl unmask $s >/dev/null 2>&1; systemctl enable $s >/dev/null 2>&1")
    sh(["docker", "restart", box_b])
    booted(box_b)
    old = failed_sssd(box_b)
    check(f"negative: {release} with systemd: as an older join left it (socket units enabled beside services), "
          "sssd's socket units fail at boot", old != [], old)
    code, out = on(box_b, f"bash /root/join-linux.sh {fp} --user adam", stdin=PW + "\n")
    after_boot(box_b, release, "an older join, the script run again (its fix)")

# the DC away: a person who logged on before still can (cached credentials)
sh(["docker", "stop", DC])
time.sleep(5)
code, out = logon(box, "alice", PW)
check("with the DC stopped, a person who logged on before still logs on (cached credentials)",
      code == 0 and "successfully" in out, out)
sh(["docker", "start", DC])

for _ in range(60):
    if dc_healthy():
        break
    time.sleep(5)

# a sudo rule on a host group (manual 1.6.11.7): lara (in no grant's sudo) may run uptime on the machines of hosts-web, which holds the
# 24.04 machine only; sssd matches the rule's sudoHost (each member's names) against the machine's own name
made = [run_op(V, SECRETS, "create_host_group", {"name": "web"}, DC),
        run_op(V, SECRETS, "set_host_group_member", {"name": "web", "machine": RELEASES["24.04"], "member": True}, DC),
        run_op(V, SECRETS, "add_sudo_rule", {"name": "web-uptime", "users": ["lara"], "commands": ["/usr/bin/uptime"],
                                             "run_as": ["root"], "hosts": "hosts-web"}, DC)]
check("a host group hosts-web holding the 24.04 machine, and a sudo rule for lara on it (its hosts: that "
      "machine's names)", RELEASES["24.04"] in made[2]["hosts"] and RELEASES["26.04"] not in made[2]["hosts"], made)
for name, applies in ((RELEASES["24.04"], True), (RELEASES["26.04"], False)):
    lbox = testrun.name(f"lj-{name}")
    on(lbox, "systemctl restart sssd")              # sssd's sudo rules fetched anew (else its next refresh)
    time.sleep(8)
    code, out = on(lbox, "sudo -l -U lara")
    check(f"{name}: the host group's sudo rule " + ("applies on its member: lara may run /usr/bin/uptime"
                                                    if applies else "does not apply on a machine outside it"),
          ("/usr/bin/uptime" in out) == applies and (applies or "not allowed" in out), out)

if not os.environ.get("FABRIC_TEST_KEEP"):         # FABRIC_TEST_KEEP=1 leaves the containers for a look
    cleanup()
print(f"\n{FAILED and 'FAILED' or 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
