"""The `samba` suite, real containers (manual 1.6.5.13, S1.3): a DC from fabric's image, run as the rendered compose
file runs it (on a private test network instead of the host's: WSL is shared with other environments), its files
written by the real deploy_samba, the domain converged by the real converge_domain — twice, the second changing
nothing — and the refusals: a site admin in another site, a password the policy refuses, a wrong password.
    sudo python3 tests/samba/dc.py
"""
import json
import os
import shlex
import shutil
import subprocess
import sys

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.directory.run_op import run_op  # noqa: E402
from fabriclib.federation.network_conflicts import network_conflicts  # noqa: E402
from fabriclib.federation.read_address_plan import read_address_plan  # noqa: E402
from fabriclib.radius.windows_lan_profile import windows_lan_profile  # noqa: E402
from fabriclib.samba.converge_domain import converge_domain  # noqa: E402
from fabriclib.samba.deploy_samba import deploy_samba  # noqa: E402
from fabriclib.samba.write_bind_dlz import write_bind_dlz  # noqa: E402
from fabriclib.secrets.random_password import random_password  # noqa: E402

W = os.path.join(os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests"), "samba")
NET, SUBNET, IP = "sambatest_net", "10.254.30.0/24", "10.254.30.10"
# BIND shares the DC's address, as both share the host's on an install (the AD zone sends updates to the DC's name)
BIND_IP = IP
DC, IMAGE, BIND = "sambatest-dc", "fabric/samba:test", "sambatest-bind"
CLIENT = IMAGE                  # the DC's image has dig and nsupdate (bind9-dnsutils)
BASE = "DC=ad,DC=lan,DC=test"
POLICY = {"minimum_length": 14, "complexity": True, "history": 24, "minimum_age_days": 0, "maximum_age_days": 0,
          "lockout_threshold": 5, "lockout_minutes": 15, "lockout_window_minutes": 15}
PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


def sh(cmd, ok=True, **kw):
    res = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)
    if ok and res.returncode:
        raise RuntimeError(f"{cmd}: {res.stderr.strip()[-400:]}")
    return res


def cleanup():
    sh(["docker", "rm", "-f", DC, BIND, "sambatest-rodc"], ok=False)
    sh(["docker", "network", "rm", NET], ok=False)


def dc(*args, stdin=None):
    return sh(["docker", "exec", "-i", DC, *args], ok=False, input=stdin)


def as_user(user, password, tool, ldif=None):
    """Run an ldb tool against the DC over LDAP as a user, from a throwaway container (the DC's image): ldbadd or
    ldbmodify with an LDIF, or (ldif None) ldbsearch of the domain's base, which needs a successful sign-in."""
    auth = os.path.join(W, f"{user}.auth")
    with open(auth, "w") as f:
        f.write(f"username={user}\npassword={password}\ndomain=AD\n")
    os.chmod(auth, 0o600)
    with open(os.path.join(W, "op.ldif"), "w") as f:
        f.write(ldif or "")
    what = ["/op.ldif"] if ldif is not None else ["-b", BASE, "-s", "base", "dn"]
    return sh(["docker", "run", "--rm", "--network", NET, "-v", f"{auth}:/auth:ro", "-v", f"{W}/op.ldif:/op.ldif:ro",
               "--entrypoint", tool, IMAGE, "-H", f"ldap://{IP}", "-A", "/auth", *what], ok=False)


cleanup()
shutil.rmtree(W, ignore_errors=True)
os.makedirs(os.path.join(W, "stepca", "data", "certs"))
DEBIAN = read_images_lock(os.path.join(REPO, "config"))["debian"]["ref"]
# the build folder as a host has it: install_service_units copies it with plain modes (files 0644)
context = os.path.join(W, "build")
shutil.copytree(f"{REPO}/packaging/images/samba", context)
for name in os.listdir(context):
    os.chmod(os.path.join(context, name), 0o644)
build = sh(["docker", "build", "-q", "-t", IMAGE, "--build-arg", f"BASE_IMAGE={DEBIAN}", context], ok=False)
check("the DC image builds from Debian's packages on the pinned base", build.returncode == 0, build.stderr)
if build.returncode:
    sys.exit(1)

# the settings and compose file as an install renders them
env = jinja_env(os.path.join(REPO, "templates"))
v = yaml.safe_load(env.get_template("vars.yaml.j2").render(
    domain="lan.test", hostname="pi-host", dc_name="dc1", host_ip=IP, lan_cidr=SUBNET, lan_gateway="10.254.30.1",
    site_name="lan",
    ad_domain="ad.lan.test", ad_password_policy=POLICY, deploy_base_dir=W,
    ad_ntp_signd_dir=os.path.join(W, "ntp_signd")))     # never the host's own /var/lib/samba
compose = yaml.safe_load(env.get_template("samba/docker-compose.yml.j2").render(**v))["services"]["samba"]
# a stand-in for fabric's Step-CA: the DC's certificate and the root CA the trust GPO carries
pki = os.path.join(W, "stepca", "data", "certs")
sh(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{pki}/root.key", "-out",
    f"{pki}/root_ca.crt", "-days", "2", "-subj", "/CN=Test Root"])
# fabric's secrets for the domain: the Administrator and the site's service accounts
SECRETS = {name: random_password() for name in ("ad_admin_password", "ad_agent_password", "ad_keycloak_password",
                                                "ad_radius_password")}
deploy_samba(v, SECRETS, env)
tls = os.path.join(W, "samba", "tls")
shutil.copy(f"{pki}/root_ca.crt", f"{tls}/root_ca.crt")
sh(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{tls}/privkey.pem", "-out",
    f"{tls}/fullchain.pem", "-days", "2", "-subj", f"/CN={v['hostname_dc']}"])
os.chmod(f"{tls}/privkey.pem", 0o600)
admin_pw = open(os.path.join(W, "samba", "secrets", "admin_password")).read().strip()
check("deploy_samba: the DC's resolver is the host's address",
      open(os.path.join(W, "samba", "resolv.conf")).read().startswith(f"nameserver {IP}\n"))
check("deploy_samba: root-only folders (data traversable: SYSVOL is served as each user), the password file "
      "0600, the converge code copied",
      all(os.stat(os.path.join(W, "samba", d)).st_mode & 0o077 == 0 for d in ("secrets", "converge"))
      and os.stat(os.path.join(W, "samba", "data")).st_mode & 0o777 == 0o755
      and os.stat(os.path.join(W, "samba", "secrets", "admin_password")).st_mode & 0o777 == 0o600
      and os.path.exists(os.path.join(W, "samba", "converge", "converge.py")))

# run it as the compose file says, on the test network
sh(["docker", "network", "create", "--subnet", SUBNET, NET])
# the container's host name is the host's (the host network gives it the host's): the DC has its own (2.1.6.45)
run = ["docker", "run", "-d", "--name", DC, "--hostname", "pi-host", "--network", NET, "--ip", IP,
       "--read-only", "--memory", compose["mem_limit"], "--cap-drop", "ALL"]
run += [x for c in compose["cap_add"] for x in ("--cap-add", c)]
run += [x for o in compose["security_opt"] for x in ("--security-opt", o)]
run += [x for t in compose["tmpfs"] for x in ("--tmpfs", t)]
run += [x for k, val in compose["environment"].items() for x in ("-e", f"{k}={val}")]
run += [x for m in compose["volumes"] for x in ("-v", m)]
run += ["--health-cmd", shlex.join(compose["healthcheck"]["test"][1:]), "--health-interval", "10s",
        "--health-start-period", "180s", IMAGE]
sh(run)
health = ""
for _ in range(60):
    health = sh(["docker", "inspect", "-f", "{{.State.Health.Status}}", DC], ok=False).stdout.strip()
    if health == "healthy":
        break
    sh("sleep 5")
check("the DC provisions and turns healthy", health == "healthy", sh(["docker", "logs", DC], ok=False).stdout[-800:])
if health != "healthy":
    cleanup()
    sys.exit(1)
check("provisioning prints no password (only that one was set)",
      all("password set for" in line for line in sh(["docker", "logs", DC], ok=False).stdout.lower().splitlines()
          if "password" in line))
info = json.loads(sh(["docker", "inspect", DC]).stdout)[0]["HostConfig"]
check("hardened as rendered: exactly the six capabilities, read-only, no-new-privileges, a memory limit",
      sorted(info["CapAdd"]) == ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_NET_BIND_SERVICE", "CAP_SETGID",
                                 "CAP_SETUID"]
      and info["CapDrop"] == ["ALL"] and info["ReadonlyRootfs"] and "no-new-privileges:true" in info["SecurityOpt"]
      and info["Memory"] > 0, info["CapAdd"])

dc_obj = dc("ldbsearch", "-H", "/data/private/sam.ldb", "(objectClass=computer)", "sAMAccountName",
            "dNSHostName").stdout
check("the DC provisions with its own name, unlike its host's (2.1.6.45): DC1$, dc1.ad.lan.test, no PI-HOST$",
      "sAMAccountName: DC1$" in dc_obj and "dNSHostName: dc1.ad.lan.test" in dc_obj and "PI-HOST" not in dc_obj.upper()
      and compose["environment"]["HOST_NAME"] == "dc1", dc_obj)
first = converge_domain(v, os.path.join(W, "federation.yaml"), SECRETS, container=DC)
check("converge: schema, layout, groups, access, AD site, policy and GPOs made", len(first) > 30, first)
again = converge_domain(v, os.path.join(W, "federation.yaml"), SECRETS, container=DC)
check("converge again changes nothing (idempotent)", again == [], again)

# 2.1.6.29: the AD zones keep no AAAA (the DC listens on IPv4 only); one published from the host's IPv6 goes at converge
AAAA_PROBE = r"""
import sys
sys.path.insert(0, "/fabric")
import ldb
from samba.dcerpc import dnsp
from samba.dnsserver import AAAARecord
from samba.ndr import ndr_pack, ndr_unpack
from open_samdb import open_samdb
samdb, lp = open_samdb("/data/etc/smb.conf")
base, realm = str(samdb.domain_dn()), lp.get("realm").lower()
dn = f"DC=@,DC={realm},CN=MicrosoftDNS,DC=DomainDnsZones,{base}"
node = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["dnsRecord"])[0]
types = lambda n: sorted({ndr_unpack(dnsp.DnssrvRpcRecord, bytes(r)).wType for r in n.get("dnsRecord", [])})
if sys.argv[1] == "add":
    m = ldb.Message(node.dn)
    m["dnsRecord"] = ldb.MessageElement([ndr_pack(AAAARecord("fd01::d034"))], ldb.FLAG_MOD_ADD, "dnsRecord")
    samdb.modify(m)
print(types(samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["dnsRecord"])[0]))
"""
added = dc("python3", "-", "add", stdin=AAAA_PROBE).stdout.strip()
cleaned = converge_domain(v, os.path.join(W, "federation.yaml"), SECRETS, container=DC)
after = dc("python3", "-", "show", stdin=AAAA_PROBE).stdout.strip()
check("an IPv6 record in the AD zone (from the host's IPv6) is removed by the next converge; its A stays (2.1.6.29)",
      "28" in added and any("IPv6 record removed" in c for c in cleaned) and "28" not in after and "1" in after,
      (added, cleaned, after))
check("converge wrote the site's networks into its OU=networks (the address plan, S4.1)",
      "network lan added" in first and [(n["site"], n["name"], n["cidr"]) for n in read_address_plan(v, SECRETS, DC)]
      == [("lan", "lan", SUBNET)], first)

# S2.2: the site's service accounts, its id block, fabric's groups with their gids, the agent's own sign-in
info_ = run_op(v, SECRETS, "site_info", container=DC)
check("the agent signs in as fabric-agent-lan and reads its site's id block: site 1's, 1000000-1999999, laid out in "
      "ranges, one mark each (2.1.6.46)", info_["id_range"] == "1000000-1999999"
      and set(info_["id_marks"]) == {"first_admin", "admin", "service", "builtin_group", "group", "person", "guest"},
      info_)
def attr(filter_, name):
    out = dc("ldbsearch", "-H", "/data/private/sam.ldb", filter_, name).stdout
    return [line.split(": ", 1)[1] for line in out.splitlines() if line.startswith(name + ": ")]
check("the organisation's groups carry their fixed gids in the root's built-in range: admins 1040001 in "
      "OU=organisation, Domain Users 1040009 (fabric's users)",
      attr("(sAMAccountName=admins)", "gidNumber") == ["1040001"]
      and attr("(sAMAccountName=Domain Users)", "gidNumber") == ["1040009"]
      and "OU=organisation" in attr("(sAMAccountName=admins)", "distinguishedName")[0])
site_gids = [int(attr(f"(sAMAccountName={g})", "gidNumber")[0]) for g in ("lan-users", "lan-admins",
                                                                          "fabric-break-glass")]
check("the site's own groups and break-glass take gids from the built-in range, past the organisation's hundred",
      all(1040101 <= g <= 1049999 for g in site_gids) and len(set(site_gids)) == 3, site_gids)
svc_uids = [int((attr(f"(sAMAccountName=fabric-{k}-lan)", "uidNumber") or ["0"])[0])
            for k in ("agent", "keycloak", "radius")]
check("the site's service accounts take uids from the service range (1020001-1039999), primary gid users, no shell",
      all(1020001 <= u <= 1039999 for u in svc_uids) and len(set(svc_uids)) == 3
      and attr("(sAMAccountName=fabric-agent-lan)", "gidNumber") == ["1040009"]
      and attr("(sAMAccountName=fabric-agent-lan)", "loginShell") == ["/usr/sbin/nologin"], svc_uids)
uac = attr("(sAMAccountName=fabric-agent-lan)", "userAccountControl")
check("the site's service accounts exist in its OU, their passwords never expiring",
      all(attr(f"(sAMAccountName=fabric-{k}-lan)", "distinguishedName")[0].startswith(f"CN=fabric-{k}-lan,OU=service-accounts,")
          for k in ("agent", "keycloak", "radius")) and int(uac[0]) & 0x10000)
priv = os.stat(os.path.join(W, "samba", "data", "state", "winbindd_privileged"))
check("winbind's privileged pipe: FreeRADIUS's group only (root, 0750); its socket in the host folder FreeRADIUS mounts",
      (priv.st_uid, priv.st_gid, priv.st_mode & 0o7777) == (0, int(v["service_users"]["freeradius"]["gid"]), 0o750)
      and os.path.exists(os.path.join(W, "samba", "winbindd", "pipe")),
      (priv.st_uid, priv.st_gid, oct(priv.st_mode)))
signd = os.stat(os.path.join(W, "ntp_signd"))
check("the DC's time-signing socket in the folder the host's chrony reaches (2.1.13.1): root, 0750",
      os.path.exists(os.path.join(W, "ntp_signd", "socket")) and signd.st_uid == 0
      and signd.st_mode & 0o7777 == 0o750, oct(signd.st_mode))
SECRETS["ad_agent_password"] = random_password()
healed = converge_domain(v, os.path.join(W, "federation.yaml"), SECRETS, container=DC)
check("a changed agent password is set by the next convergence (when the old one no longer signs in)",
      healed == ["service account fabric-agent-lan: password set"]
      and run_op(v, SECRETS, "site_info", container=DC)["dn"].startswith("OU=lan"), healed)
try:
    run_op(v, {**SECRETS, "ad_agent_password": "wrong"}, "site_info", container=DC)
    check("refused: the agent with a wrong password", False)
except ValidationError as e:
    check("refused: the agent with a wrong password", "refused" in str(e), e)
try:
    run_op(v, SECRETS, "no_such_op", container=DC)
    check("refused: an operation the DC does not know", False)
except ValidationError as e:
    check("refused: an operation the DC does not know", "unknown directory operation" in str(e), e)
ous = dc("ldbsearch", "-H", "/data/private/sam.ldb", "-b", f"OU=sites,{BASE}", "(objectClass=organizationalUnit)",
         "dn").stdout
check("the site's OU tree under OU=sites, with OU=organisation at the root site",
      ous.count("dn: ") == 14 and f"OU=organisation,OU=lan,OU=sites,{BASE}" in ous, ous.count("dn: "))
check("the directory is consistent (dbcheck)", "(0 errors)" in dc("samba-tool", "dbcheck", "-s", "/data/etc/smb.conf",
                                                                  "--cross-ncs").stdout)
policy = dc("samba-tool", "domain", "passwordsettings", "show", "-s", "/data/etc/smb.conf").stdout
check("the admin's password policy is the domain's",
      "Minimum password length: 14" in policy and "Password complexity: on" in policy
      and "Account lockout threshold (attempts): 5" in policy, policy)
gpos = dc("samba-tool", "gpo", "listall", "-H", "/data/private/sam.ldb", "-s", "/data/etc/smb.conf").stdout
check("the trust GPO and the site's log-on GPO exist", "fabric: trust in fabric's root CA" in gpos
      and "fabric: lan log-on rights" in gpos, gpos)
files = dc("find", "/data/state/sysvol", "-name", "Registry.pol", "-o", "-name", "GptTmpl.inf").stdout
check("their files are in SYSVOL (Registry.pol, GptTmpl.inf)", "Registry.pol" in files and "GptTmpl.inf" in files)
inf_path = next(x for x in files.splitlines() if x.endswith("GptTmpl.inf"))
inf = subprocess.run(["docker", "exec", DC, "cat", inf_path], capture_output=True).stdout     # UTF-16: bytes
check("the log-on policy names the site's groups and each machine's local Administrators (never lock out)",
      "S-1-5-32-544".encode("utf-16-le") in inf and "SeInteractiveLogonRight".encode("utf-16-le") in inf)
check("...and makes the site's windows-admins role a member of each machine's Administrators (added, 2.1.9.13)",
      "__Memberof = *S-1-5-32-544".encode("utf-16-le") in inf and "[Group Membership]".encode("utf-16-le") in inf)
roles = dc("ldbsearch", "-H", "/data/private/sam.ldb", "(&(objectClass=group)(sAMAccountName=lan-*))",
           "sAMAccountName", "member").stdout
check("the site's five role groups, lan-admins a member of each (2.1.9.13)",
      all(f"sAMAccountName: lan-{r}" in roles for r in ("ou-admins", "machine-admins", "gpo-admins", "linux-sudo",
                                                      "windows-admins"))
      and roles.count("member: CN=lan-admins,") == 5, roles[-600:])

# BIND serves the AD zone from the DC's database through DLZ (manual 1.6.5.6, Q2): fabric's BIND image with the
# files write_bind_dlz makes, mounted as the rendered compose file mounts them; a minimal named.conf around them
check("before the domain exists BIND's DLZ files load nothing", "not provisioned" in open(
    os.path.join(W, "samba", "bind", "dlz.conf")).read())
check("once provisioned, write_bind_dlz turns DLZ on (BIND must restart)", write_bind_dlz(v) is True)
check("and again changes nothing", write_bind_dlz(v) is False)
bind_build = sh(["docker", "build", "-q", "-t", "fabric/bind9:samba-test", "--build-arg", f"BASE_IMAGE={DEBIAN}",
                 f"{REPO}/packaging/images/bind9"], ok=False)
check("fabric's BIND image (with Samba's DLZ libraries) builds", bind_build.returncode == 0, bind_build.stderr)
etc_bind = os.path.join(W, "bindtest")
os.makedirs(etc_bind)
with open(os.path.join(etc_bind, "named.conf"), "w") as f:
    f.write('options {\n directory "/var/cache/bind";\n listen-on port 53 { any; };\n listen-on-v6 { none; };\n'
            ' recursion no;\n allow-query { any; };\n include "/etc/bind-samba/options.conf";\n};\n'
            'zone "lan.test" { type primary; file "/etc/bind/db.lan.test"; };\n'
            'include "/etc/bind-samba/dlz.conf";\n')
with open(os.path.join(etc_bind, "db.lan.test"), "w") as f:
    f.write("$TTL 300\n@ IN SOA ns.lan.test. admin.lan.test. 1 3600 600 86400 300\n@ IN NS ns.lan.test.\n"
            "ns IN A 10.254.30.10\nweb IN A 10.254.30.20\n")
for name in os.listdir(etc_bind):
    os.chmod(os.path.join(etc_bind, name), 0o644)
os.chmod(etc_bind, 0o755)
bind_compose = yaml.safe_load(env.get_template("bind9/docker-compose.yml.j2").render(**v))["services"]["bind9"]
samba_mounts = [m for m in bind_compose["volumes"]
                if m.split(":")[1] in ("/etc/bind-samba", "/data/bind-dns", "/etc/samba")]
sh(["docker", "run", "-d", "--name", BIND, "--network", f"container:{DC}", "--user", "600:600", "--read-only",
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--memory", "128m",
    "--tmpfs", "/run/named:uid=600,gid=600,mode=0755,size=4m", "--tmpfs", "/tmp:size=8m",
    "--tmpfs", "/var/cache/bind:uid=600,gid=600,size=8m"]
   + [x for t in bind_compose["tmpfs"] if t.startswith("/var/tmp") for x in ("--tmpfs", t)]
   + [x for m in samba_mounts for x in ("-v", m)] + ["-v", f"{etc_bind}:/etc/bind:ro", "fabric/bind9:samba-test"])
sh("sleep 8")


def client(*args):
    return sh(["docker", "run", "--rm", "--network", NET, "--entrypoint", args[0], CLIENT, *args[1:]], ok=False)


def unsigned_update(zone):
    """An nsupdate with no key: BIND must refuse it in every zone."""
    with open(os.path.join(W, "upd"), "w") as f:
        f.write(f"server {BIND_IP}\nzone {zone}\nupdate add evil.{zone} 60 A 10.254.30.66\nsend\n")
    return sh(["docker", "run", "--rm", "--network", NET, "-v", f"{W}/upd:/upd:ro", "--entrypoint", "nsupdate",
               CLIENT, "/upd"], ok=False)


srv = client("dig", "+short", f"@{BIND_IP}", "SRV", "_ldap._tcp.ad.lan.test").stdout
check("BIND answers the AD zone from the DC's database (DLZ)", "389 dc1.ad.lan.test." in srv,
      sh(["docker", "logs", BIND], ok=False).stderr[-600:])
check("and fabric's own zone, unchanged", client("dig", "+short", f"@{BIND_IP}", "A", "web.lan.test").stdout.strip()
      == "10.254.30.20")
upd = dc("samba_dnsupdate", "-s", "/data/etc/smb.conf", "--all-names")
check("the DC's signed (GSS-TSIG) updates are accepted through BIND",
      upd.returncode == 0 and "Failed update" not in upd.stdout + upd.stderr, (upd.stdout + upd.stderr)[-400:])
cmd = dc("testparm", "-s", "--parameter-name=dns update command", "/data/etc/smb.conf").stdout.strip()
pinned = dc("sh", "-c", f"{cmd} -s /data/etc/smb.conf --all-names")
a_rec = client("dig", "+short", f"@{BIND_IP}", "A", "dc1.ad.lan.test").stdout.split()
check("the DC's own DNS updates name its LAN address only, never fabric_net's gateway it also listens on (2.1.2.15)",
      f"--current-ip={IP}" in cmd and pinned.returncode == 0 and a_rec == [IP], (cmd, a_rec, pinned.stderr[-300:]))
evil = unsigned_update("ad.lan.test")
check("refused: an unsigned update to the AD zone", "REFUSED" in evil.stdout + evil.stderr, evil.stderr[-200:])
evil = unsigned_update("lan.test")
check("refused: an unsigned update to fabric's zone", "REFUSED" in evil.stdout + evil.stderr, evil.stderr[-200:])
bind_info = json.loads(sh(["docker", "inspect", BIND]).stdout)[0]
check("BIND still runs as its own user with no capabilities", bind_info["Config"]["User"] == "600:600"
      and not bind_info["HostConfig"]["CapAdd"] and bind_info["State"]["Running"])

# refusals: a site's admin writes its own site only (Q4), the policy is enforced
LAB_NETS = [{"name": "lan", "cidr": "10.77.0.0/24", "kind": "lan", "vlan": None, "notes": "", "allow_overlap": ""},
            {"name": "iot", "cidr": "10.78.0.0/24", "kind": "dhcp", "vlan": 21, "notes": "cameras", "allow_overlap": ""}]
lab = {"site": "lab", "root": False, "parent": "lan", "password_policy": POLICY, "networks": LAB_NETS,
       "root_ca_pem": open(f"{pki}/root_ca.crt").read(), "id_range": "200001-300000", "groups": [],
       "admin_group": "admins",
       "accounts": {f"fabric-{k}-lab": random_password() for k in ("agent", "keycloak", "radius")}, "radius_gid": 610,
       "lan_profile": windows_lan_profile("peap", "radius.lab.lan.test", "aa " * 19 + "aa")}
res = dc("python3", "/fabric/converge.py", stdin=json.dumps(lab))
check("a second site's OU, groups and access entries", res.returncode == 0 and "group lab-admins created" in res.stdout,
      res.stderr)
check("...its OU nested in its parent's (2.1.6.20), marked as a site OU",
      "dn: OU=lab,OU=lan,OU=sites," in dc("ldbsearch", "-H", "/data/private/sam.ldb", "(&(objectClass=fabricSiteInfo)(ou=lab))", "dn").stdout)
READ_BASELINE = r"""
import json, os, sys
import ldb
from samba.dcerpc import preg
from samba.ndr import ndr_unpack
sys.path.insert(0, "/fabric")
from open_samdb import open_samdb
samdb, lp = open_samdb("/data/etc/smb.conf")
out = {}
for site in ("lan", "lab"):
    g = samdb.search(base="CN=Policies,CN=System," + str(samdb.domain_dn()), scope=ldb.SCOPE_ONELEVEL,
                     expression="(displayName=fabric: %s Windows baseline)" % site,
                     attrs=["cn", "gPCMachineExtensionNames", "versionNumber"])[0]
    folder = os.path.join(lp.get("path", "sysvol"), lp.get("realm").lower(), "Policies", str(g["cn"]), "Machine")
    pol = ndr_unpack(preg.file, open(os.path.join(folder, "Registry.pol"), "rb").read())
    ou = "OU=lan,OU=sites" if site == "lan" else "OU=lab,OU=lan,OU=sites"
    link = samdb.search(base="%s,%s" % (ou, samdb.domain_dn()), scope=ldb.SCOPE_BASE, attrs=["gPLink"])
    scripts = os.path.join(folder, "Scripts")
    out[site] = {"linked": str(g.dn).lower() in str(link[0].get("gPLink", [""])[0]).lower(),
                 "ext": str(g["gPCMachineExtensionNames"]), "version": int(str(g["versionNumber"])),
                 "values": sorted([e.keyname, e.valuename, e.data] for e in pol.entries),
                 "ini": open(os.path.join(scripts, "scripts.ini"), "rb").read().decode("utf-16")
                 if os.path.exists(os.path.join(scripts, "scripts.ini")) else None,
                 "xml": open(os.path.join(scripts, "Startup", "fabric-lan.xml")).read()
                 if os.path.exists(os.path.join(scripts, "Startup", "fabric-lan.xml")) else None,
                 "cmd": open(os.path.join(scripts, "Startup", "fabric-8021x.cmd"), "rb").read().decode()
                 if os.path.exists(os.path.join(scripts, "Startup", "fabric-8021x.cmd")) else None}
print(json.dumps(out))
"""
base_res = dc("python3", "-", stdin=READ_BASELINE)
baseline = json.loads(base_res.stdout or "{}") if base_res.returncode == 0 else {}
want_values = [["Software\\Policies\\Microsoft\\W32Time\\Parameters", "Type", "NT5DS"],
               ["Software\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "SyncForegroundPolicy", 1]]
check("each site's Windows baseline GPO is linked to its OU: wait for the network at log-on, the domain's time (NT5DS)",
      all(baseline.get(s, {}).get("linked") and baseline[s]["values"] == want_values for s in ("lan", "lab")),
      base_res.stderr[-400:] or baseline)
lab_b, lan_b = baseline.get("lab", {}), baseline.get("lan", {})
check("with 802.1X (lab): a start-up script turns on Wired AutoConfig and adds the PEAP profile naming the site's server",
      lab_b.get("ini") and "0CmdLine=fabric-8021x.cmd" in lab_b["ini"] and "netsh lan add profile" in lab_b["cmd"]
      and "<Type>25</Type>" in lab_b["xml"] and "radius.lab.lan.test" in lab_b["xml"]
      and "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}" in lab_b["ext"], lab_b)
check("without 802.1X (lan: FreeRADIUS off): no script, the registry settings only",
      lan_b.get("ini") is None and lan_b.get("xml") is None and "{42B5FAAE" not in lan_b.get("ext", "x{42B5FAAE"), lan_b)
plan = read_address_plan(v, SECRETS, DC)
check("the address plan, read as lan's agent, holds every site's networks with VLAN and notes (nothing gathered)",
      [(n["site"], n["name"], n["cidr"], n["vlan"], n["notes"]) for n in plan]
      == [("lab", "lan", "10.77.0.0/24", None, ""), ("lab", "iot", "10.78.0.0/24", 21, "cameras"),
          ("lan", "lan", SUBNET, None, "")], plan)
clash = network_conflicts([{"name": "new", "cidr": "10.78.0.128/25"}], plan, "lan")
check("a network of this site overlapping another site's is found in the plan",
      clash and clash[0]["other_site"] == "lab" and not clash[0]["allowed"], clash)
lab_less = dc("python3", "/fabric/converge.py", stdin=json.dumps({**lab, "networks": LAB_NETS[:1]}))
check("a network a site no longer has leaves the plan (and its AD subnet)",
      "network iot removed" in lab_less.stdout and [n["name"] for n in read_address_plan(v, SECRETS, DC)
                                                    if n["site"] == "lab"] == ["lan"], lab_less.stdout[-400:])
lab_pw = random_password(20)
made = dc("samba-tool", "user", "create", "labadmin", lab_pw, "--userou=OU=people,OU=lab,OU=lan,OU=sites",
          "-s", "/data/etc/smb.conf")
dc("samba-tool", "group", "addmembers", "lab-admins", "labadmin", "-s", "/data/etc/smb.conf")
check("a lab admin is created", made.returncode == 0, made.stderr)
user = "dn: CN={0},OU=people,{1},%s\nobjectClass: user\nsAMAccountName: {0}\n" % BASE
LAN_OU, LAB_OU = "OU=lan,OU=sites", "OU=lab,OU=lan,OU=sites"
own = as_user("labadmin", lab_pw, "ldbadd", user.format("labuser", LAB_OU))
check("a site admin adds a person in its own site", "successfully" in own.stdout + own.stderr, own.stderr)
other = as_user("labadmin", lab_pw, "ldbadd", user.format("intruder", LAN_OU))
share = sh(["docker", "run", "--rm", "--network", NET, "-v", f"{W}/labadmin.auth:/auth:ro", "--entrypoint",
            "smbclient", IMAGE, f"//{IP}/sysvol", "-A", "/auth", "-c",
            "ls ad.lan.test/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/*"], ok=False)
check("an ordinary domain user reads SYSVOL (Group Policy reads it as the machine; found on host-1, S1.7)",
      share.returncode == 0 and "GPT.INI" in share.stdout.upper(), (share.stdout + share.stderr)[-300:])
agent_own = as_user("fabric-agent-lan", SECRETS["ad_agent_password"], "ldbadd", user.format("agentmade", LAN_OU))
check("the site's agent adds a person in its own site", "successfully" in agent_own.stdout + agent_own.stderr,
      agent_own.stderr[-200:])
agent_child = as_user("fabric-agent-lan", SECRETS["ad_agent_password"], "ldbadd", user.format("agentkid", LAB_OU))
check("the parent's agent adds a person in the site nested below it (inherited, 2.1.6.20)",
      "successfully" in agent_child.stdout + agent_child.stderr, agent_child.stderr[-200:])
lab_agent = lab["accounts"]["fabric-agent-lab"]
agent_up = as_user("fabric-agent-lab", lab_agent, "ldbadd", user.format("agentevil", LAN_OU))
check("refused: a nested site's agent adding a person in its parent",
      "successfully" not in agent_up.stdout + agent_up.stderr)
kid_svc = as_user("fabric-agent-lan", SECRETS["ad_agent_password"], "ldbadd",
                  f"dn: CN=svc3,OU=service-accounts,{LAB_OU},{BASE}\nobjectClass: user\nsAMAccountName: svc3\n")
check("refused: the parent's agent adding to a nested site's service accounts",
      "successfully" not in kid_svc.stdout + kid_svc.stderr)
protect = as_user("labadmin", lab_pw, "ldbmodify",
                  f"dn: {LAB_OU},{BASE}\nchangetype: modify\nreplace: nTSecurityDescriptor\n"
                  "nTSecurityDescriptor: O:DAG:DAD:P(A;;GA;;;DA)\n")
as_user("Administrator", admin_pw, "ldbadd", f"dn: OU=sdtest,{BASE}\nobjectClass: organizationalUnit\n")
control = as_user("Administrator", admin_pw, "ldbmodify",
                  f"dn: OU=sdtest,{BASE}\nchangetype: modify\nreplace: nTSecurityDescriptor\n"
                  "nTSecurityDescriptor: O:DAG:DAD:P(A;;GA;;;DA)\n")
check("refused: a nested site's admin changing its OU's permissions (it cannot shut its parents out; the same "
      "change by the domain's Administrator works)", "successfully" in control.stdout + control.stderr
      and "successfully" not in protect.stdout + protect.stderr, (control.stderr + protect.stderr)[-300:])
agent_svc = as_user("fabric-agent-lan", SECRETS["ad_agent_password"], "ldbadd",
                    f"dn: CN=svc2,OU=service-accounts,OU=lan,OU=sites,{BASE}\nobjectClass: user\nsAMAccountName: svc2\n")
check("refused: the site's agent adding to its own site's service accounts",
      "successfully" not in agent_svc.stdout + agent_svc.stderr)
check("refused: a site admin adding a person in another site", "successfully" not in other.stdout + other.stderr)
svc = as_user("labadmin", lab_pw, "ldbadd",
              f"dn: CN=svc,OU=service-accounts,OU=lab,OU=lan,OU=sites,{BASE}\nobjectClass: user\nsAMAccountName: svc\n")
check("refused: a site admin adding to its site's service accounts", "successfully" not in svc.stdout + svc.stderr)
domain = as_user("labadmin", lab_pw, "ldbmodify",
                 f"dn: CN=Administrator,CN=Users,{BASE}\nchangetype: modify\nreplace: description\ndescription: x\n")
check("refused: a site admin changing the domain's Administrator", "successfully" not in domain.stdout + domain.stderr)
# roles given apart (2.1.9.13): a machine admin of lab who is not a lab admin
mach_pw = random_password(20)
dc("samba-tool", "user", "create", "macky", mach_pw, f"--userou=OU=people,{LAB_OU}", "-s", "/data/etc/smb.conf")
dc("samba-tool", "group", "addmembers", "lab-machine-admins", "macky", "-s", "/data/etc/smb.conf")
computer = (f"dn: CN=LABPC1,OU=machines,{LAB_OU},{BASE}\nobjectClass: computer\nsAMAccountName: LABPC1$\n"
            "userAccountControl: 4096\n")
m_pc = as_user("macky", mach_pw, "ldbadd", computer)
check("lab's machine-admins role adds a machine to lab", "successfully" in m_pc.stdout + m_pc.stderr,
      m_pc.stderr[-200:])
m_person = as_user("macky", mach_pw, "ldbadd", user.format("byrole", LAB_OU))
check("refused: the machine-admins role adding a person (that is ou-admins')",
      "successfully" not in m_person.stdout + m_person.stderr)
lab_policies = dc("ldbsearch", "-H", "/data/private/sam.ldb", "-b", f"{LAB_OU},{BASE}", "-s", "base",
                  "nTSecurityDescriptor").stdout.replace("\n ", "")      # LDIF folds long lines
gpo_sid = dc("ldbsearch", "-H", "/data/private/sam.ldb", "(sAMAccountName=lab-gpo-admins)", "objectSid").stdout
gpo_sid = gpo_sid.split("objectSid: ")[1].split()[0] if "objectSid: " in gpo_sid else "?"
check("lab's gpo-admins role may write its OU's GPO links and blocked inheritance, and nothing else there",
      f"(OA;;RPWP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;;{gpo_sid})" in lab_policies
      and f"(OA;;RPWP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;;{gpo_sid})" in lab_policies
      and f"(A;CI;RPWPCRCCDCLCLORCSDDTSW;;;{gpo_sid})" not in lab_policies, lab_policies[-500:])
short = dc("samba-tool", "user", "create", "shorty", "Ab1shortpw", "-s", "/data/etc/smb.conf")
check("refused: a password shorter than the policy's minimum", short.returncode != 0)
wrong = as_user("labadmin", lab_pw + "x", "ldbsearch")
check("refused: a wrong password", wrong.returncode != 0 and BASE not in wrong.stdout, wrong.stdout[-200:])
admin = as_user("Administrator", admin_pw, "ldbsearch")
check("the Administrator signs in with fabric's generated password", admin.returncode == 0 and BASE in admin.stdout,
      admin.stderr)

# S2.4: people, as the site's agent (manual 1.6.3.4, 1.6.3.9)
def mk(uid, email=None, pw=None, site_v=None, sec=None):
    return run_op(site_v or v, sec or SECRETS, "create_person",
                  {"uid": uid, "first": uid.title(), "last": "Test", "email": email or f"{uid}@lan.test",
                   "password": pw or ("Pw-" + random_password(20)), "gid": 5000, "home_base": "/home",
                   "shell": "/bin/bash"}, container=DC)


alice = mk("alice")
check("a person is created with a uid from the people range of the site's block (1100001-1899999)",
      1100001 <= alice["uidNumber"] <= 1899999, alice)
check("their POSIX identity: primary gid 5000 (fabric's users), /home/alice, /bin/bash, in lan-users",
      attr("(sAMAccountName=alice)", "gidNumber") == ["5000"]
      and attr("(sAMAccountName=alice)", "unixHomeDirectory") == ["/home/alice"]
      and attr("(sAMAccountName=alice)", "loginShell") == ["/bin/bash"]
      and any(m.startswith("CN=lan-users,") for m in attr("(sAMAccountName=alice)", "memberOf")))
check("they live in the site's OU=people, named by their user name",
      attr("(sAMAccountName=alice)", "distinguishedName")[0].startswith("CN=alice,OU=people,OU=lan,OU=sites,"))
for label, args in (("the same user name", ("alice", "other@lan.test")), ("the same e-mail address", ("alice2",
                                                                                                    "alice@lan.test"))):
    try:
        mk(*args)
        check(f"refused: {label}", False)
    except ValidationError as e:
        check(f"refused: {label}", "already taken" in str(e), e)
try:
    mk("shortpw", pw="Ab1-short")
    check("refused: a one-time password the policy refuses", False)
except ValidationError as e:
    check("refused: a one-time password the policy refuses", "refused" in str(e), e)
people = run_op(v, SECRETS, "list_people", container=DC)
a = next((u for u in people["users"] if u["uid"] == "alice"), {})
check("the People page lists the person (site, groups, not locked) and no service account",
      a.get("site") == "lan" and "lan-users" in a.get("groups", []) and a.get("locked") is False
      and not any(u["uid"].startswith("fabric-") for u in people["users"])
      and any(g["name"] == "admins" for g in people["groups"]), a)
check("nothing secret in the list", "password" not in json.dumps(people).lower() and "unicodePwd" not in json.dumps(people))
person = run_op(v, SECRETS, "get_person", {"uid": "alice"}, container=DC)
check("a person's groups for the reset guard", "lan-users" in person["groups"], person)
new_otp = "Rs-" + random_password(20)
run_op(v, SECRETS, "reset_password", {"uid": "alice", "password": new_otp}, container=DC)
check("a reset sets a new one-time password (it must be changed: AD refuses it for a sign-in until then)",
      attr("(sAMAccountName=alice)", "pwdLastSet") == ["0"])
try:
    run_op({**v, "site_name": "lab"}, {**SECRETS, "ad_agent_password": lab["accounts"]["fabric-agent-lab"]},
           "reset_password", {"uid": "alice", "password": new_otp}, container=DC)
    check("refused: a nested site's agent resetting a person of its parent", False)
except ValidationError as e:
    check("refused: a nested site's agent resetting a person of its parent",
          "refused" in str(e) or "not permitted" in str(e), e)

# fabricctl people's operations (2.1.6.30, manual 1.6.3.11): disable / enable, groups, remove — the site's own only
dave_pw = "Dv-" + random_password(20)
mk("dave", pw=dave_pw)
dc("samba-tool", "user", "setpassword", "dave", f"--newpassword={dave_pw}", "-s", "/data/etc/smb.conf")
signin = as_user("dave", dave_pw, "ldbsearch")
check("a person signs in (the starting point)", signin.returncode == 0 and BASE in signin.stdout, signin.stderr[-300:])
off = run_op(v, SECRETS, "set_person", {"uid": "dave", "enabled": False}, container=DC)
signin = as_user("dave", dave_pw, "ldbsearch")
check("disable: the account is disabled and its sign-in refused", off["changed"] and signin.returncode != 0
      and int(attr("(sAMAccountName=dave)", "userAccountControl")[0]) & 0x2, signin.stdout[-200:])
again = run_op(v, SECRETS, "set_person", {"uid": "dave", "enabled": False}, container=DC)
check("disable twice: no change the second time", again["changed"] is False, again)
listed = next(u for u in run_op(v, SECRETS, "list_people", container=DC)["users"] if u["uid"] == "dave")
check("the People list shows them locked", listed["locked"] is True, listed)
on = run_op(v, SECRETS, "set_person", {"uid": "dave", "enabled": True}, container=DC)
signin = as_user("dave", dave_pw, "ldbsearch")
check("enable: they sign in again", on["changed"] and signin.returncode == 0, signin.stderr[-300:])
for label, args, site_v, sec in (
        ("a service account is not a person", {"uid": "fabric-agent-lan", "enabled": False}, v, SECRETS),
        ("a nested site's agent disabling a person of its parent", {"uid": "dave", "enabled": False},
         {**v, "site_name": "lab"}, {**SECRETS, "ad_agent_password": lab["accounts"]["fabric-agent-lab"]})):
    try:
        run_op(site_v, sec, "set_person", args, container=DC)
        check(f"refused: {label}", False)
    except ValidationError as e:
        check(f"refused: {label}", "no such entry" in str(e) or "refused" in str(e), e)
added = run_op(v, SECRETS, "add_group_member", {"group": "admins", "uid": "dave"}, container=DC)
gone = run_op(v, SECRETS, "remove_group_member", {"group": "admins", "uid": "dave"}, container=DC)
twice = run_op(v, SECRETS, "remove_group_member", {"group": "admins", "uid": "dave"}, container=DC)
check("groups: in, then out of a group, once", added["added"] and gone["removed"] and twice["removed"] is False
      and "admins" not in run_op(v, SECRETS, "get_person", {"uid": "dave"}, container=DC)["groups"])
try:
    run_op(v, SECRETS, "remove_group_member", {"group": "no-such-group", "uid": "dave"}, container=DC)
    check("refused: a group that does not exist", False)
except ValidationError as e:
    check("refused: a group that does not exist", "no such entry" in str(e), e)
try:
    run_op({**v, "site_name": "lab"}, {**SECRETS, "ad_agent_password": lab["accounts"]["fabric-agent-lab"]},
           "remove_person", {"uid": "dave"}, container=DC)
    check("refused: a nested site's agent removing a person of its parent", False)
except ValidationError as e:
    check("refused: a nested site's agent removing a person of its parent", "no such entry" in str(e), e)
run_op(v, SECRETS, "remove_person", {"uid": "dave"}, container=DC)
signin = as_user("dave", dave_pw, "ldbsearch")
check("remove: the account is gone and its sign-in refused", attr("(sAMAccountName=dave)", "dn") == []
      and signin.returncode != 0)
first = alice["uidNumber"]
dc("samba-tool", "user", "delete", "alice", "-s", "/data/etc/smb.conf")
carol = mk("carol")
check("ids are never reused: after alice is deleted, carol gets a higher number", carol["uidNumber"] > first, carol)
# a tiny site whose block is used up: its 7 groups (users, admins, the five roles) take 900-906, one person 907
tiny = {**lab, "site": "tiny", "id_range": "900-907", "networks": [],
        "accounts": {f"fabric-{k}-tiny": random_password() for k in ("agent", "keycloak", "radius")}, "radius_gid": 610}
dc("python3", "/fabric/converge.py", stdin=json.dumps(tiny))
tiny_v, tiny_s = {**v, "site_name": "tiny"}, {**SECRETS, "ad_agent_password": tiny["accounts"]["fabric-agent-tiny"]}
first_tiny = mk("tina", site_v=tiny_v, sec=tiny_s)
check("a site's people take numbers from that site's own block (a block from before 0.7.0: one run, as before)",
      first_tiny["uidNumber"] == 907, first_tiny)
try:
    mk("tim", site_v=tiny_v, sec=tiny_s)
    check("refused: a person when the site's block is full", False)
except ValidationError as e:
    check("refused: a person when the site's block is full", "full" in str(e), e)

# 2.1.6.46 (manual 1.6.3.17): each kind of account in its range; a full range refused, naming it; the 1000th block
def mk_kind(uid, kind):
    return run_op(v, SECRETS, "create_person", {"uid": uid, "first": uid.title(), "last": "Test",
                                                "email": f"{uid}@lan.test", "password": "Pw-" + random_password(20),
                                                "gid": 1040009, "home_base": "/home", "shell": "/bin/bash",
                                                "kind": kind}, container=DC)


boss, boss2 = mk_kind("boss", "first_admin"), mk_kind("boss2", "first_admin")
adm, gst = mk_kind("adm", "admin"), mk_kind("gst", "guest")
check("the first admin takes the block's first id; past it, an admin account's range; admins and guests their own",
      boss["uidNumber"] == 1000000 and 1000001 <= boss2["uidNumber"] <= 1019999
      and 1000001 <= adm["uidNumber"] <= 1019999 and 1900001 <= gst["uidNumber"] <= 1949999, (boss, boss2, adm, gst))
try:
    mk_kind("svc", "service")
    why = ""
except ValidationError as e:
    why = str(e)
check("refused: a person in a range that is not a person's (service accounts are fabric's)", "kind" in why, why)
FILL = """
import sys
sys.path.insert(0, "/fabric")
import ldb
from open_samdb import open_samdb
import paths
samdb, _ = open_samdb("/data/etc/smb.conf")
dn = paths.site_dn(samdb, "lan")
old = [str(m) for m in samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["fabricIdMark"])[0]["fabricIdMark"]
       if str(m).startswith("guest=")][0]
samdb.modify_ldif(f"dn: {dn}\nchangetype: modify\ndelete: fabricIdMark\nfabricIdMark: {old}\n-\n"
                  "add: fabricIdMark\nfabricIdMark: guest=1949999\n")
print("filled")
"""
check("(the guest range brought to its last id)", "filled" in dc("python3", "-", stdin=FILL).stdout)
last_guest = mk_kind("gst2", "guest")
try:
    mk_kind("gst3", "guest")
    why = ""
except ValidationError as e:
    why = str(e)
check("a range's last id is taken, then the range is refused as full, naming it; other ranges go on",
      last_guest["uidNumber"] == 1949999 and "guest range 1900001-1949999" in why and "full" in why
      and 1100001 <= mk("after")["uidNumber"] <= 1899999, (last_guest, why))
from fabriclib.federation.next_id_block import next_id_block  # noqa: E402
check("the next site's block follows the domain's: site 2's after the root's (2000000-2999999)",
      next_id_block(v, {"sites": {}}, container=DC) == "2000000-2999999", next_id_block(v, {"sites": {}}, container=DC))
try:
    next_id_block(v, {"sites": {"s999": {"id_range": "999000000-999999999"}}}, container=DC)
    why = ""
except ValidationError as e:
    why = str(e)
check("refused: a 1000th site's block (ids stay below 1000000000; no setting raises it)",
      "999 sites" in why, why)

# a read-only DC joining with fabric's image (its join path), and NTLM at it for an account it does not cache:
# forwarded to the writable DC while it is up (the Q6 follow-up S1 owes: PEAP at an RODC site relies on it); with the
# writable DC down, cached accounts only, and no writes (manual 1.9.8.3)
RODC, RODC_IP = "sambatest-rodc", "10.254.30.12"
rw = os.path.join(W, "rodc")
for sub in ("data", "secrets"):
    os.makedirs(os.path.join(rw, sub), mode=0o700)
with open(os.path.join(rw, "secrets", "join.auth"), "w") as f:
    f.write(f"username=Administrator\npassword={admin_pw}\ndomain=AD\n")
os.chmod(os.path.join(rw, "secrets", "join.auth"), 0o600)
renv = {**compose["environment"], "HOST_NAME": "rodc1", "HOST_IP": RODC_IP, "INTERFACES": f"127.0.0.1 {RODC_IP}",
        "JOIN_ROLE": "RODC", "JOIN_SERVER": "dc1.ad.lan.test"}
rrun = ["docker", "run", "-d", "--name", RODC, "--hostname", "rodc1", "--network", NET, "--ip", RODC_IP,
        "--dns", IP, "--read-only", "--memory", compose["mem_limit"], "--cap-drop", "ALL"]
rrun += [x for c in compose["cap_add"] for x in ("--cap-add", c)]
rrun += [x for o in compose["security_opt"] for x in ("--security-opt", o)]
rrun += [x for t in compose["tmpfs"] for x in ("--tmpfs", t)]
rrun += [x for k, val in renv.items() for x in ("-e", f"{k}={val}")]
rrun += ["-v", f"{rw}/data:/data", "-v", f"{rw}/secrets:/run/secrets:ro", "-v", f"{W}/samba/tls:/tls:ro",
         "--health-cmd", shlex.join(compose["healthcheck"]["test"][1:]), "--health-interval", "10s",
         "--health-start-period", "180s", IMAGE]
sh(rrun)
rhealth = ""
for _ in range(60):
    rhealth = sh(["docker", "inspect", "-f", "{{.State.Health.Status}}", RODC], ok=False).stdout.strip()
    if rhealth in ("healthy", ""):
        break
    sh("sleep 5")
rlog = sh(["docker", "logs", RODC], ok=False)
check("an RODC joins with fabric's image (hardened like the DC) and turns healthy",
      rhealth == "healthy" and "joined" in rlog.stdout, (rlog.stdout + rlog.stderr)[-600:])
rep = sh(["docker", "exec", RODC, "ldbsearch", "-H", "/data/private/sam.ldb", "-b", f"OU=lan,OU=sites,{BASE}",
          "-s", "base", "dn"], ok=False).stdout
check("the domain, its layout and fabric's schema replicated to the RODC", f"OU=lan,OU=sites,{BASE}" in rep)


def ntlm_at_rodc(user, password):
    """An NTLM-only sign-in (Kerberos off) at the RODC over LDAP: its search of the base succeeds or fails."""
    auth = os.path.join(W, f"{user}-ntlm.auth")
    with open(auth, "w") as f:
        f.write(f"username={user}\npassword={password}\ndomain=AD\n")
    os.chmod(auth, 0o600)
    res = sh(["docker", "run", "--rm", "--network", NET, "-v", f"{auth}:/auth:ro", "--entrypoint", "ldbsearch", IMAGE,
              "-H", f"ldap://{RODC_IP}", "-A", "/auth", "--use-kerberos=off", "-b", BASE, "-s", "base", "dn"],
             ok=False)
    return res.returncode == 0 and BASE in res.stdout


check("NTLM at the RODC for an account it does not cache is forwarded to the writable DC (Q6 follow-up)",
      ntlm_at_rodc("labadmin", lab_pw))
cached_pw = random_password(20)
dc("samba-tool", "user", "create", "cachy", cached_pw, "--userou=OU=people,OU=lab,OU=lan,OU=sites", "-s", "/data/etc/smb.conf")
dc("samba-tool", "group", "addmembers", "Allowed RODC Password Replication Group", "cachy", "-s", "/data/etc/smb.conf")
pre = sh(["docker", "exec", RODC, "samba-tool", "rodc", "preload", "cachy", "-s", "/data/etc/smb.conf",
          "--server=dc1.ad.lan.test"], ok=False)
check("a site person's password is preloaded at the RODC", pre.returncode == 0, pre.stderr[-300:])
sh(["docker", "stop", DC])
check("with the writable DC down: a cached person signs in at the RODC", ntlm_at_rodc("cachy", cached_pw))
check("with the writable DC down: refused, the Administrator (never cached)", not ntlm_at_rodc("Administrator",
                                                                                               admin_pw))
check("with the writable DC down: refused, a person the RODC does not cache", not ntlm_at_rodc("labadmin", lab_pw))
with open(os.path.join(W, "op.ldif"), "w") as f:
    f.write(f"dn: CN=cachy,OU=people,OU=lab,OU=lan,OU=sites,{BASE}\nchangetype: modify\nreplace: description\n"
            "description: written at the RODC\n")
wr = sh(["docker", "run", "--rm", "--network", NET, "-v", f"{W}/cachy-ntlm.auth:/auth:ro", "-v",
         f"{W}/op.ldif:/op.ldif:ro", "--entrypoint", "ldbmodify", IMAGE, "-H", f"ldap://{RODC_IP}", "-A", "/auth",
         "--use-kerberos=off", "/op.ldif"], ok=False)
check("refused: a write at the RODC", "successfully" not in wr.stdout + wr.stderr, wr.stdout[-200:])
rinfo = json.loads(sh(["docker", "inspect", RODC]).stdout)[0]["HostConfig"]
check("the RODC is hardened like the DC (the six capabilities, read-only, a limit)",
      len(rinfo["CapAdd"]) == 6 and rinfo["ReadonlyRootfs"] and rinfo["Memory"] > 0)
print("RODC memory: " + sh(["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", RODC], ok=False).stdout.strip())

if not os.environ.get("SAMBA_TEST_KEEP"):        # keep the containers to look into a failure
    cleanup()
print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
