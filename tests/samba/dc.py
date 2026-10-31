"""The `samba` suite, real containers (manual 1.6.5.13, S1.3): a DC from fabric's image, run as the rendered compose
file runs it (on a private test network instead of the host's: WSL is shared with other environments), its files
written by the real deploy_samba, the domain converged by the real converge_domain — twice, the second changing
nothing — and the refusals: what a Directory Administrator may not touch, a password the policy refuses, a wrong
password.
    sudo python3 tests/samba/dc.py
"""
import base64
import contextlib
import datetime
import functools
import io
import json
import os
import shlex
import shutil
import string
import subprocess
import sys
import time

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.join(REPO, "tests", "common")]
import test_run as testrun  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.breakglass.break_glass_password import break_glass_password  # noqa: E402
from fabriclib.breakglass.constants import SAFE_SPECIALS  # noqa: E402
from fabriclib.breakglass.ensure_enterprise_admin import ensure_enterprise_admin  # noqa: E402
from fabriclib.breakglass.reset_break_glass import reset_break_glass  # noqa: E402
from fabriclib.breakglass import run_admin_command as m_admin  # noqa: E402
from fabriclib.breakglass.run_admin_command import run_admin_command  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.directory.ensure_admin import ensure_admin  # noqa: E402
from fabriclib.directory.run_op import run_op  # noqa: E402
from fabriclib.federation.network_conflicts import network_conflicts  # noqa: E402
from fabriclib.federation.read_address_plan import read_address_plan  # noqa: E402
from fabriclib.radius.windows_lan_profile import windows_lan_profile  # noqa: E402
from fabriclib.samba.allow_rodc_cache import allow_rodc_cache  # noqa: E402
from fabriclib.samba.check_tier_policies import check_tier_policies  # noqa: E402
from fabriclib.samba.converge_domain import converge_domain  # noqa: E402
from fabriclib.samba.deploy_samba import deploy_samba  # noqa: E402
from fabriclib.samba.tier_policy_defaults import tier_policy_defaults  # noqa: E402
from fabriclib.samba.write_bind_dlz import write_bind_dlz  # noqa: E402
from fabriclib.secrets.random_password import random_password  # noqa: E402

W = os.path.join(os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests"), "samba")
NET, SUBNET, IP = testrun.name("sambatest_net"), f"{testrun.PREFIX}.30.0/24", f"{testrun.PREFIX}.30.10"
# BIND shares the DC's address, as both share the host's on an install (the AD zone sends updates to the DC's name)
BIND_IP = IP
DC, BIND = testrun.name("sambatest-dc"), testrun.name("sambatest-bind")       # per run (manual 3.1.2.6)
IMAGE, BIND_IMAGE = "fabric/samba:" + testrun.name("test"), "fabric/bind9:" + testrun.name("samba-test")
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
    testrun.remove("container", DC, BIND, testrun.name("sambatest-rodc"))     # this run's only
    testrun.remove("network", NET, testrun.name("sambatest_gw"))


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
    domain="lan.test", hostname="pi-host", dc_name="dc-0001", host_ip=IP, lan_cidr=SUBNET, lan_gateway=f"{testrun.PREFIX}.30.1",
    site_name="lan",
    ad_domain="ad.lan.test", ad_password_policy=POLICY, deploy_base_dir=W,
    ad_ntp_signd_dir=os.path.join(W, "ntp_signd")))     # never the host's own /var/lib/samba
compose = yaml.safe_load(env.get_template("samba/docker-compose.yml.j2").render(**v))["services"]["samba"]
# a stand-in for fabric's Step-CA: the DC's certificate and the root CA the trust GPO carries
pki = os.path.join(W, "stepca", "data", "certs")
sh(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{pki}/root.key", "-out",
    f"{pki}/root_ca.crt", "-days", "2", "-subj", "/CN=Test Root"])
# fabric's secrets for the domain: the Administrator and the DC's service accounts
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
testrun.create_network(NET, SUBNET)
# the container's host name is the host's (the host network gives it the host's): the DC has its own (2.1.6.45)
run = ["docker", "run", "-d", "--name", DC, *testrun.labels(), "--hostname", "pi-host", "--network", NET, "--ip", IP,
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
check("the DC provisions with its own name, unlike its host's (2.1.6.45): DC-0001$, dc-0001.ad.lan.test, no "
      "PI-HOST$", "sAMAccountName: DC-0001$" in dc_obj and "dNSHostName: dc-0001.ad.lan.test" in dc_obj and "PI-HOST" not in dc_obj.upper()
      and compose["environment"]["HOST_NAME"] == "dc-0001", dc_obj)
first = converge_domain(v, os.path.join(W, "federation.yaml"), SECRETS, container=DC)
check("converge: schema, layout, groups, access, AD site, policy and GPOs made", len(first) > 30, first)
again = converge_domain(v, os.path.join(W, "federation.yaml"), SECRETS, container=DC)
check("converge again changes nothing (idempotent)", again == [], again)
check("the AD site renamed from Default-First-Site-Name, the roles' owners follow the DC (2.3.1.19.1)",
      "AD site Default-First-Site-Name renamed lan" in first
      and any(c.startswith("role owner of CN=Schema,") for c in first), first)

# 2.3.1.19.1: a DC whose AD site was renamed before the roles followed (every install before 0.7.0) refused every schema
# addition ("we are not master"); found upgrading the test Pi from 0.6.2. Reproduced: the schema's owner written
# while the site has another name, the site renamed back; the next converge repairs it, and the schema takes additions
STALE = """
import ldb, sys
sys.path.insert(0, "/fabric")
from open_samdb import open_samdb
s, _ = open_samdb("/data/etc/smb.conf")
sites = "CN=Sites," + str(s.get_config_basedn())
s.rename("CN=lan," + sites, "CN=lan-moved," + sites)
s.modify(ldb.Message.from_dict(s, {"dn": str(s.get_schema_basedn()), "fSMORoleOwner": str(s.get_dsServiceName())},
                               ldb.FLAG_MOD_REPLACE))
s.rename("CN=lan-moved," + sites, "CN=lan," + sites)
"""
PROBE = """
import sys
sys.path.insert(0, "/fabric")
from open_samdb import open_samdb
s, _ = open_samdb("/data/etc/smb.conf", schema_updates=True)
schema = str(s.get_schema_basedn())
s.add({"dn": "CN=Fabric-Test-Probe-%s,%s" % (sys.argv[1], schema), "objectClass": ["top", "attributeSchema"],
       "attributeID": "1.2.840.113556.1.8000.2554.99999.%s" % sys.argv[1], "lDAPDisplayName": "fabricTestProbe%s"
       % sys.argv[1], "adminDisplayName": "Fabric-Test-Probe-%s" % sys.argv[1], "attributeSyntax": "2.5.5.12",
       "oMSyntax": "64", "isSingleValued": "TRUE"})
"""
staled = dc("python3", "-", stdin=STALE)
refused = dc("python3", "-", "1", stdin=PROBE)
check("reproduced: a stale schema owner (the site renamed after it was written) refuses a schema addition",
      staled.returncode == 0 and refused.returncode != 0 and "not master" in refused.stderr,
      staled.stderr[-300:] + refused.stderr[-300:])
repaired = converge_domain(v, os.path.join(W, "federation.yaml"), SECRETS, container=DC)
accepted = dc("python3", "-", "2", stdin=PROBE)
check("the next converge names the schema's owner by the DC's current DN, and the schema takes additions again",
      any(c.startswith("role owner of CN=Schema,") for c in repaired) and accepted.returncode == 0,
      (repaired, accepted.stderr[-300:]))
# converge repairs and then adds in one process, where Samba keeps the schema it loaded first
ONE = PROBE.replace('s, _ = open_samdb("/data/etc/smb.conf", schema_updates=True)\n',
                    's, _ = open_samdb("/data/etc/smb.conf", schema_updates=True)\n'
                    'from repair_role_owners import repair_role_owners\nassert repair_role_owners(s)\n')
staled = dc("python3", "-", stdin=STALE)
same = dc("python3", "-", "3", stdin=ONE)
check("...in one process too, as converge runs them: repaired, then the schema takes an addition",
      staled.returncode == 0 and same.returncode == 0, staled.stderr[-300:] + same.stderr[-300:])

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

# S2.2: the DC's record and id range (2.1.6.63, 2.1.6.79), its service accounts, fabric's groups with their gids
info_ = run_op(v, SECRETS, "dc_info", container=DC)
check("the agent signs in as fabric-agent-dc-0001 and reads its DC's record in CN=dcs,CN=fabric,CN=System: dc-0001's "
      "range, 1000000-1999999 (its number's), its site, laid out in ranges, one mark each (2.1.6.46)",
      info_["id_range"] == "1000000-1999999" and info_["site"] == "lan"
      and info_["dn"] == f"CN=dc-0001,CN=dcs,CN=fabric,CN=System,{BASE}"
      and set(info_["id_marks"]) == {"first_admin", "admin", "service", "builtin_group", "group", "person", "guest"},
      info_)
def attr(filter_, name):
    out = dc("ldbsearch", "-H", "/data/private/sam.ldb", filter_, name).stdout.replace("\n ", "")   # LDIF folds
    return [line.split(": ", 1)[1] for line in out.splitlines() if line.startswith(name + ": ")]
check("the organisation's groups carry their fixed gids in dc-0001's built-in range: directory-admins 1040001 in "
      "OU=groups, Domain Users 1040009 (fabric's users)",
      attr("(sAMAccountName=directory-admins)", "gidNumber") == ["1040001"]
      and attr("(sAMAccountName=Domain Users)", "gidNumber") == ["1040009"]
      and attr("(sAMAccountName=directory-admins)", "distinguishedName") == [f"CN=directory-admins,OU=groups,{BASE}"])
DOMAIN_GROUPS = ("dc-hosts", "fabric-managed", "fabric-break-glass", "server-admins", "desktop-admins",
                 "network-admins", "machines-servers", "machines-desktops", "machines-network", "site-lan")
site_gids = [int((attr(f"(sAMAccountName={g})", "gidNumber") or ["0"])[0]) for g in DOMAIN_GROUPS]
check("the domain's groups (1.6.13.3) in OU=groups, with gids from the built-in range past the organisation's hundred",
      all(attr(f"(sAMAccountName={g})", "distinguishedName") == [f"CN={g},OU=groups,{BASE}"] for g in DOMAIN_GROUPS)
      and all(1040101 <= g <= 1049999 for g in site_gids) and len(set(site_gids)) == len(DOMAIN_GROUPS), site_gids)
old_groups = dc("ldbsearch", "-H", "/data/private/sam.ldb", "(|(sAMAccountName=lan-*)(sAMAccountName=fabric-admins)"
                "(sAMAccountName=admins))", "sAMAccountName").stdout
check("negative: none of the old per-site groups (lan-users, lan-admins, the site roles, lan-fabric-machines), "
      "fabric-admins or admins is made", "sAMAccountName:" not in old_groups, old_groups[-300:])
svc_uids = [int((attr(f"(sAMAccountName=fabric-{k}-dc-0001)", "uidNumber") or ["0"])[0])
            for k in ("agent", "keycloak", "radius")]
check("the DC's service accounts take uids from its service range (1020001-1039999), primary gid users, no shell",
      all(1020001 <= u <= 1039999 for u in svc_uids) and len(set(svc_uids)) == 3
      and attr("(sAMAccountName=fabric-agent-dc-0001)", "gidNumber") == ["1040009"]
      and attr("(sAMAccountName=fabric-agent-dc-0001)", "loginShell") == ["/usr/sbin/nologin"], svc_uids)
uac = attr("(sAMAccountName=fabric-agent-dc-0001)", "userAccountControl")
check("the DC's service accounts are fabric-<kind>-dc-0001 in OU=service-accounts (2.1.6.82), passwords never expiring",
      all(attr(f"(sAMAccountName=fabric-{k}-dc-0001)", "distinguishedName")
          == [f"CN=fabric-{k}-dc-0001,OU=service-accounts,{BASE}"] for k in ("agent", "keycloak", "radius"))
      and int(uac[0]) & 0x10000)
priv = os.stat(os.path.join(W, "samba", "data", "state", "winbindd_privileged"))
check("winbind's privileged pipe: FreeRADIUS's group only (root, 0750); its socket in the host folder FreeRADIUS mounts",
      (priv.st_uid, priv.st_gid, priv.st_mode & 0o7777) == (0, int(v["service_users"]["freeradius"]["gid"]), 0o750)
      and os.path.exists(os.path.join(W, "samba", "winbindd", "pipe")),
      (priv.st_uid, priv.st_gid, oct(priv.st_mode)))
signd = os.stat(os.path.join(W, "ntp_signd"))
# covers: setting:ad_ntp_signd_dir +
check("the DC's time-signing socket in the folder the host's chrony reaches (2.1.13.1): root, 0750",
      os.path.exists(os.path.join(W, "ntp_signd", "socket")) and signd.st_uid == 0
      and signd.st_mode & 0o7777 == 0o750, oct(signd.st_mode))
SECRETS["ad_agent_password"] = random_password()
healed = converge_domain(v, os.path.join(W, "federation.yaml"), SECRETS, container=DC)
check("a changed agent password is set by the next convergence (when the old one no longer signs in)",
      healed == ["service account fabric-agent-dc-0001: password set"]
      and run_op(v, SECRETS, "dc_info", container=DC)["dc"] == "dc-0001", healed)
try:
    run_op(v, {**SECRETS, "ad_agent_password": "wrong"}, "dc_info", container=DC)
    check("refused: the agent with a wrong password", False)
except ValidationError as e:
    check("refused: the agent with a wrong password", "refused" in str(e), e)
try:
    run_op(v, SECRETS, "no_such_op", container=DC)
    check("refused: an operation the DC does not know", False)
except ValidationError as e:
    check("refused: an operation the DC does not know", "unknown directory operation" in str(e), e)
try:
    run_op(v, SECRETS, "site_info", container=DC)
    check("negative: the retired operation site_info is gone (dc_info replaced it)", False)
except ValidationError as e:
    check("negative: the retired operation site_info is gone (dc_info replaced it)",
          "unknown directory operation" in str(e), e)
FOLDERS = ("people", "service-accounts", "groups", "machines", "fabric-hosts", "devices", "device-roles", "networks",
           "sudoers")
ous = dc("ldbsearch", "-H", "/data/private/sam.ldb", "-b", BASE, "-s", "one", "(objectClass=organizationalUnit)",
         "dn", "description").stdout.replace("\n ", "")
inner = dc("ldbsearch", "-H", "/data/private/sam.ldb", "(objectClass=organizationalUnit)", "dn").stdout
check("the directory's folders, one set for the domain (1.6.13.2), each marked as fabric's; OU=fabric inside "
      "OU=groups; OU=servers, OU=desktops, OU=network inside OU=machines",
      all(f"dn: OU={f},{BASE}" in ous for f in FOLDERS) and ous.count("managed by fabric") == len(FOLDERS)
      and f"dn: OU=fabric,OU=groups,{BASE}" in inner
      and all(f"dn: OU={t},OU=machines,{BASE}" in inner for t in ("servers", "desktops", "network")), ous[-600:])
check("negative: no site OU, no OU=sites, no OU=organisation, no OS-family OU (OU=linux, OU=windows)",
      not any(f"OU={x}," in inner for x in ("sites", "organisation", "lan", "linux", "windows")), inner[-600:])
state_dn = dc("ldbsearch", "-H", "/data/private/sam.ldb", "-b", f"CN=fabric,CN=System,{BASE}", "dn").stdout
check("fabric's state beside AD's: CN=fabric,CN=System with CN=dcs and dc-0001's record (2.1.6.79)",
      f"dn: CN=dc-0001,CN=dcs,CN=fabric,CN=System,{BASE}" in state_dn, state_dn[-400:])
redir_pw = random_password(20)
dc("samba-tool", "user", "create", "redir", redir_pw, "-s", "/data/etc/smb.conf")
dc("samba-tool", "computer", "create", "REDIRPC", "-s", "/data/etc/smb.conf")
check("AD's default containers point at the folders: a user made with no OU lands in OU=people, a computer in "
      "OU=machines (what Windows' own tools make lands in fabric's folders)",
      attr("(sAMAccountName=redir)", "distinguishedName") == [f"CN=redir,OU=people,{BASE}"]
      and attr("(sAMAccountName=REDIRPC$)", "distinguishedName") == [f"CN=REDIRPC,OU=machines,{BASE}"],
      (attr("(sAMAccountName=redir)", "distinguishedName"), attr("(sAMAccountName=REDIRPC$)", "distinguishedName")))
dc("samba-tool", "user", "delete", "redir", "-s", "/data/etc/smb.conf")
dc("samba-tool", "computer", "delete", "REDIRPC", "-s", "/data/etc/smb.conf")
check("the directory is consistent (dbcheck)", "(0 errors)" in dc("samba-tool", "dbcheck", "-s", "/data/etc/smb.conf",
                                                                  "--cross-ncs").stdout)
policy = dc("samba-tool", "domain", "passwordsettings", "show", "-s", "/data/etc/smb.conf").stdout
# covers: setting:ad_password_policy +
check("the admin's password policy is the domain's",
      "Minimum password length: 14" in policy and "Password complexity: on" in policy
      and "Account lockout threshold (attempts): 5" in policy, policy)
gpos = dc("samba-tool", "gpo", "listall", "-H", "/data/private/sam.ldb", "-s", "/data/etc/smb.conf").stdout
check("the trust GPO exists, and no log-on GPO (the per-OU log-on policies are retired in D1, 2.3.6.17)",
      "fabric: trust in fabric's root CA" in gpos and "log-on" not in gpos, gpos)
files = dc("find", "/data/state/sysvol", "-name", "Registry.pol", "-o", "-name", "GptTmpl.inf").stdout
check("its file is in SYSVOL (Registry.pol); the only log-on rights fabric writes are the grants' (the fallback, fabric: access none, 1.6.13.4)",
      "Registry.pol" in files and "fabric: access none" in gpos and len([x for x in files.splitlines() if x.endswith("GptTmpl.inf")
                                           and "31B2F340" not in x and "6AC1786C" not in x]) >= 1, files)
rules = dc("ldbsearch", "-H", "/data/private/sam.ldb", "(objectClass=sudoRole)", "cn").stdout
check("negative: convergence writes no sudo rule but the shipped grants' (the site's default rule is retired, 2.1.6.80)",
      sorted(x[4:] for x in rules.splitlines() if x.startswith("cn: ")) == ["grant-desktop-administrators",
                                                                     "grant-network-administrators",
                                                                     "grant-server-administrators"], rules[-300:])


def members(group):
    """The member DNs' first RDN values of a group (lower case)."""
    out = dc("ldbsearch", "-H", "/data/private/sam.ldb", f"(sAMAccountName={group})", "member").stdout
    return {line.split(":", 1)[1].strip().split(",")[0][3:].lower() for line in out.splitlines()
            if line.startswith("member:")}


check("no group is nested in another: who may do what comes from grants (D3)",
      all(not members(g) for g in ("directory-admins", "server-admins", "desktop-admins", "network-admins")),
      {g: members(g) for g in ("directory-admins", "server-admins")})
check("and the next converge changes nothing", converge_domain(v, os.path.join(W, "federation.yaml"), SECRETS,
                                                               container=DC) == [])

# BIND serves the AD zone from the DC's database through DLZ (manual 1.6.5.6, Q2): fabric's BIND image with the
# files write_bind_dlz makes, mounted as the rendered compose file mounts them; a minimal named.conf around them
check("before the domain exists BIND's DLZ files load nothing", "not provisioned" in open(
    os.path.join(W, "samba", "bind", "dlz.conf")).read())
check("once provisioned, write_bind_dlz turns DLZ on (BIND must restart)", write_bind_dlz(v) is True)
check("and again changes nothing", write_bind_dlz(v) is False)
bind_build = sh(["docker", "build", "-q", "-t", BIND_IMAGE, "--build-arg", f"BASE_IMAGE={DEBIAN}",
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
            f"ns IN A {testrun.PREFIX}.30.10\nweb IN A {testrun.PREFIX}.30.20\n")
for name in os.listdir(etc_bind):
    os.chmod(os.path.join(etc_bind, name), 0o644)
os.chmod(etc_bind, 0o755)
bind_compose = yaml.safe_load(env.get_template("bind9/docker-compose.yml.j2").render(**v))["services"]["bind9"]
samba_mounts = [m for m in bind_compose["volumes"]
                if m.split(":")[1] in ("/etc/bind-samba", "/data/bind-dns", "/etc/samba")]
sh(["docker", "run", "-d", "--name", BIND, *testrun.labels(), "--network", f"container:{DC}", "--user", "600:600", "--read-only",
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--memory", "128m",
    "--tmpfs", "/run/named:uid=600,gid=600,mode=0755,size=4m", "--tmpfs", "/tmp:size=8m",
    "--tmpfs", "/var/cache/bind:uid=600,gid=600,size=8m"]
   + [x for t in bind_compose["tmpfs"] if t.startswith("/var/tmp") for x in ("--tmpfs", t)]
   + [x for m in samba_mounts for x in ("-v", m)] + ["-v", f"{etc_bind}:/etc/bind:ro", BIND_IMAGE])
sh("sleep 8")


def client(*args):
    return sh(["docker", "run", "--rm", "--network", NET, "--entrypoint", args[0], CLIENT, *args[1:]], ok=False)


def unsigned_update(zone):
    """An nsupdate with no key: BIND must refuse it in every zone."""
    with open(os.path.join(W, "upd"), "w") as f:
        f.write(f"server {BIND_IP}\nzone {zone}\nupdate add evil.{zone} 60 A {testrun.PREFIX}.30.66\nsend\n")
    return sh(["docker", "run", "--rm", "--network", NET, "-v", f"{W}/upd:/upd:ro", "--entrypoint", "nsupdate",
               CLIENT, "/upd"], ok=False)


srv = client("dig", "+short", f"@{BIND_IP}", "SRV", "_ldap._tcp.ad.lan.test").stdout
check("BIND answers the AD zone from the DC's database (DLZ)", "389 dc-0001.ad.lan.test." in srv,
      sh(["docker", "logs", BIND], ok=False).stderr[-600:])
check("and fabric's own zone, unchanged", client("dig", "+short", f"@{BIND_IP}", "A", "web.lan.test").stdout.strip()
      == f"{testrun.PREFIX}.30.20")
upd = dc("samba_dnsupdate", "-s", "/data/etc/smb.conf", "--all-names")
check("the DC's signed (GSS-TSIG) updates are accepted through BIND",
      upd.returncode == 0 and "Failed update" not in upd.stdout + upd.stderr, (upd.stdout + upd.stderr)[-400:])
cmd = dc("testparm", "-s", "--parameter-name=dns update command", "/data/etc/smb.conf").stdout.strip()
pinned = dc("sh", "-c", f"{cmd} -s /data/etc/smb.conf --all-names")
a_rec = client("dig", "+short", f"@{BIND_IP}", "A", "dc-0001.ad.lan.test").stdout.split()
check("the DC's own DNS updates name its LAN address only, never fabric_net's gateway it also listens on (2.1.2.15)",
      f"--current-ip={IP}" in cmd and pinned.returncode == 0 and a_rec == [IP], (cmd, a_rec, pinned.stderr[-300:]))
evil = unsigned_update("ad.lan.test")
check("refused: an unsigned update to the AD zone", "REFUSED" in evil.stdout + evil.stderr, evil.stderr[-200:])
evil = unsigned_update("lan.test")
check("refused: an unsigned update to fabric's zone", "REFUSED" in evil.stdout + evil.stderr, evil.stderr[-200:])
bind_info = json.loads(sh(["docker", "inspect", BIND]).stdout)[0]
check("BIND still runs as its own user with no capabilities", bind_info["Config"]["User"] == "600:600"
      and not bind_info["HostConfig"]["CapAdd"] and bind_info["State"]["Running"])

# a second site and its DC (dc-0002), prepared as a parent prepares a join (manual 1.9.8.4): the DC's record and
# range, the site's group, the DC's service accounts; the folders are the domain's, so nothing else is made
LAB_NETS = [{"name": "lan", "cidr": "10.77.0.0/24", "kind": "lan", "vlan": None, "notes": "", "allow_overlap": ""},
            {"name": "iot", "cidr": "10.78.0.0/24", "kind": "dhcp", "vlan": 21, "notes": "cameras", "allow_overlap": ""}]
lab = {"site": "lab", "dc": "dc-0002", "dc_type": "writable", "root": False, "parent": "lan", "password_policy": POLICY,
       "networks": LAB_NETS, "root_ca_pem": open(f"{pki}/root_ca.crt").read(), "groups": [],
       "accounts": {f"fabric-{k}-dc-0002": random_password() for k in ("agent", "keycloak", "radius")}, "radius_gid": 610,
       "lan_profile": windows_lan_profile("peap", "radius.lab.lan.test", "aa " * 19 + "aa")}
res = dc("python3", "/fabric/converge.py", stdin=json.dumps(lab))
check("a second site's DC: its record, the site's group site-lab and the DC's accounts",
      res.returncode == 0 and "group site-lab created" in res.stdout and "DC record dc-0002 created" in res.stdout
      and attr("(sAMAccountName=fabric-agent-dc-0002)", "distinguishedName")
      == [f"CN=fabric-agent-dc-0002,OU=service-accounts,{BASE}"], res.stderr[-300:] or res.stdout[-300:])
lab_v = {**v, "site_name": "lab", "dc_name": "dc-0002"}
lab_sec = {**SECRETS, "ad_agent_password": lab["accounts"]["fabric-agent-dc-0002"]}
lab_info = run_op(lab_v, lab_sec, "dc_info", container=DC)
check("...its range is its number's (2000000-2999999) and its record names its site", lab_info["id_range"]
      == "2000000-2999999" and lab_info["site"] == "lab", lab_info)
sites = json.loads(dc("python3", "/fabric/read_sites.py").stdout or "{}")
check("read_sites: every DC's record with its site and range (what a parent reads at a join)",
      sites.get("dcs") == [{"dc": "dc-0001", "site": "lan", "id_range": "1000000-1999999"},
                           {"dc": "dc-0002", "site": "lab", "id_range": "2000000-2999999"}], sites)
READ_BASELINE = r"""
import json, os, sys
import ldb
from samba.dcerpc import preg
from samba.ndr import ndr_unpack
sys.path.insert(0, "/fabric")
from open_samdb import open_samdb
samdb, lp = open_samdb("/data/etc/smb.conf")
out = {}
link = samdb.search(base="OU=machines,%s" % samdb.domain_dn(), scope=ldb.SCOPE_BASE, attrs=["gPLink"])
for site in ("lan", "lab"):
    g = samdb.search(base="CN=Policies,CN=System," + str(samdb.domain_dn()), scope=ldb.SCOPE_ONELEVEL,
                     expression="(displayName=fabric: %s Windows baseline)" % site,
                     attrs=["cn", "gPCMachineExtensionNames", "versionNumber"])[0]
    folder = os.path.join(lp.get("path", "sysvol"), lp.get("realm").lower(), "Policies", str(g["cn"]), "Machine")
    pol = ndr_unpack(preg.file, open(os.path.join(folder, "Registry.pol"), "rb").read())
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
check("each site's Windows baseline GPO is linked at OU=machines (2.1.6.84): wait for the network at log-on, the "
      "domain's time (NT5DS)",
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
check("the address plan, read as dc-0001's agent, holds every site's networks with VLAN and notes, all in OU=networks",
      [(n["site"], n["name"], n["cidr"], n["vlan"], n["notes"]) for n in plan]
      == [("lab", "lan", "10.77.0.0/24", None, ""), ("lab", "iot", "10.78.0.0/24", 21, "cameras"),
          ("lan", "lan", SUBNET, None, "")]
      and attr("(objectClass=fabricNetwork)", "distinguishedName") != []
      and all(d.endswith(f",OU=networks,{BASE}") for d in attr("(objectClass=fabricNetwork)", "distinguishedName")),
      plan)
clash = network_conflicts([{"name": "new", "cidr": "10.78.0.128/25"}], plan, "lan")
check("a network of this site overlapping another site's is found in the plan",
      clash and clash[0]["other_site"] == "lab" and not clash[0]["allowed"], clash)
lab_less = dc("python3", "/fabric/converge.py", stdin=json.dumps({**lab, "networks": LAB_NETS[:1]}))
check("a network a site no longer has leaves the plan (and its AD subnet); the other site's same-named one stays",
      "network iot removed" in lab_less.stdout and [n["name"] for n in read_address_plan(v, SECRETS, DC)
                                                    if n["site"] == "lab"] == ["lan"]
      and [n["name"] for n in read_address_plan(v, SECRETS, DC) if n["site"] == "lan"] == ["lan"],
      lab_less.stdout[-400:])

# the Directory Administrators' rights (2.1.6.76, 2.1.6.81; manual 1.6.13.2): full control of OU=people,
# OU=service-accounts, OU=machines and OU=groups, never fabric's accounts, the tiers' groups, OU=fabric, the top tier,
# the Domain Controllers OU, OU=fabric-hosts or fabric's state; in AD's own ACLs, so RSAT is held to them too
dir_pw = random_password(20)
made = dc("samba-tool", "user", "create", "diradmin", dir_pw, "--userou=OU=people", "-s", "/data/etc/smb.conf")
dc("samba-tool", "group", "addmembers", "directory-admins", "diradmin", "-s", "/data/etc/smb.conf")
check("a Directory Administrator is created", made.returncode == 0, made.stderr)
user = "dn: CN={0},{1},%s\nobjectClass: user\nsAMAccountName: {0}\n" % BASE


def done(res):
    return "successfully" in res.stdout + res.stderr


def modify(dn, attribute="description", value="x"):
    return f"dn: {dn}\nchangetype: modify\nreplace: {attribute}\n{attribute}: {value}\n"


def reset(dn):
    """An LDIF that sets an account's password (unicodePwd: the quoted password in UTF-16-LE, base64)."""
    return (f"dn: {dn}\nchangetype: modify\nreplace: unicodePwd\nunicodePwd:: "
            + base64.b64encode(f'"Rs-{random_password(20)}"'.encode("utf-16-le")).decode() + "\n")


check("a Directory Administrator adds a person in OU=people",
      done(as_user("diradmin", dir_pw, "ldbadd", user.format("dirmade", "OU=people"))))
check("...a service account of their own in OU=service-accounts",
      done(as_user("diradmin", dir_pw, "ldbadd", user.format("svc-backup", "OU=service-accounts"))))
check("...a machine in OU=machines' servers",
      done(as_user("diradmin", dir_pw, "ldbadd", f"dn: CN=DIRPC1,OU=servers,OU=machines,{BASE}\nobjectClass: computer\n"
                                                 "sAMAccountName: DIRPC1$\nuserAccountControl: 4096\n")))
check("...a group in OU=groups, and puts a person in site-lab",
      done(as_user("diradmin", dir_pw, "ldbadd", f"dn: CN=web-ops,OU=groups,{BASE}\nobjectClass: group\n"
                                                 "sAMAccountName: web-ops\n"))
      and done(as_user("diradmin", dir_pw, "ldbmodify", f"dn: CN=site-lab,OU=groups,{BASE}\nchangetype: modify\n"
                                                        f"add: member\nmember: CN=dirmade,OU=people,{BASE}\n")))
check("...resets a person's password (the control for the refusals below)",
      done(as_user("diradmin", dir_pw, "ldbmodify", reset(f"CN=dirmade,OU=people,{BASE}"))))
check("...and sets GPO options at OU=machines' servers (the GPO link rights, 2.1.6.84)",
      done(as_user("diradmin", dir_pw, "ldbmodify", modify(f"OU=servers,OU=machines,{BASE}", "gPOptions", "0"))))
REFUSED = [
    ("adding a member to directory-admins (a tier's group)",
     f"dn: CN=directory-admins,OU=groups,{BASE}\nchangetype: modify\nadd: member\nmember: CN=dirmade,OU=people,{BASE}\n"),
    ("changing dc-hosts (a tier's group)", modify(f"CN=dc-hosts,OU=groups,{BASE}")),
    ("adding a group to OU=fabric (the grants' computed groups)",
     f"dn: CN=evil,OU=fabric,OU=groups,{BASE}\nobjectClass: group\nsAMAccountName: evil\n"),
    ("changing fabric's own agent account", modify(f"CN=fabric-agent-dc-0001,OU=service-accounts,{BASE}")),
    ("resetting fabric's Keycloak account's password", reset(f"CN=fabric-keycloak-dc-0001,OU=service-accounts,{BASE}")),
    ("changing the domain's Administrator", modify(f"CN=Administrator,CN=Users,{BASE}")),
    ("changing the Domain Controllers OU", modify(f"OU=Domain Controllers,{BASE}")),
    ("adding to OU=fabric-hosts", f"dn: CN=EVILHOST,OU=fabric-hosts,{BASE}\nobjectClass: computer\n"
                                  "sAMAccountName: EVILHOST$\nuserAccountControl: 4096\n"),
    ("changing fabric's state (a DC's record)", modify(f"CN=dc-0001,CN=dcs,CN=fabric,CN=System,{BASE}")),
    ("changing OU=people's permissions (never WD, WO: no holder lifts the denies)",
     modify(f"OU=people,{BASE}", "nTSecurityDescriptor", "O:DAG:DAD:P(A;;GA;;;DA)")),
]
for label, ldif in REFUSED:
    tool = "ldbadd" if "changetype" not in ldif else "ldbmodify"
    check(f"refused: a Directory Administrator {label}", not done(as_user("diradmin", dir_pw, tool, ldif)))
# the top tier (2.1.6.68, 2.1.6.69): setup makes fabric-admin, the Enterprise Admin, with a generated password at the
# root's DC as root (ensure_enterprise_admin), alone in Enterprise, Schema and Domain Admins, never a Directory
# Administrator; the Directory Administrators' rights never reach it
generated = [break_glass_password() for _ in range(300)]
check("the break-glass password: 24 characters of letters, digits and only - _ . , : + = @ ^ ~, each class at least "
      "once, never the same twice (2.1.6.69)",
      all(len(g) == 24 and set(g) <= set(string.ascii_letters + string.digits + SAFE_SPECIALS)
          and any(c.isupper() for c in g) and any(c.islower() for c in g) and any(c.isdigit() for c in g)
          and any(c in SAFE_SPECIALS for c in g) for g in generated) and len(set(generated)) == 300)
try:
    break_glass_password(13)
    why = ""
except ValueError as e:
    why = str(e)
check("negative: a break-glass password under 14 characters is refused", "at least 14" in why, why)
try:
    ensure_enterprise_admin(v, container=DC, password="Ab1-short")
    why = ""
except ValidationError as e:
    why = str(e)
check("negative: fabric-admin with a password the domain's policy refuses: refused with the DC's reason, nothing made",
      "could not be made" in why and attr("(sAMAccountName=fabric-admin)", "dn") == [], why)
made_ea = ensure_enterprise_admin(v, container=DC)
top_pw = made_ea["password"]
top_groups = attr("(sAMAccountName=fabric-admin)", "memberOf")
check("ensure_enterprise_admin: fabric-admin made in OU=people with dc-0001's first id, a member of Enterprise, "
      "Schema and Domain Admins only (not directory-admins, no site), its generated password returned once",
      made_ea["created"] and top_pw and len(top_pw) == 24
      and attr("(sAMAccountName=fabric-admin)", "dn") == [f"CN=fabric-admin,OU=people,{BASE}"]
      and attr("(sAMAccountName=fabric-admin)", "uidNumber") == ["1000000"]
      and all(any(g.startswith(f"CN={n},") for g in top_groups)
              for n in ("Enterprise Admins", "Schema Admins", "Domain Admins"))
      and not any("directory-admins" in g or "CN=site-" in g for g in top_groups), (made_ea["changed"], top_groups))
again_ea = ensure_enterprise_admin(v, container=DC)
check("...a second run changes nothing and keeps its password (none returned)",
      not again_ea["created"] and again_ea["password"] is None and again_ea["changed"] == [], again_ea)
# the generated password signs in through every layer that receives it (2.1.6.69): LDAP, Kerberos, NTLM over SMB
ldap_in = as_user("fabric-admin", top_pw, "ldbsearch")
krb_in = dc("bash", "-c", "printf '[libdefaults]\\n default_realm = AD.LAN.TEST\\n[realms]\\n AD.LAN.TEST = { kdc = "
            "127.0.0.1 }\\n' > /tmp/ea-krb5.conf && export KRB5_CONFIG=/tmp/ea-krb5.conf KRB5CCNAME=FILE:/tmp/cc-ea "
            "&& kinit fabric-admin >/dev/null && klist && kdestroy", stdin=top_pw + "\n")
smb_in = sh(["docker", "run", "--rm", "--network", NET, "-v", f"{W}/fabric-admin.auth:/auth:ro", "--entrypoint",
             "smbclient", IMAGE, f"//{IP}/sysvol", "-A", "/auth", "-c",
             "ls ad.lan.test/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/*"], ok=False)
check("its generated password signs in over LDAP", ldap_in.returncode == 0 and BASE in ldap_in.stdout,
      (ldap_in.stdout + ldap_in.stderr)[-300:])
check("...by Kerberos (kinit)", krb_in.returncode == 0 and "fabric-admin@AD.LAN.TEST" in krb_in.stdout,
      (krb_in.stdout + krb_in.stderr)[-300:])
check("...and by NTLM (SMB, reading SYSVOL)", smb_in.returncode == 0 and "GPT.INI" in smb_in.stdout.upper(),
      (smb_in.stdout + smb_in.stderr)[-300:])
check("refused: a Directory Administrator changing fabric-admin in OU=people",
      not done(as_user("diradmin", dir_pw, "ldbmodify", modify(f"CN=fabric-admin,OU=people,{BASE}"))))
check("refused: a Directory Administrator resetting fabric-admin's password",
      not done(as_user("diradmin", dir_pw, "ldbmodify", reset(f"CN=fabric-admin,OU=people,{BASE}"))))
check("...while the top tier itself (fabric-admin) changes a tier's group: the denies are the Directory "
      "Administrators' only",
      done(as_user("fabric-admin", top_pw, "ldbmodify", modify(f"CN=dc-hosts,OU=groups,{BASE}"))))
# the first Directory Administrator (2.1.6.69, 2.1.6.93): a person in OU=people and directory-admins, with their first
# and last names and
# e-mail, their own password, never in AD's top tier
first_pw = "Da-" + random_password(20)
state, _ = ensure_admin(v, SECRETS, "pat.admin", "pat@lan.test", lambda: first_pw, container=DC,
                        first="Pat Q.", last="Example")
pat_groups = attr("(sAMAccountName=pat.admin)", "memberOf")
check("ensure_admin: the first Directory Administrator in OU=people and directory-admins (and the site's group), "
      "named and mailed as given, an admin's id, outside AD's top tier",
      state == "created" and attr("(sAMAccountName=pat.admin)", "dn") == [f"CN=pat.admin,OU=people,{BASE}"]
      and any(g.startswith("CN=directory-admins,") for g in pat_groups)
      and not any(g.startswith(("CN=Domain Admins,", "CN=Enterprise Admins,", "CN=Schema Admins,")) for g in pat_groups)
      and attr("(sAMAccountName=pat.admin)", "givenName") == ["Pat Q."]
      and attr("(sAMAccountName=pat.admin)", "sn") == ["Example"]
      and attr("(sAMAccountName=pat.admin)", "mail") == ["pat@lan.test"]
      and 1000001 <= int((attr("(sAMAccountName=pat.admin)", "uidNumber") or ["0"])[0]) <= 1019999, pat_groups)
check("...signing in with the password they chose", as_user("pat.admin", first_pw, "ldbsearch").returncode == 0)
state2, _ = ensure_admin(v, SECRETS, "pat.admin", "pat@lan.test", lambda: "never-asked", container=DC)
check("...a second run finds them and keeps their password", state2 == "exists"
      and as_user("pat.admin", first_pw, "ldbsearch").returncode == 0, state2)
# the tiers' own password policies (2.1.6.69, 2.1.6.71): fine-grained password policies beside the domain's, written at
# the root's convergence; fabric-admin's on its own account (3, then a lockout that ends by itself), the Directory
# Administrators' on directory-admins; the domain's default stays everyone else's
TIERS = tier_policy_defaults(POLICY)
# covers: setting:ad_tier_password_policies +
tiered = converge_domain({**v, "ad_tier_password_policies": TIERS}, os.path.join(W, "federation.yaml"), SECRETS,
                         container=DC)
PSO_BASE = f"CN=Password Settings Container,CN=System,{BASE}"


def pso(name, attr_):
    out = dc("ldbsearch", "-H", "/data/private/sam.ldb", "-b", f"CN={name},{PSO_BASE}", "-s", "base",
             attr_).stdout.replace("\n ", "")
    return [line.split(": ", 1)[1] for line in out.splitlines() if line.startswith(attr_ + ": ")]


check("the tiers' policies: fabric-enterprise-admin (precedence 1) on fabric-admin, 3 failed sign-ins then 15 "
      "minutes (window 15); fabric-directory-admins (precedence 2) on directory-admins, a copy of the default",
      pso("fabric-enterprise-admin", "msDS-LockoutThreshold") == ["3"]
      and pso("fabric-enterprise-admin", "msDS-LockoutDuration") == [str(-15 * 60 * 10 ** 7)]
      and pso("fabric-enterprise-admin", "msDS-LockoutObservationWindow") == [str(-15 * 60 * 10 ** 7)]
      and pso("fabric-enterprise-admin", "msDS-PasswordSettingsPrecedence") == ["1"]
      and pso("fabric-enterprise-admin", "msDS-PSOAppliesTo") == [f"CN=fabric-admin,OU=people,{BASE}"]
      and pso("fabric-directory-admins", "msDS-PSOAppliesTo") == [f"CN=directory-admins,OU=groups,{BASE}"]
      and pso("fabric-directory-admins", "msDS-LockoutThreshold") == [str(POLICY["lockout_threshold"])]
      and pso("fabric-directory-admins", "msDS-MinimumPasswordLength") == [str(POLICY["minimum_length"])], tiered)
resultant = dc("ldbsearch", "-H", "/data/private/sam.ldb", "(|(sAMAccountName=fabric-admin)(sAMAccountName=pat.admin)"
               "(sAMAccountName=diradmin))", "msDS-ResultantPSO").stdout.replace("\n ", "")
check("...AD resolves them: fabric-admin's own, a Directory Administrator's (pat.admin, diradmin) theirs",
      f"msDS-ResultantPSO: CN=fabric-enterprise-admin,{PSO_BASE}" in resultant
      and resultant.count(f"msDS-ResultantPSO: CN=fabric-directory-admins,{PSO_BASE}") == 2, resultant[-600:])
check("...a second convergence changes nothing in them",
      not any("password policy fabric-" in c for c in converge_domain(
          {**v, "ad_tier_password_policies": TIERS}, os.path.join(W, "federation.yaml"), SECRETS, container=DC)))
# a lockout that ends by itself: 3 wrong passwords lock fabric-admin (its right one refused), and after the lockout it
# signs in again with no admin's help; tried with a one-minute policy so the suite waits one minute, not fifteen
quick = {**TIERS, "enterprise_admin": {**TIERS["enterprise_admin"], "lockout_minutes": 1,
                                       "lockout_window_minutes": 1}}
converge_domain({**v, "ad_tier_password_policies": quick}, os.path.join(W, "federation.yaml"), SECRETS, container=DC)
for _ in range(3):
    as_user("fabric-admin", top_pw + "x", "ldbsearch")
locked = as_user("fabric-admin", top_pw, "ldbsearch")
check("fabric-admin: after 3 wrong passwords it is locked: its right password is refused",
      locked.returncode != 0 and BASE not in locked.stdout, locked.stdout[-200:])
time.sleep(70)
unlocked = as_user("fabric-admin", top_pw, "ldbsearch")
check("...and once its lockout is over it signs in again by itself (no admin unlocks break glass)",
      unlocked.returncode == 0 and BASE in unlocked.stdout, (unlocked.stdout + unlocked.stderr)[-300:])
for _ in range(3):
    as_user("pat.admin", first_pw + "x", "ldbsearch")
check("...while a Directory Administrator is not locked after 3 (their policy is the default's copy: "
      f"{POLICY['lockout_threshold']})", as_user("pat.admin", first_pw, "ldbsearch").returncode == 0)
converge_domain({**v, "ad_tier_password_policies": TIERS}, os.path.join(W, "federation.yaml"), SECRETS, container=DC)
for bad, why in (({**TIERS, "enterprise_admin": {**TIERS["enterprise_admin"], "lockout_minutes": 0}}, "unlocks it"),
                 ({"enterprise_admin": TIERS["enterprise_admin"]}, "exactly enterprise_admin and directory_admins"),
                 ({**TIERS, "directory_admins": {**TIERS["directory_admins"], "minimum_length": 99}},
                  "the Directory Administrators: ad_password_policy.minimum_length")):
    try:
        check_tier_policies(bad)
        got = ""
    except ValidationError as e:
        got = str(e)
    # covers: setting:ad_tier_password_policies -
    check(f"refused: a tiers' policy ({why}), saying why", why in got, got)
# reset-break-glass (2.1.6.75): a lost password replaced on the writable DC's host, the account unlocked, the file
# written again to the person's ~/fabric-admin/ (a test home here), audited; refused on a read-only DC's host and with
# the DC not running, nothing changed
for _ in range(3):
    as_user("fabric-admin", top_pw + "x", "ldbsearch")
check("fabric-admin locked again (3 wrong passwords, its 15-minute lockout) before the reset",
      as_user("fabric-admin", top_pw, "ldbsearch").returncode != 0)
GLASS_HOME = os.path.join(W, "glass-home")
GLASS_CONF = os.path.join(W, "glass-config")
shutil.rmtree(GLASS_HOME, ignore_errors=True)
os.makedirs(GLASS_HOME)
os.makedirs(GLASS_CONF, exist_ok=True)
OWNER = ("tester", GLASS_HOME, os.getuid(), os.getgid())
audited = []


def note(*a):
    audited.append(a)


for bad_v, bad_dc, why in (({**v, "ad_dc_type": "rodc", "ad_join_server": "dc-0001.lan.test"}, DC, "read-only"),
                           (v, "fabric-no-such-dc", "could not be reset"),
                           ({**v, "ad_domain": ""}, DC, "no domain")):
    try:
        reset_break_glass({**bad_v, "ad_tier_password_policies": TIERS}, GLASS_CONF, "tester", container=bad_dc,
                          owner=OWNER, audit=note)
        got = ""
    except ValidationError as e:
        got = str(e)
    check(f"refused: reset-break-glass ({why}), saying why; no file, no audit",
          why in got and not os.listdir(GLASS_HOME) and not audited, got)
reset = reset_break_glass({**v, "ad_tier_password_policies": TIERS}, GLASS_CONF, "tester", container=DC, owner=OWNER,
                          audit=note)
glass = open(reset["path"]).read()
new_pw = glass.split("password:", 1)[1].split("\n", 1)[0].strip()
lock_after = dc("ldbsearch", "-H", "/data/private/sam.ldb", "(sAMAccountName=fabric-admin)", "lockoutTime").stdout
check("reset-break-glass: a new generated password (24, each class) in ~/fabric-admin/fabric-admin-password.txt "
      "(0700/0600), the lockout left in force with its end said (about 15 minutes on; 2.1.6.92), audited "
      "BREAK_GLASS_RESET without the password",
      reset["path"] == os.path.join(GLASS_HOME, "fabric-admin", "fabric-admin-password.txt")
      and len(new_pw) == 24 and new_pw != top_pw and not reset["disabled"]
      and reset["changed"] == ["fabric-admin: a new password"] and reset["locked_until"]
      and 0 < (datetime.datetime.strptime(reset["locked_until"], "%Y-%m-%dT%H:%M:%SZ")
               - datetime.datetime.utcnow()).total_seconds() <= 15 * 60 + 5
      and "lockoutTime: 0" not in lock_after and f"locked_until={reset['locked_until']}" in str(audited)
      and os.stat(os.path.dirname(reset["path"])).st_mode & 0o777 == 0o700
      and os.stat(reset["path"]).st_mode & 0o777 == 0o600
      and [a[1] for a in audited] == ["BREAK_GLASS_RESET"] and new_pw not in str(audited)
      and json.load(open(os.path.join(GLASS_CONF, "break-glass.json")))["by"] == "reset", (reset, audited))
check("negative: while the lockout runs, even the new password is refused (the reset never shortens it)",
      as_user("fabric-admin", new_pw, "ldbsearch").returncode != 0)
# the lockout's time run out (here by the system clearing lockoutTime, as AD does when it ends; no waiting 15
# minutes in a suite)
fa_dn = dc("ldbsearch", "-H", "/data/private/sam.ldb", "(sAMAccountName=fabric-admin)", "dn").stdout.split("dn: ", 1)[1]
sh(["docker", "exec", "-i", DC, "ldbmodify", "-H", "/data/private/sam.ldb"], ok=False,
   input=f"dn: {fa_dn.splitlines()[0]}\nchangetype: modify\nreplace: lockoutTime\nlockoutTime: 0\n")
check("...once it has run out, the new password signs in; the old one is refused",
      as_user("fabric-admin", new_pw, "ldbsearch").returncode == 0
      and as_user("fabric-admin", top_pw, "ldbsearch").returncode != 0)
top_pw = new_pw
# the command (`sudo fabricctl admin reset-break-glass`): routes to the reset, says where the file is, never the password
m_admin.reset_break_glass = functools.partial(reset_break_glass, container=DC, owner=OWNER, audit=note)
TV = {**v, "ad_tier_password_policies": TIERS}
with contextlib.redirect_stdout(io.StringIO()) as said:
    code = run_admin_command(TV, ["reset-break-glass"], GLASS_CONF)
glass = open(os.path.join(GLASS_HOME, "fabric-admin", "fabric-admin-password.txt")).read()
new_pw = glass.split("password:", 1)[1].split("\n", 1)[0].strip()
# covers: cli:admin.reset-break-glass +
check("fabricctl admin reset-break-glass: exit 0, the file's path said and not the password; the new one signs in",
      code == 0 and "fabric-admin-password.txt" in said.getvalue() and new_pw not in said.getvalue()
      and new_pw != top_pw and as_user("fabric-admin", new_pw, "ldbsearch").returncode == 0, said.getvalue())
top_pw = new_pw
for args_, tv, want, why in ((["reset-break-glass", "--now"], TV, 2, "usage:"),
                             (["reset-break-glass"], {**TV, "ad_dc_type": "rodc"}, 1, "read-only")):
    with contextlib.redirect_stdout(io.StringIO()) as said:
        code = run_admin_command(tv, args_, GLASS_CONF)
    # covers: cli:admin.reset-break-glass -
    check(f"refused: fabricctl admin {' '.join(args_)} ({why}), exit {want}; the password unchanged",
          code == want and why in said.getvalue()
          and as_user("fabric-admin", top_pw, "ldbsearch").returncode == 0, said.getvalue())
# the agents (2.1.6.82): each DC's agent writes fabric's folders, never OU=service-accounts
check("a DC's agent adds a person in OU=people (the domain's people: any DC's agent, 2.1.6.64)",
      done(as_user("fabric-agent-dc-0001", SECRETS["ad_agent_password"], "ldbadd", user.format("agentmade", "OU=people")))
      and done(as_user("fabric-agent-dc-0002", lab["accounts"]["fabric-agent-dc-0002"], "ldbadd",
                       user.format("agentkid", "OU=people"))))
check("refused: a DC's agent adding to OU=service-accounts",
      not done(as_user("fabric-agent-dc-0001", SECRETS["ad_agent_password"], "ldbadd",
                       user.format("svc2", "OU=service-accounts"))))
check("refused: a DC's agent changing the domain's Administrator",
      not done(as_user("fabric-agent-dc-0002", lab["accounts"]["fabric-agent-dc-0002"], "ldbmodify",
                       modify(f"CN=Administrator,CN=Users,{BASE}"))))
share = sh(["docker", "run", "--rm", "--network", NET, "-v", f"{W}/diradmin.auth:/auth:ro", "--entrypoint",
            "smbclient", IMAGE, f"//{IP}/sysvol", "-A", "/auth", "-c",
            "ls ad.lan.test/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/*"], ok=False)
check("a domain user reads SYSVOL (Group Policy reads it as the machine; found on host-1, S1.7)",
      share.returncode == 0 and "GPT.INI" in share.stdout.upper(), (share.stdout + share.stderr)[-300:])
short = dc("samba-tool", "user", "create", "shorty", "Ab1shortpw", "-s", "/data/etc/smb.conf")
check("refused: a password shorter than the policy's minimum", short.returncode != 0)
wrong = as_user("diradmin", dir_pw + "x", "ldbsearch")
check("refused: a wrong password", wrong.returncode != 0 and BASE not in wrong.stdout, wrong.stdout[-200:])
admin = as_user("Administrator", admin_pw, "ldbsearch")
check("the Administrator signs in with fabric's generated password", admin.returncode == 0 and BASE in admin.stdout,
      admin.stderr)

# S2.4: people, as the DC's agent (manual 1.6.3.4, 1.6.3.9, 1.6.13.2)
def mk(uid, email=None, pw=None, site_v=None, sec=None):
    return run_op(site_v or v, sec or SECRETS, "create_person",
                  {"uid": uid, "first": uid.title(), "last": "Test", "email": email or f"{uid}@lan.test",
                   "password": pw or ("Pw-" + random_password(20)), "gid": 5000, "home_base": "/home",
                   "shell": "/bin/bash"}, container=DC)


alice = mk("alice")
check("a person is created with a uid from the people range of the DC's range (1100001-1899999)",
      1100001 <= alice["uidNumber"] <= 1899999, alice)
check("their POSIX identity: primary gid 5000 (fabric's users), /home/alice, /bin/bash, in their site's site-lan",
      attr("(sAMAccountName=alice)", "gidNumber") == ["5000"]
      and attr("(sAMAccountName=alice)", "unixHomeDirectory") == ["/home/alice"]
      and attr("(sAMAccountName=alice)", "loginShell") == ["/bin/bash"]
      and any(m.startswith("CN=site-lan,") for m in attr("(sAMAccountName=alice)", "memberOf")))
check("they live in OU=people, flat, named by their user name",
      attr("(sAMAccountName=alice)", "distinguishedName") == [f"CN=alice,OU=people,{BASE}"])
bob = mk("bob", site_v=lab_v, sec=lab_sec)
check("a person made by another site's DC: in the same OU=people, a uid from that DC's range, in site-lab",
      attr("(sAMAccountName=bob)", "distinguishedName") == [f"CN=bob,OU=people,{BASE}"]
      and 2100001 <= bob["uidNumber"] <= 2899999
      and any(m.startswith("CN=site-lab,") for m in attr("(sAMAccountName=bob)", "memberOf")), bob)
for label, args in (("the same user name", ("alice", "other@lan.test")), ("the same e-mail address", ("alice2",
                                                                                                    "alice@lan.test"))):
    try:
        mk(*args)
        check(f"refused: {label}", False)
    except ValidationError as e:
        check(f"refused: {label}", "already taken" in str(e), e)
try:
    mk("bob", email="bob2@lan.test")
    check("refused: a user name another site's DC took (people are the domain's)", False)
except ValidationError as e:
    check("refused: a user name another site's DC took (people are the domain's)", "already taken" in str(e), e)
try:
    mk("shortpw", pw="Ab1-short")
    check("refused: a one-time password the policy refuses", False)
except ValidationError as e:
    check("refused: a one-time password the policy refuses", "refused" in str(e), e)
people = run_op(v, SECRETS, "list_people", container=DC)
a = next((u for u in people["users"] if u["uid"] == "alice"), {})
b = next((u for u in people["users"] if u["uid"] == "bob"), {})
check("the People page lists every person in OU=people with their sites (site-<name>), groups, not locked, and no "
      "service account",
      a.get("site") == "lan" and a.get("sites") == ["lan"] and b.get("site") == "lab"
      and "site-lan" in a.get("groups", []) and a.get("locked") is False
      and not any((u["uid"].startswith("fabric-") and u["uid"] != "fabric-admin") or u["uid"] == "svc-backup"
                  for u in people["users"])
      and any(g["name"] == "directory-admins" for g in people["groups"]), (a, b))
check("nothing secret in the list", "password" not in json.dumps(people).lower() and "unicodePwd" not in json.dumps(people))
person = run_op(v, SECRETS, "get_person", {"uid": "alice"}, container=DC)
check("a person's groups for the reset guard", "site-lan" in person["groups"], person)
new_otp = "Rs-" + random_password(20)
run_op(v, SECRETS, "reset_password", {"uid": "alice", "password": new_otp}, container=DC)
check("a reset sets a new one-time password (it must be changed: AD refuses it for a sign-in until then)",
      attr("(sAMAccountName=alice)", "pwdLastSet") == ["0"])
try:
    run_op(v, SECRETS, "reset_password", {"uid": "fabric-agent-dc-0002", "password": new_otp}, container=DC)
    check("refused: resetting a service account's password as if it were a person", False)
except ValidationError as e:
    check("refused: resetting a service account's password as if it were a person",
          "no such entry" in str(e) or "refused" in str(e), e)

# fabricctl people's operations (2.1.6.30, manual 1.6.3.11): disable / enable, groups, remove
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
for label, args in (("a service account is not a person", {"uid": "fabric-agent-dc-0001", "enabled": False}),
                    ("a person who does not exist", {"uid": "nobody", "enabled": False})):
    try:
        run_op(v, SECRETS, "set_person", args, container=DC)
        check(f"refused: {label}", False)
    except ValidationError as e:
        check(f"refused: {label}", "no such entry" in str(e) or "refused" in str(e), e)
added = run_op(v, SECRETS, "add_group_member", {"group": "web-ops", "uid": "dave"}, container=DC)
gone = run_op(v, SECRETS, "remove_group_member", {"group": "web-ops", "uid": "dave"}, container=DC)
twice = run_op(v, SECRETS, "remove_group_member", {"group": "web-ops", "uid": "dave"}, container=DC)
check("groups: in, then out of a group, once", added["added"] and gone["removed"] and twice["removed"] is False
      and "web-ops" not in run_op(v, SECRETS, "get_person", {"uid": "dave"}, container=DC)["groups"])
try:
    run_op(v, SECRETS, "remove_group_member", {"group": "no-such-group", "uid": "dave"}, container=DC)
    check("refused: a group that does not exist", False)
except ValidationError as e:
    check("refused: a group that does not exist", "no such entry" in str(e), e)
try:
    run_op(v, SECRETS, "remove_person", {"uid": "nobody"}, container=DC)
    check("refused: removing a person who does not exist", False)
except ValidationError as e:
    check("refused: removing a person who does not exist", "no such entry" in str(e), e)
run_op(lab_v, lab_sec, "remove_person", {"uid": "dave"}, container=DC)
signin = as_user("dave", dave_pw, "ldbsearch")
check("remove (by another site's DC: people are the domain's): the account is gone and its sign-in refused",
      attr("(sAMAccountName=dave)", "dn") == [] and signin.returncode != 0)
first = alice["uidNumber"]
dc("samba-tool", "user", "delete", "alice", "-s", "/data/etc/smb.conf")
carol = mk("carol")
check("ids are never reused: after alice is deleted, carol gets a higher number", carol["uidNumber"] > first, carol)
# a DC named otherwise than dc-NNNN (an install from before 0.8.0, 2.1.6.86) is refused before anything is written
old = {**lab, "site": "tiny", "dc": "dc1", "networks": [],
       "accounts": {f"fabric-{k}-dc1": random_password() for k in ("agent", "keycloak", "radius")}}
old_run = dc("python3", "/fabric/converge.py", stdin=json.dumps(old))
check("refused: a DC whose name is not dc-NNNN (no range), nothing written: no record, no group, no account",
      old_run.returncode != 0 and "numbered names" in old_run.stderr
      and attr("(sAMAccountName=site-tiny)", "dn") == [] and attr("(sAMAccountName=fabric-agent-dc1)", "dn") == []
      and "CN=dc1," not in dc("ldbsearch", "-H", "/data/private/sam.ldb", "-b", f"CN=dcs,CN=fabric,CN=System,{BASE}",
                              "dn").stdout, (old_run.stdout + old_run.stderr)[-300:])

# 2.1.6.46 (manual 1.6.3.17): each kind of account in its range; a full range taken from the site's other DCs
# (2.1.6.63), then refused, naming it
def mk_kind(uid, kind):
    return run_op(v, SECRETS, "create_person", {"uid": uid, "first": uid.title(), "last": "Test",
                                                "email": f"{uid}@lan.test", "password": "Pw-" + random_password(20),
                                                "gid": 1040009, "home_base": "/home", "shell": "/bin/bash",
                                                "kind": kind}, container=DC)


boss, boss2 = mk_kind("boss", "first_admin"), mk_kind("boss2", "first_admin")
adm, gst = mk_kind("adm", "admin"), mk_kind("gst", "guest")
check("the range's first id is fabric-admin's (above); past it, a first admin takes an admin account's range; admins "
      "and guests their own",
      1000001 <= boss["uidNumber"] <= 1019999 and 1000001 <= boss2["uidNumber"] <= 1019999
      and 1000001 <= adm["uidNumber"] <= 1019999 and 1900001 <= gst["uidNumber"] <= 1949999, (boss, boss2, adm, gst))
try:
    mk_kind("svc", "service")
    why = ""
except ValidationError as e:
    why = str(e)
check("refused: a person in a range that is not a person's (service accounts are fabric's)", "kind" in why, why)
# a second DC of lan (dc-0004): its record in the same site, so dc-0001's full range falls back to it
lan2 = {**lab, "site": "lan", "dc": "dc-0004", "parent": "", "lan_profile": "",
        "networks": [{"name": "lan", "cidr": SUBNET, "kind": "lan", "vlan": None, "notes": "", "allow_overlap": ""}],
        "accounts": {f"fabric-{k}-dc-0004": random_password() for k in ("agent", "keycloak", "radius")}}
lan2_run = dc("python3", "/fabric/converge.py", stdin=json.dumps(lan2))
check("(a second DC of lan, dc-0004, prepared)", lan2_run.returncode == 0, lan2_run.stderr[-300:])
FILL = r"""
import sys
sys.path.insert(0, "/fabric")
import ldb
from open_samdb import open_samdb
import paths
samdb, _ = open_samdb("/data/etc/smb.conf")
dn = paths.dc_record_dn(samdb, sys.argv[1])
old = [str(m) for m in samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["fabricIdMark"])[0]["fabricIdMark"]
       if str(m).startswith("guest=")][0]
samdb.modify_ldif(f"dn: {dn}\nchangetype: modify\ndelete: fabricIdMark\nfabricIdMark: {old}\n-\n"
                  f"add: fabricIdMark\nfabricIdMark: guest={sys.argv[2]}\n")
print("filled")
"""
filled = dc("python3", "-", "dc-0001", "1949999", stdin=FILL)
check("(dc-0001's guest range brought to its last id)", "filled" in filled.stdout, filled.stderr[-400:])
last_guest = mk_kind("gst2", "guest")
from_other = mk_kind("gst3", "guest")
check("a range's last id is taken; then the same range of the site's other DC (dc-0004's 4900001-4949999)",
      last_guest["uidNumber"] == 1949999 and 4900001 <= from_other["uidNumber"] <= 4949999, (last_guest, from_other))
check("negative: never another site's DC (dc-0002, lab) while its own site has one",
      not 2900001 <= from_other["uidNumber"] <= 2949999, from_other)
filled = dc("python3", "-", "dc-0004", "4949999", stdin=FILL)
mk_kind("gst4", "guest")
try:
    mk_kind("gst5", "guest")
    why = ""
except ValidationError as e:
    why = str(e)
check("every DC of the site full: refused, naming the range; other ranges go on",
      "guest range 1900001-1949999 of dc-0001 is full" in why and "other DCs" in why
      and 1100001 <= mk("after")["uidNumber"] <= 1899999, why)

# a read-only DC joining with fabric's image (its join path), and NTLM at it for an account it does not cache:
# forwarded to the writable DC while it is up (the Q6 follow-up S1 owes: PEAP at an RODC site relies on it); with the
# writable DC down, cached accounts only, and no writes (manual 1.9.8.3)
RODC, RODC_IP = testrun.name("sambatest-rodc"), f"{testrun.PREFIX}.30.12"
# lab's read-only DC, dc-0003, prepared at the writable DC as a parent prepares a join (2.1.6.85): its record (a
# read-only DC cannot write it), its accounts and its cache group rodc-cache-dc-0003
rodc_state = {**lab, "dc": "dc-0003", "dc_type": "rodc",
              "accounts": {f"fabric-{k}-dc-0003": random_password() for k in ("agent", "keycloak", "radius")}}
prep = dc("python3", "/fabric/converge.py", stdin=json.dumps(rodc_state))
check("a read-only DC prepared at the writable DC: its record (range 3000000-3999999) and rodc-cache-dc-0003",
      prep.returncode == 0 and "DC record dc-0003 created" in prep.stdout and "group rodc-cache-dc-0003 created" in prep.stdout,
      (prep.stdout + prep.stderr)[-300:])
rw = os.path.join(W, "rodc")
for sub in ("data", "secrets"):
    os.makedirs(os.path.join(rw, sub), mode=0o700)
with open(os.path.join(rw, "secrets", "join.auth"), "w") as f:
    f.write(f"username=Administrator\npassword={admin_pw}\ndomain=AD\n")
os.chmod(os.path.join(rw, "secrets", "join.auth"), 0o600)
# a second address, as fabric_net's gateway is on a host: in its interfaces, never in its DNS records (2.1.2.15)
GW_NET, RODC_GW = testrun.name("sambatest_gw"), f"{testrun.PREFIX}.31.12"
testrun.create_network(GW_NET, f"{testrun.PREFIX}.31.0/24")
renv = {**compose["environment"], "HOST_NAME": "dc-0003", "HOST_IP": RODC_IP,
        "INTERFACES": f"127.0.0.1 {RODC_IP} {RODC_GW}", "JOIN_ROLE": "RODC", "JOIN_SERVER": "dc-0001.ad.lan.test"}
rrun = ["docker", "create", "--name", RODC, *testrun.labels(), "--hostname", "rodc-host", "--network", NET, "--ip", RODC_IP,
        "--dns", IP, "--read-only", "--memory", compose["mem_limit"], "--cap-drop", "ALL"]
rrun += [x for c in compose["cap_add"] for x in ("--cap-add", c)]
rrun += [x for o in compose["security_opt"] for x in ("--security-opt", o)]
rrun += [x for t in compose["tmpfs"] for x in ("--tmpfs", t)]
rrun += [x for k, val in renv.items() for x in ("-e", f"{k}={val}")]
rrun += ["-v", f"{rw}/data:/data", "-v", f"{rw}/secrets:/run/secrets:ro", "-v", f"{W}/samba/tls:/tls:ro",
         "--health-cmd", shlex.join(compose["healthcheck"]["test"][1:]), "--health-interval", "10s",
         "--health-start-period", "180s", IMAGE]
sh(rrun)
sh(["docker", "network", "connect", "--ip", RODC_GW, GW_NET, RODC])
sh(["docker", "start", RODC])
rhealth = ""
for _ in range(60):
    rhealth = sh(["docker", "inspect", "-f", "{{.State.Health.Status}}", RODC], ok=False).stdout.strip()
    if rhealth in ("healthy", ""):
        break
    sh("sleep 5")
rlog = sh(["docker", "logs", RODC], ok=False)
check("an RODC joins with fabric's image (hardened like the DC) and turns healthy",
      rhealth == "healthy" and "joined" in rlog.stdout, (rlog.stdout + rlog.stderr)[-600:])
rep = sh(["docker", "exec", RODC, "ldbsearch", "-H", "/data/private/sam.ldb", "-b", f"OU=people,{BASE}",
          "-s", "base", "dn"], ok=False).stdout
check("the domain, its folders and fabric's schema replicated to the RODC", f"OU=people,{BASE}" in rep)
r_rec = client("dig", "+short", f"@{BIND_IP}", "A", "dc-0003.ad.lan.test").stdout.split()
r_ifs = sh(["docker", "exec", RODC, "testparm", "-s", "--parameter-name=interfaces", "/data/etc/smb.conf"], ok=False).stdout
check("the joined DC's name is registered at its LAN address only, never at the second address it also listens on "
      "(2.1.2.15: a host's fabric_net gateway; 2.3.1.32)", r_rec == [RODC_IP] and RODC_GW in r_ifs, (r_rec, r_ifs))


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
      ntlm_at_rodc("diradmin", dir_pw))
cached_pw = random_password(20)
dc("samba-tool", "user", "create", "cachy", cached_pw, "--userou=OU=people", "-s", "/data/etc/smb.conf")
dc("samba-tool", "group", "addmembers", "Allowed RODC Password Replication Group", "cachy", "-s", "/data/etc/smb.conf")
pre = sh(["docker", "exec", RODC, "samba-tool", "rodc", "preload", "cachy", "-s", "/data/etc/smb.conf",
          "--server=dc-0001.ad.lan.test"], ok=False)
check("a site person's password is preloaded at the RODC", pre.returncode == 0, pre.stderr[-300:])

# the fabric host at a read-only DC's site (decision 2.1.6.52, manual 1.6.11.13): the DC's rodc-cache group on the
# read-only DC's allow list, written at the writable DC with the join account from inside the read-only DC (as setup
# does at the join); the host's account made and placed at the writable DC by the read-only DC's agent; cached at once
rv = {"ad_dc_type": "rodc", "ad_join_server": IP, "dc_name": "dc-0003", "site_name": "lab", "ad_domain": "ad.lan.test",
      "ad_base_dn": BASE}
LAB_CACHE = f"CN=rodc-cache-dc-0003,OU=groups,{BASE}"


def reveal_list():
    out = dc("ldbsearch", "-H", "/data/private/sam.ldb", "-b", f"CN=DC-0003,OU=Domain Controllers,{BASE}", "-s", "base",
             "msDS-RevealOnDemandGroup").stdout.replace("\n ", "")
    return [x.split(": ", 1)[1] for x in out.splitlines() if x.startswith("msDS-RevealOnDemandGroup: ")]


check("the DC's rodc-cache-dc-0003 group exists (prepared with the DC) and is not yet on the RODC's allow "
      "list", "dn: " + LAB_CACHE in dc("ldbsearch", "-H", "/data/private/sam.ldb", "(cn=rodc-cache-dc-0003)", "dn").stdout
      and LAB_CACHE.lower() not in [x.lower() for x in reveal_list()], reveal_list())
said = allow_rodc_cache(rv, container=RODC)
check("allow_rodc_cache: the group put on the read-only DC's allow list at the writable DC (the default entry kept)",
      said and LAB_CACHE.lower() in [x.lower() for x in reveal_list()] and len(reveal_list()) == 2, (said, reveal_list()))
check("...a second run writes nothing", allow_rodc_cache(rv, container=RODC) == "", reveal_list())
check("...nothing to do where the site's DC is writable", allow_rodc_cache({**rv, "ad_dc_type": "writable"}) == "")
try:
    allow_rodc_cache({**rv, "ad_join_server": f"{testrun.PREFIX}.30.99"}, container=RODC)
    why = ""
except ValidationError as e:
    why = str(e)
check("negative: allow_rodc_cache with the writable DC not answering: refused, saying where", f"{testrun.PREFIX}.30.99" in why, why)
rodc_v = {**v, "site_name": "lab", "dc_name": "dc-0003"}
rodc_sec = {**SECRETS, "ad_agent_password": rodc_state["accounts"]["fabric-agent-dc-0003"]}
host_pw = random_password(24)
run_op(rodc_v, rodc_sec, "create_machine",
       {"name": "labhost", "password": host_pw, "managed": False, "in_site": False}, DC, IP)
placed = run_op(rodc_v, rodc_sec, "place_fabric_host", {"name": "LABHOST", "rodc_cache": True}, DC, IP)
host_groups = dc("ldbsearch", "-H", "/data/private/sam.ldb", "(sAMAccountName=LABHOST$)",
                 "memberOf").stdout.replace("\n ", "")
check("the host's account made and placed at the writable DC by the read-only DC's agent: in OU=fabric-hosts, in "
      "fabric-managed, dc-hosts and rodc-cache-dc-0003, in no site's group (1.6.13.6)",
      placed["moved"] and placed["joined"] == ["fabric-managed", "dc-hosts"] and placed["cached"]
      and placed["dn"] == f"CN=LABHOST,OU=fabric-hosts,{BASE}" and LAB_CACHE in host_groups
      and f"CN=dc-hosts,OU=groups,{BASE}" in host_groups and "CN=site-" not in host_groups, (placed, host_groups))
again = run_op(rodc_v, rodc_sec, "place_fabric_host", {"name": "LABHOST", "rodc_cache": True}, DC, IP)
check("...a second placing changes nothing", not (again["moved"] or again["joined"] or again["cached"]), again)
try:
    run_op(rodc_v, rodc_sec, "create_machine", {"name": "labrw", "password": host_pw}, DC, RODC_IP)
    why = ""
except ValidationError as e:
    why = str(e)
check("negative: the same write at the read-only DC is refused (why the account is made at the writable one)",
      why != "" and "labrw" not in dc("ldbsearch", "-H", "/data/private/sam.ldb", "(sAMAccountName=labrw$)",
                                      "dn").stdout, why)
try:
    run_op(rodc_v, rodc_sec, "place_fabric_host", {"name": "LABHOST"}, DC, f"{testrun.PREFIX}.30.99")
    why = ""
except ValidationError as e:
    why = str(e)
check("negative: a writable DC that does not answer: refused, nothing changed", why != "", why)
pre_host = sh(["docker", "exec", RODC, "samba-tool", "rodc", "preload", "LABHOST$", f"--server={IP}", "-s",
               "/data/etc/smb.conf"], ok=False)
check("the read-only DC caches the host's account at once (rodc preload, as the member step asks it, by the writable "
      "DC's address)", pre_host.returncode == 0, (pre_host.stdout + pre_host.stderr)[-400:])
run_op(rodc_v, rodc_sec, "create_machine",
       {"name": "labother", "password": host_pw, "type": "server"}, DC, IP)
pre_other = sh(["docker", "exec", RODC, "samba-tool", "rodc", "preload", "LABOTHER$", f"--server={IP}", "-s",
                "/data/etc/smb.conf"], ok=False)
check("negative: a machine outside rodc-cache-dc-0003 is not cached (the allow list holds the group, not every machine)",
      pre_other.returncode != 0, (pre_other.stdout + pre_other.stderr)[-400:])
sh(["docker", "stop", DC])
check("with the writable DC down: a cached person signs in at the RODC", ntlm_at_rodc("cachy", cached_pw))
check("with the writable DC down: refused, the Administrator (never cached)", not ntlm_at_rodc("Administrator",
                                                                                               admin_pw))
check("with the writable DC down: refused, a person the RODC does not cache", not ntlm_at_rodc("diradmin", dir_pw))
check("with the writable DC down: the fabric host's account, cached, signs in at the RODC (2.1.6.52)",
      ntlm_at_rodc("LABHOST$", host_pw))
with open(os.path.join(W, "op.ldif"), "w") as f:
    f.write(f"dn: CN=cachy,OU=people,{BASE}\nchangetype: modify\nreplace: description\n"
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
