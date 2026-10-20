#!/usr/bin/env python3
"""FreeRADIUS 802.1X (optional, design §6) on fabric's image and templates, against a real domain controller
(manual 1.6.5.17, S3.2) with devices and roles created by fabric's own directory functions and people made the way
fabric makes them:

  EAP-TLS (eapol_test): a certificate linked to an enabled device whose role
  grants network:eap-tls is accepted with the role's VLAN (lowest priority
  wins); refused: a disabled device, an unlinked certificate, a role without
  the permission, a certificate from another CA; unlinking takes effect at
  once. MAB (radclient): a device's MAC with network:mab is accepted with its
  VLAN, without it refused. EAP-TTLS/PAP (people, eapol_test): members of a
  mapped group are accepted with the group's VLAN (lowest priority wins),
  refused: a wrong password, a locked account (the domain's lockout), a
  disabled person, a person still on their one-time password, a person in no
  mapped group, an unknown name, and a password sent outside the tunnel.
  PEAP-MSCHAPv2 (eapol_test), checked by the DC through its winbind: a
  person in a mapped group and a machine in OU=machines (host/<name>, by
  its Domain Computers mapping) accepted on their VLANs; refused: a wrong
  password, a disabled person, a person in no mapped group, a machine
  outside OU=machines (1.6.13.2).
  Refused before any policy: an unknown RADIUS client, a wrong secret, a
  request without Message-Authenticator. The DC down -> refused (fail
  closed), and back -> reconnected. Container hardening.

    sudo python3 tests/freeradius/run.py      (needs Docker, openssl, root)
"""
import os
import re
import shutil
import subprocess
import sys
import time

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests")
W = OUT + "/freeradius"
NET, SUBNET = "radtest_net", "10.254.24.0/24"
DC_IP, RADIUS_IP, SWITCH_IP, STRANGER_IP = "10.254.24.50", "10.254.24.98", "10.254.24.10", "10.254.24.11"
DOMAIN = "lan.j-j.family"                                          # tests/render.py's install
DC = "samba"                    # the product's own name: fabric's directory functions use it
SECRET = "Sw1tchSecretForTests0123456789ab"
FAILED = 0
sys.path[0:0] = [os.path.join(REPO, "src"), REPO, os.path.join(REPO, "tests", "samba")]
from start_dc import start_dc  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.pki.install_cert import install_cert  # noqa: E402
from fabriclib.pki.publish_crl import _gencrl  # noqa: E402
from fabriclib.radius.deploy_freeradius import deploy_freeradius  # noqa: E402
from fabriclib.radius.normalize_radius_clients import normalize_radius_clients  # noqa: E402
from fabriclib.radius.normalize_radius_people import normalize_radius_people  # noqa: E402
from fabriclib.directory.ensure_default_device_roles import ensure_default_device_roles  # noqa: E402
from fabriclib.directory.list_roles import list_roles  # noqa: E402
from fabriclib.directory.run_op import run_op  # noqa: E402
from fabriclib.secrets.random_password import random_password  # noqa: E402
import fabriclib.directory.add_device as add_device_mod  # noqa: E402
import fabriclib.directory.add_role as add_role_mod  # noqa: E402
import fabriclib.directory.common.read_directory as read_mod  # noqa: E402
import fabriclib.directory.link_device_cert as link_mod  # noqa: E402


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[-700:]}"))


def sh(cmd, ok=True, **kw):
    res = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)
    if ok and res.returncode != 0:
        raise SystemExit(f"failed: {cmd}\n{res.stdout[-1500:]}{res.stderr[-1500:]}")
    return res


def until(pred, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(2)
    return False


def cleanup():
    sh(f"docker rm -f {DC} rt-radius rt-switch rt-stranger >/dev/null 2>&1", ok=False)
    sh(f"docker network rm {NET} >/dev/null 2>&1", ok=False)


def openssl(*args):
    sh(["openssl", *args], cwd=f"{W}/pki")


def leaf(name, ca, eku="clientAuth", cn=None):
    """A key + certificate signed by `ca` (root/int/foreign); returns the SHA-256 fingerprint."""
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr",
            "-subj", f"/CN={cn or name}")
    with open(f"{W}/pki/{name}.ext", "w") as f:
        f.write(f"extendedKeyUsage={eku}\n" + (f"subjectAltName=DNS:{cn}\n" if cn else ""))
    openssl("x509", "-req", "-in", f"{name}.csr", "-CA", f"{ca}.crt", "-CAkey", f"{ca}.key", "-CAcreateserial",
            "-out", f"{name}.crt", "-days", "2", "-extfile", f"{name}.ext")
    fp = sh(["openssl", "x509", "-in", f"{W}/pki/{name}.crt", "-noout", "-fingerprint", "-sha256"]).stdout
    return fp.strip().split("=", 1)[1].upper()


def dc_healthy():
    return sh(["docker", "inspect", "-f", "{{.State.Health.Status}}", DC], ok=False).stdout.strip() == "healthy"


if sh(["docker", "inspect", "-f", "{{.Config.Image}}", DC], ok=False).stdout.strip() not in ("", "fabric/samba:test"):
    sys.exit(f"a container named {DC} that is not a test DC runs here: not touching it")
cleanup()
shutil.rmtree(W, ignore_errors=True)
os.makedirs(f"{W}/pki")
DEBIAN = read_images_lock(os.path.join(REPO, "config"))["debian"]["ref"]

# ------------------------------------------------------------------ images
build = sh(["docker", "build", "-q", "-t", "fabric/freeradius:test", "--build-arg", f"BASE_IMAGE={DEBIAN}",
            f"{REPO}/packaging/images/freeradius"], ok=False)
check("FreeRADIUS image builds from Debian's packages on the pinned base", build.returncode == 0, build.stderr)
if build.returncode:
    sys.exit(1)
version = sh("docker run --rm --entrypoint /usr/sbin/freeradius fabric/freeradius:test -v", ok=False).stdout
check("FreeRADIUS 3.2 inside", "FreeRADIUS Version 3.2." in version, version[:120])
os.makedirs(f"{W}/client-build")
with open(f"{W}/client-build/Dockerfile", "w") as f:        # the test's switch: eapol_test + radclient
    f.write("FROM fabric/freeradius:test\nUSER root\nRUN apt-get update && apt-get install -y "
            "--no-install-recommends eapoltest freeradius-utils && rm -rf /var/lib/apt/lists/*\n"
            'ENTRYPOINT ["sleep", "infinity"]\n')
sh(["docker", "build", "-q", "-t", "fabric/radius-client:test", f"{W}/client-build"])

# ------------------------------------------------------------------ the DC, and a PKI under its root (as Step-CA's)
dc = start_dc(f"{W}/dc", DC, NET, SUBNET, DC_IP, domain=DOMAIN)
V, SECRETS = dc["v"], dc["secrets"]
check("the site's DC is up and converged (its fabric-radius-dc-0001 account included)", dc_healthy())
for mod in (add_device_mod, add_role_mod, read_mod, link_mod):   # fabric's secrets and audit log, stood in for
    if hasattr(mod, "load_secrets"):
        mod.load_secrets = lambda: SECRETS
    if hasattr(mod, "write_audit"):
        mod.write_audit = lambda *a, **k: None
shutil.copy(dc["root_ca"], f"{W}/pki/root.crt")
shutil.copy(dc["root_key"], f"{W}/pki/root.key")
openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "int.key", "-out", "int.csr", "-subj", "/CN=Test Int")
with open(f"{W}/pki/int.ext", "w") as f:
    f.write("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n")
openssl("x509", "-req", "-in", "int.csr", "-CA", "root.crt", "-CAkey", "root.key", "-CAcreateserial",
        "-out", "int.crt", "-days", "2", "-extfile", "int.ext")
openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "foreign.key", "-out", "foreign.crt",
        "-days", "2", "-subj", "/CN=Foreign Root", "-addext", "basicConstraints=critical,CA:TRUE")
SERVER_NAME = V["hostname_radius"]                         # the name supplicants check (fabric's setting)
leaf("radius", "int", "serverAuth", SERVER_NAME)
FP = {d: leaf(d, "int") for d in ("laptop1", "laptop2", "laptop3", "printer1", "cam1")}
FP["impostor"] = leaf("impostor", "foreign")
with open(f"{W}/pki/radius.chain", "w") as f:          # the chain as Step-CA hands it out
    f.write(open(f"{W}/pki/radius.crt").read() + open(f"{W}/pki/int.crt").read())

# setup's default device roles: created once; a deleted one is not brought back
marker = f"{W}/default-device-roles"
added = ensure_default_device_roles(V, SECRETS, marker, DC)
roles = {r["name"]: r for r in list_roles(V)}
check("default device roles created (six, no VLANs), MAB ones only network:mab",
      sorted(added) == ["iot", "network-gear", "phones-tablets", "printers", "servers", "workstations"]
      and all(not r["vlan"] for r in roles.values()) and roles["printers"]["permissions"] == ["network:mab"]
      and "network:eap-tls" in roles["workstations"]["permissions"], (added, roles))
run_op(V, SECRETS, "remove_role", {"name": "iot"}, DC)
again = ensure_default_device_roles(V, SECRETS, marker, DC)
check("...a default role the admin deleted is not brought back on the next setup",
      again == [] and "iot" not in {r["name"] for r in list_roles(V)}, again)

# roles and devices, made by fabric's own directory functions
add_role_mod.add_role(V, "test", "staff", {"permissions": ["network:eap-tls"], "vlan": "20", "priority": 50})
add_role_mod.add_role(V, "test", "quarantine", {"permissions": ["network:eap-tls"], "vlan": "99", "priority": 10})
add_role_mod.add_role(V, "test", "mab-printers", {"permissions": ["network:mab"], "vlan": "30", "priority": 50})
add_role_mod.add_role(V, "test", "dns-only", {"permissions": ["dns:dhcp-register"], "priority": 50})
add_device_mod.add_device(V, "test", "laptop1", {"type": "laptop", "roles": ["staff"]})
add_device_mod.add_device(V, "test", "laptop2", {"type": "laptop", "roles": ["staff"], "enabled": False})
add_device_mod.add_device(V, "test", "laptop3", {"type": "laptop", "roles": ["staff", "quarantine"]})
add_device_mod.add_device(V, "test", "printer1", {"type": "printer", "roles": ["mab-printers"],
                                                  "macs": ["02:00:00:00:30:01"]})
add_device_mod.add_device(V, "test", "cam1", {"type": "camera", "roles": ["dns-only"], "macs": ["02:00:00:00:30:02"]})
for d in ("laptop1", "laptop2", "laptop3", "cam1"):          # printer1's certificate stays unlinked
    link_mod.link_device_cert(V, "test", d, FP[d])

# people made the way fabric makes them (one-time password, site-<site>), then given a password of their own as
# Keycloak's first sign-in would; groups as an admin makes them with AD's tools (not `guests`: AD has its own). newbie keeps the one-time password.
PW = "Correct-Horse-9"
ONE_TIME = "Ot-" + random_password(20)
MACHINE_PW = "Mc-" + random_password(30)
PEOPLE = {"alice": ["staff"], "gina": ["staff", "visitors"], "sam": ["contractors"], "nora": ["sales"],
          "lockme": ["staff"], "dora": ["staff"], "newbie": ["staff"]}
for uid in PEOPLE:
    run_op(V, SECRETS, "create_person", {"uid": uid, "first": uid.title(), "last": "Test", "email": f"{uid}@{DOMAIN}",
                                         "password": ONE_TIME, "gid": 5000, "home_base": "/home",
                                         "shell": "/bin/bash"}, DC)
seed_people = f"""
import sys
sys.path.insert(0, "/fabric")
from samba.dsdb import GTYPE_SECURITY_GLOBAL_GROUP
from open_samdb import open_samdb
samdb, lp = open_samdb("/data/etc/smb.conf")
people = {PEOPLE!r}
for uid in people:
    if uid != "newbie":
        samdb.setpassword("(sAMAccountName=%s)" % uid, {PW!r}, force_change_at_next_login=False)
samdb.disable_account("(sAMAccountName=dora)")
for machine, ou in (("ws1", "OU=servers,OU=machines"), ("ws9", "CN=Computers")):   # ws9: outside OU=machines
    samdb.newcomputer(machine, computerou=ou)
    samdb.setpassword("(sAMAccountName=%s$)" % machine, {MACHINE_PW!r}, force_change_at_next_login=False)
for group in sorted({{g for gs in people.values() for g in gs}}):
    samdb.newgroup(group, groupou="OU=groups", grouptype=GTYPE_SECURITY_GLOBAL_GROUP)
    samdb.add_remove_group_members(group, [u for u, gs in people.items() if group in gs], add_members_operation=True)
print("seeded")
"""
seeded = sh(["docker", "exec", "-i", DC, "python3", "-"], input=seed_people, ok=False)
check("people and groups in the domain", "seeded" in seeded.stdout, seeded.stderr[-600:])

# ------------------------------------------------------------------ FreeRADIUS from fabric's templates
clients, embedded = normalize_radius_clients([{"name": "switch1", "address": SWITCH_IP, "secret": SECRET}])
people_map = normalize_radius_people([{"group": "staff", "vlan": 20, "priority": 50},
                                      {"group": "visitors", "vlan": 50, "priority": 60},
                                      {"group": "contractors", "priority": 70},
                                      {"group": "Domain Computers", "vlan": 40, "priority": 80}])
rv = {**V, "deploy_base_dir": W, "radius_clients": clients, "radius_people": people_map,
      "service_users": {"freeradius": {"uid": 610, "gid": 610}}, "ip_freeradius": RADIUS_IP,
      "freeradius_mem_limit": "96m"}
# the container's address and memory limit as fabric's compose file sets them (ip_freeradius, freeradius_mem_limit)
COMPOSE = yaml.safe_load(jinja_env(os.path.join(REPO, "templates")).get_template(
    "freeradius/docker-compose.yml.j2").render(**rv))["services"]["freeradius"]
deploy_freeradius(rv, {"radius_secrets": embedded, "ad_radius_password": SECRETS["ad_radius_password"]},
                  jinja_env(os.path.join(REPO, "templates")))
install_cert(f"{W}/pki/radius.chain", f"{W}/pki/radius.key", f"{W}/pki/root.crt", f"{W}/freeradius/certs", 610, 610,
             names=("server.pem", "server.key", None))
CRL_PW = f"{W}/pki/crl.pw"
open(CRL_PW, "w").write("unused\n")                          # the test CA's key is not encrypted


def write_ca_pem(revoked=()):
    """FreeRADIUS's ca.pem as fabric's publish_crl writes it: the CA certificates, then the intermediate's CRL
    (check_crl = yes, 2.1.5.10); revoked — serials in that CRL."""
    entries = [{"serial": s, "when": "2026-10-08T10:00:00+00:00", "reason": "keyCompromise"} for s in revoked]
    crl = _gencrl(f"{W}/pki/int.crt", f"{W}/pki/int.key", CRL_PW, entries)
    with open(f"{W}/freeradius/certs/ca.pem", "w") as f:       # as setup's certificate step writes it
        f.write(open(f"{W}/pki/root.crt").read() + open(f"{W}/pki/int.crt").read() + crl)


write_ca_pem()
# covers: setting:radius_clients +
check("config: clients.conf holds the client secret, mode 0640 (never world-readable)",
      oct(os.stat(f"{W}/freeradius/config/clients.conf").st_mode & 0o777) == "0o640"
      and SECRET in open(f"{W}/freeradius/config/clients.conf").read())
check("config: the directory account's password file, mode 0640",
      oct(os.stat(f"{W}/freeradius/config/ad-password").st_mode & 0o777) == "0o640")


def start_radius():
    sh(["docker", "run", "-d", "--name", "rt-radius", "--network", NET, "--ip",
        COMPOSE["networks"]["fabric_net"]["ipv4_address"], "--memory", COMPOSE["mem_limit"], "--user", "610:610",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--tmpfs", "/tmp:noexec,nosuid,size=8m", "--tmpfs", "/run/freeradius:uid=610,gid=610,mode=0700,size=8m",
        "-v", f"{W}/freeradius/config:/etc/freeradius/fabric:ro",
        "-v", f"{W}/freeradius/certs:/etc/freeradius/certs:ro",
        "-v", f"{W}/freeradius/python:/etc/freeradius/python:ro",
        # as the compose file mounts them: the DC's winbind for PEAP
        "-v", f"{W}/dc/samba/winbindd:/run/samba/winbindd:ro",
        "-v", f"{W}/dc/samba/data/state/winbindd_privileged:/data/state/winbindd_privileged:ro",
        "-v", f"{W}/dc/samba/data/etc:/etc/samba:ro", "fabric/freeradius:test"])
    return until(lambda: "Ready to process requests" in logs(), 60)


def logs():
    res = sh("docker logs rt-radius", ok=False)
    return res.stdout + res.stderr


ready = start_radius()
check("FreeRADIUS starts on fabric's configuration (non-root, read-only)", ready, logs()[-1500:])
if not ready:
    cleanup()
    sys.exit(1)
for name, ip in (("rt-switch", SWITCH_IP), ("rt-stranger", STRANGER_IP)):
    sh(["docker", "run", "-d", "--name", name, "--network", NET, "--ip", ip, "-v", f"{W}/pki:/pki:ro",
        "fabric/radius-client:test"])


def eap_tls(cert, box="rt-switch", secret=SECRET, mac="02:00:00:00:10:01"):
    """(accepted, VLAN or None, output) for one EAP-TLS authentication."""
    conf = (f'network={{\n key_mgmt=IEEE8021X\n eap=TLS\n identity="{cert}"\n ca_cert="/pki/root.crt"\n'
            f' client_cert="/pki/{cert}.crt"\n private_key="/pki/{cert}.key"\n'
            f' domain_suffix_match="{SERVER_NAME}"\n eapol_flags=0\n}}\n')
    res = sh(["docker", "exec", "-i", box, "sh", "-c",
              f"cat > /tmp/{cert}.conf && eapol_test -c /tmp/{cert}.conf -a {RADIUS_IP} -s '{secret}' "
              f"-M {mac} -t 10 -r 0"], ok=False, input=conf)
    text = res.stdout + res.stderr
    # eapol_test dumps the value in hex: "Value: 3230" is VLAN "20"
    vlan = re.search(r"Attribute 81 \(Tunnel-Private-Group-Id\).*?\n\s*Value: ([0-9a-fA-F]+)", text)
    vlan = bytes.fromhex(vlan.group(1)).decode() if vlan else None
    return res.returncode == 0 and "SUCCESS" in text, vlan, text


# radclient always adds a Message-Authenticator (since BlastRADIUS): a raw request without one
RAW_REQUEST = r'''
import hashlib, os, socket, sys
server, secret, mac = sys.argv[1], sys.argv[2].encode(), sys.argv[3].encode()
auth = os.urandom(16)
def attr(t, v):
    return bytes([t, len(v) + 2]) + v
pw, prev, enc = mac.ljust(32, b"\0"), auth, b""
for i in range(0, 32, 16):
    block = bytes(a ^ b for a, b in zip(pw[i:i + 16], hashlib.md5(secret + prev).digest()))
    enc, prev = enc + block, block
body = attr(1, mac) + attr(2, enc) + attr(31, mac) + attr(32, b"switch1")
packet = bytes([1, 7]) + (20 + len(body)).to_bytes(2, "big") + auth + body
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(4)
s.sendto(packet, (server, 1812))
try:
    print("Received", {2: "Access-Accept", 3: "Access-Reject"}.get(s.recv(4096)[0], "?"))
except socket.timeout:
    print("no reply")
'''


def mab(mac, box="rt-switch", secret=SECRET, authenticator=True, user=None, timeout=3):
    """(reply code or None, VLAN or None, output) for one MAB request (User-Name = the MAC)."""
    if not authenticator:
        res = sh(["docker", "exec", "-i", box, "python3", "-", RADIUS_IP, secret, mac], ok=False, input=RAW_REQUEST)
        code = re.search(r"Received (Access-\w+)", res.stdout)
        return code.group(1) if code else None, None, res.stdout + res.stderr
    attrs = (f'User-Name = "{user or mac}", User-Password = "{user or mac}", Calling-Station-Id = "{mac}", '
             f'NAS-Identifier = "switch1", Message-Authenticator = 0x00')
    res = sh(["docker", "exec", "-i", box, "radclient", "-x", "-r", "1", "-t", str(timeout), f"{RADIUS_IP}:1812",
              "auth", secret], ok=False, input=attrs + "\n")
    text = res.stdout + res.stderr
    code = re.search(r"Received (Access-\w+)", text)
    vlan = re.search(r'Tunnel-Private-Group-Id(?::\d+)? = "?(\d+)', text)
    return code.group(1) if code else None, vlan.group(1) if vlan else None, text


# ------------------------------------------------------------------ EAP-TLS
ok, vlan, out = eap_tls("laptop1")
check("EAP-TLS: linked certificate, enabled device, role grants it -> accepted on the role's VLAN (20)",
      ok and vlan == "20", out[-1200:] + logs()[-800:])
ok, vlan, out = eap_tls("laptop3")
check("EAP-TLS: two roles with VLANs -> the lowest priority number wins (quarantine, 99)", ok and vlan == "99",
      (vlan, out[-600:]))
ok, _, out = eap_tls("laptop2")
check("EAP-TLS: a disabled device is refused", not ok and "device=laptop2 reason=device_disabled" in logs(),
      logs()[-600:])
ok, _, out = eap_tls("printer1")
check("EAP-TLS: a fabric certificate linked to no device is refused",
      not ok and "reason=no_device_has_it" in logs(), logs()[-600:])
ok, _, out = eap_tls("cam1")
check("EAP-TLS: a device whose roles lack network:eap-tls is refused",
      not ok and "device=cam1 reason=no_role_grants_network:eap-tls" in logs(), logs()[-600:])
ok, _, out = eap_tls("impostor")
check("EAP-TLS: a certificate from another CA is refused in the TLS handshake", not ok, out[-400:])
link_mod.link_device_cert(V, "test", "laptop1", FP["laptop1"], link=False)
ok, _, out = eap_tls("laptop1")
check("EAP-TLS: unlinking the certificate refuses it at the next authentication",
      not ok and "REJECT method=eap-tls device=- reason=no_device_has_it" in logs()
      and f"sha256={FP['laptop1']}" in logs().rsplit("REJECT method=eap-tls", 1)[-1], logs()[-400:])
link_mod.link_device_cert(V, "test", "laptop1", FP["laptop1"])
laptop1_serial = sh(["openssl", "x509", "-in", f"{W}/pki/laptop1.crt", "-noout", "-serial"]).stdout.strip().split("=")[1]
write_ca_pem(revoked=[laptop1_serial])                       # revoked, still linked (2.1.5.10)
sh("docker rm -f rt-radius", ok=False)
start_radius()
ok, _, out = eap_tls("laptop1")
check("EAP-TLS: a revoked certificate is refused in the TLS handshake even while its device is linked (CRL)",
      not ok, out[-400:])
ok, vlan, _ = eap_tls("laptop3")
check("EAP-TLS: …and a certificate that is not revoked still gets in", ok, logs()[-400:])
write_ca_pem()
sh("docker rm -f rt-radius", ok=False)
start_radius()

# ------------------------------------------------------------------ EAP-TTLS (people)
def eap_ttls(user, password, mac="02:00:00:00:20:01"):
    """(accepted, VLAN or None, output) for one EAP-TTLS/PAP login."""
    conf = (f'network={{\n key_mgmt=IEEE8021X\n eap=TTLS\n identity="{user}"\n anonymous_identity="anonymous"\n'
            f' password="{password}"\n phase2="auth=PAP"\n ca_cert="/pki/root.crt"\n'
            f' domain_suffix_match="{SERVER_NAME}"\n eapol_flags=0\n}}\n')
    res = sh(["docker", "exec", "-i", "rt-switch", "sh", "-c",
              f"cat > /tmp/ttls.conf && eapol_test -c /tmp/ttls.conf -a {RADIUS_IP} -s '{SECRET}' -M {mac} -t 10 -r 0"],
             ok=False, input=conf)
    text = res.stdout + res.stderr
    vlan = re.search(r"Attribute 81 \(Tunnel-Private-Group-Id\).*?\n\s*Value: ([0-9a-fA-F]+)", text)
    return res.returncode == 0 and "SUCCESS" in text, bytes.fromhex(vlan.group(1)).decode() if vlan else None, text


ok, vlan, out = eap_ttls("alice", PW)
# covers: setting:radius_people +
check("EAP-TTLS: a member of a mapped group, right password -> accepted on the group's VLAN (20)",
      ok and vlan == "20" and "ACCEPT method=eap-ttls person=alice group=staff vlan=20" in logs(),
      out[-800:] + logs()[-600:])
ok, vlan, out = eap_ttls("gina", PW)
check("EAP-TTLS: in two mapped groups -> the lowest priority number wins (staff, 20)", ok and vlan == "20",
      (vlan, logs()[-300:]))
ok, vlan, out = eap_ttls("sam", PW)
check("EAP-TTLS: a mapped group without a VLAN -> accepted on the port's default", ok and vlan is None,
      (vlan, logs()[-300:]))
ok, _, out = eap_ttls("alice", "wrong-password")
check("EAP-TTLS: a wrong password is refused", not ok and "person=alice reason=wrong_password_or_account_locked"
      in logs(), logs()[-400:])
ok, _, out = eap_ttls("nora", PW)
check("EAP-TTLS: a person in no mapped group is refused",
      not ok and "person=nora reason=in_no_group_mapped_for_802.1X" in logs(), logs()[-400:])
ok, _, out = eap_ttls("dora", PW)
check("EAP-TTLS: a person disabled in the domain is refused",
      not ok and "person=dora reason=wrong_password_or_account_locked" in logs(), logs()[-400:])
ok, _, out = eap_ttls("newbie", ONE_TIME)
check("EAP-TTLS: a person still on their one-time password is refused (they change it at the web sign-in first)",
      not ok and "person=newbie reason=wrong_password_or_account_locked" in logs(), logs()[-400:])
ok, _, out = eap_ttls("nobody", PW)
check("EAP-TTLS: an unknown name is refused", not ok and "person=nobody reason=no_such_person" in logs(),
      logs()[-400:])
for _ in range(5):
    eap_ttls("lockme", "wrong-password")
ok, _, out = eap_ttls("lockme", PW)
check("EAP-TTLS: after 5 wrong passwords the domain locks the account: the right one is refused too", not ok,
      logs()[-400:])
code, _, out = mab("02:00:00:00:30:01", user="alice")
check("a person's password sent outside the TLS tunnel (plain PAP) is refused", code == "Access-Reject", out[-300:])

# ------------------------------------------------------------------ PEAP-MSCHAPv2 (people and machines)
def eap_peap(user, password, mac="02:00:00:00:20:02"):
    """(accepted, VLAN or None, output) for one PEAP-MSCHAPv2 login."""
    conf = (f'network={{\n key_mgmt=IEEE8021X\n eap=PEAP\n identity="{user}"\n anonymous_identity="anonymous"\n'
            f' password="{password}"\n phase1="peaplabel=0"\n phase2="auth=MSCHAPV2"\n ca_cert="/pki/root.crt"\n'
            f' domain_suffix_match="{SERVER_NAME}"\n eapol_flags=0\n}}\n')
    res = sh(["docker", "exec", "-i", "rt-switch", "sh", "-c",
              f"cat > /tmp/peap.conf && eapol_test -c /tmp/peap.conf -a {RADIUS_IP} -s '{SECRET}' -M {mac} -t 10 -r 0"],
             ok=False, input=conf)
    text = res.stdout + res.stderr
    vlan = re.search(r"Attribute 81 \(Tunnel-Private-Group-Id\).*?\n\s*Value: ([0-9a-fA-F]+)", text)
    return res.returncode == 0 and "SUCCESS" in text, bytes.fromhex(vlan.group(1)).decode() if vlan else None, text


ok, vlan, out = eap_peap("alice", PW)
check("PEAP: a person in a mapped group, checked by the DC's winbind -> accepted on the group's VLAN (20)",
      ok and vlan == "20" and "ACCEPT method=peap group=staff vlan=20" in logs() and "person=alice" in logs(),
      out[-800:] + logs()[-800:])
ok, vlan, out = eap_peap(f"host/ws1.{V['ad_domain']}", MACHINE_PW)
check("PEAP: a machine in OU=machines (host/ws1 as ws1$, in OU=servers) by its Domain Computers mapping -> "
      "accepted on VLAN 40",
      ok and vlan == "40" and "machine=ws1$" in logs().rsplit("method=peap", 1)[-1], out[-800:] + logs()[-800:])
ok, _, out = eap_peap(f"host/ws9.{V['ad_domain']}", MACHINE_PW)
check("PEAP: a machine outside OU=machines is refused",
      not ok and "reason=not_a_machine_in_OU=machines" in logs(), logs()[-400:])
ok, _, out = eap_peap("alice", "wrong-password")
check("PEAP: a wrong password is refused by the domain", not ok, logs()[-400:])
ok, _, out = eap_peap("nora", PW)
check("PEAP: a person in no mapped group is refused",
      not ok and "reason=in_no_group_mapped_for_802.1X" in logs().rsplit("method=peap", 1)[-1], logs()[-400:])
ok, _, out = eap_peap("dora", PW)
check("PEAP: a person disabled in the domain is refused", not ok, logs()[-400:])

# ------------------------------------------------------------------ MAB
code, vlan, out = mab("02-00-00-00-30-01")
check("MAB: a MAC whose device has network:mab -> Access-Accept on its VLAN (30)",
      code == "Access-Accept" and vlan == "30", out[-800:] + logs()[-600:])
code, _, out = mab("02:00:00:00:30:02")
check("MAB: a device without network:mab is refused", code == "Access-Reject", out[-400:])
code, _, out = mab("02:00:00:00:99:99")
check("MAB: an unknown MAC is refused", code == "Access-Reject", out[-400:])
code, _, out = mab("02:00:00:00:30:01", user="alice")
check("MAB: a User-Name that is not the calling MAC is refused", code == "Access-Reject", out[-400:])

# ------------------------------------------------------------------ refused before any policy
code, _, out = mab("02:00:00:00:30:01", box="rt-stranger")
check("an address that is not a RADIUS client gets no answer", code is None, out[-300:])
code, _, out = mab("02:00:00:00:30:01", secret="WrongSecretWrongSecret")
check("a wrong shared secret gets no Access-Accept", code != "Access-Accept", out[-300:])
code, _, out = mab("02:00:00:00:30:01", authenticator=False)
check("a request without Message-Authenticator is dropped (BlastRADIUS)",
      code is None and "Message-Authenticator" in logs(), out[-300:] + logs()[-400:])

# ------------------------------------------------------------------ fail closed
sh(f"docker stop {DC}")
code, _, out = mab("02:00:00:00:30:01", timeout=12)
check("the DC down: refused, not let in (fail closed)",
      code == "Access-Reject" and "reason=directory_error" in logs(), out[-300:] + logs()[-400:])
sh(f"docker start {DC}")
until(dc_healthy, 300)
code, _, out = mab("02:00:00:00:30:01")
check("the DC back: FreeRADIUS reconnects by itself", code == "Access-Accept", out[-300:] + logs()[-400:])

# ------------------------------------------------------------------ fabricctl radius (in-process, as fabriclib/cli.py routes it)
# The commands edit vars.yaml and fabric's secrets: here a scratch copy of each (the real save_secrets, on a file), the
# audit log stood in for as above. "Apply" is what apply does for FreeRADIUS: its files from them, then a restart.
import contextlib  # noqa: E402
import functools  # noqa: E402
import getpass  # noqa: E402
import importlib  # noqa: E402
import io  # noqa: E402
from fabriclib.common.load_vars import load_vars  # noqa: E402
from fabriclib.common.save_vars import save_vars  # noqa: E402
from fabriclib.common.vars_lock import vars_lock  # noqa: E402
from fabriclib.radius.run_radius_command import run_radius_command  # noqa: E402
from fabriclib.secrets.save_secrets import save_secrets  # noqa: E402

CLI = f"{W}/cli"
os.makedirs(CLI)
VARS_FILE, SECRETS_FILE = f"{CLI}/vars.yaml", f"{CLI}/fabric-secrets.yml"
save_vars({"install_freeradius": True, "hostname_radius": V["hostname_radius"], "host_ip": V["host_ip"],
           "radius_clients": clients, "radius_people": people_map}, VARS_FILE)
save_secrets({"radius_secrets": embedded, "ad_radius_password": SECRETS["ad_radius_password"]}, SECRETS_FILE)
for name in ("add_radius_client", "rotate_radius_secret", "remove_radius_client", "map_radius_group",
             "unmap_radius_group"):
    mod = importlib.import_module(f"fabriclib.radius.{name}")
    mod.load_vars = functools.partial(load_vars, VARS_FILE)
    if hasattr(mod, "save_vars"):
        mod.save_vars = functools.partial(save_vars, path=VARS_FILE)
    mod.vars_lock = functools.partial(vars_lock, f"{CLI}/.vars.lock")
    if hasattr(mod, "save_secrets"):
        mod.save_secrets = functools.partial(save_secrets, path=SECRETS_FILE)
    mod.write_audit = lambda *a, **k: None
ASKED = []


def radius(*argv, typed=None):
    """fabricctl radius …, as the CLI routes it (the rendered vars, then the command): (exit status, stdout, stderr).
    typed — what the person types at the hidden prompt (getpass stood in for, as tests/common/ask.py does)."""
    out, err, real = io.StringIO(), io.StringIO(), getpass.getpass

    def answer(prompt=""):
        ASKED.append(prompt)
        if typed is None:
            raise EOFError
        return typed
    getpass.getpass = answer
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = run_radius_command({**V, **load_vars(VARS_FILE)}, list(argv))
    finally:
        getpass.getpass = real
    return code, out.getvalue(), err.getvalue()


def stored():
    """vars.yaml and the secrets, as saved (to prove a refusal changed nothing)."""
    return open(VARS_FILE).read(), open(SECRETS_FILE).read()


def secrets_now():
    return yaml.safe_load(open(SECRETS_FILE)).get("radius_secrets") or {}


def apply_radius():
    """What apply does for FreeRADIUS (deploy_optional_parts): its files from vars.yaml and the secrets, a restart."""
    data, sec = load_vars(VARS_FILE), yaml.safe_load(open(SECRETS_FILE))
    deploy_freeradius({**rv, "radius_clients": data.get("radius_clients") or [],
                       "radius_people": data.get("radius_people") or []},
                      {"radius_secrets": sec.get("radius_secrets") or {},
                       "ad_radius_password": sec["ad_radius_password"]}, jinja_env(os.path.join(REPO, "templates")))
    sh("docker rm -f rt-radius", ok=False)
    return start_radius()


code, out, err = radius()
# covers: cli:radius cli:radius.status setting:hostname_radius +
check("fabricctl radius (status by default): the server name supplicants verified above (hostname_radius), the "
      "client with Message-Authenticator required, the mapped groups with their VLANs; never a secret",
      code == 0 and f"server name (supplicants check it): {SERVER_NAME}   RADIUS on {V['host_ip']}:1812/udp" in out
      and re.search(rf"switch1 +{re.escape(SWITCH_IP)} +Message-Authenticator required", out)
      and re.search(r"group staff +vlan 20 +priority 50", out) and SECRET not in out and not err, (code, out, err))
code, out, err = radius("bogus")
code2, out2, err2 = radius("status", "extra")
# covers: cli:radius cli:radius.status -
check("fabricctl radius: an unknown command, or status with an argument, is refused with the usage (exit 2)",
      code == 2 and code2 == 2 and "usage: fabricctl radius status" in err and "usage: fabricctl radius status" in err2
      and not out and not out2, (code, err, code2, err2))

before = stored()
code, out, err = radius("add-client", "switch2", "0.0.0.0/0", "--no-apply")
code2, _, err2 = radius("add-client", "switch3", SWITCH_IP, "--no-apply")
code3, _, err3 = radius("add-client", "Bad_Name", STRANGER_IP, "--no-apply")
# covers: cli:radius.add-client -
check("add-client refused: 'any address', an address another client has, a name that is not one -> exit 1, why, "
      "nothing saved",
      (code, code2, code3) == (1, 1, 1) and "error: radius_clients: switch2: 'any address' is not a RADIUS client" in err
      and "overlap" in err2 and "switch1" in err2 and "is not a name" in err3 and stored() == before,
      (err, err2, err3))
code, out, err = radius("add-client", "switch2", STRANGER_IP, "--secret-prompt", "--no-apply", typed="too short")
# covers: ask:radius.secret -
check("add-client --secret-prompt: a typed secret that is too short or has spaces is refused, nothing saved",
      code == 1 and "the secret must be 16-128 printable characters" in err and ASKED[-1] == "shared secret (hidden): "
      and stored() == before, (code, err, ASKED[-1:]))

code, out, err = radius("add-client", "Switch2", STRANGER_IP, "--no-apply")
NEW = out.strip().splitlines()[-2] if code == 0 and len(out.strip().splitlines()) > 2 else ""
saved_ok = (code == 0 and "RADIUS client switch2 added" in out and "recorded; apply with: sudo fabricctl --apply" in out
            and len(NEW) == 32 and secrets_now().get("switch2") == NEW and NEW not in open(VARS_FILE).read()
            and any(c["name"] == "switch2" for c in load_vars(VARS_FILE)["radius_clients"]))
apply_radius()
reply, vlan, mab_out = mab("02:00:00:00:30:01", box="rt-stranger", secret=NEW)
# covers: cli:radius.add-client +
check("add-client: the secret shown once is kept in the secrets (not vars.yaml); after apply the new switch is "
      "answered with it (MAB accepted on VLAN 30)", saved_ok and reply == "Access-Accept" and vlan == "30",
      (code, out, err, reply, mab_out[-300:]))

TYPED = "Typed-Secret-For-Switch2-0001"
code, out, err = radius("rotate-secret", "switch2", "--secret-prompt", "--no-apply", typed=f"  {TYPED} \n")
saved_ok = (code == 0 and f"new shared secret for switch2 (shown once; give the device the same):\n{TYPED}" in out
            and secrets_now().get("switch2") == TYPED and ASKED[-1] == "shared secret (hidden): ")
apply_radius()
new_reply, _, new_out = mab("02:00:00:00:30:01", box="rt-stranger", secret=TYPED)
old_reply, _, old_out = mab("02:00:00:00:30:01", box="rt-stranger", secret=NEW)
# covers: cli:radius.rotate-secret ask:radius.secret +
check("rotate-secret --secret-prompt: the typed secret (trimmed) replaces the old one; after apply the switch is "
      "answered with it, the old one gets no Access-Accept",
      saved_ok and new_reply == "Access-Accept" and old_reply != "Access-Accept",
      (code, out, err, new_reply, old_reply, new_out[-300:]))
before = stored()
code, out, err = radius("rotate-secret", "nosuch", "--no-apply")
code2, _, err2 = radius("rotate-secret", "switch2", "--secret-prompt", "--no-apply", typed="has spaces in it, quite long")
# covers: cli:radius.rotate-secret ask:radius.secret -
check("rotate-secret refused: a client fabric does not have; a typed secret with spaces -> exit 1, why, nothing saved",
      code == 1 and "error: no RADIUS client nosuch" in err and code2 == 1
      and "the secret must be 16-128 printable characters" in err2 and stored() == before, (err, err2))

code, out, err = radius("remove-client", "nosuch", "--no-apply")
# covers: cli:radius.remove-client -
check("remove-client refused: a client fabric does not have -> exit 1, why, nothing changed",
      code == 1 and "error: no RADIUS client nosuch" in err and stored() == before, (code, err))
code, out, err = radius("remove-client", "switch2", "--no-apply")
saved_ok = (code == 0 and "RADIUS client switch2 removed" in out and "switch2" not in secrets_now()
            and not any(c["name"] == "switch2" for c in load_vars(VARS_FILE)["radius_clients"]))
apply_radius()
reply, _, mab_out = mab("02:00:00:00:30:01", box="rt-stranger", secret=TYPED)
# covers: cli:radius.remove-client +
check("remove-client: gone from vars.yaml and its secret deleted; after apply the switch gets no answer",
      saved_ok and reply is None, (code, out, err, reply, mab_out[-300:]))

before = stored()
code, out, err = radius("map-group", "sales", "--vlan", "5000", "--no-apply")
code2, _, err2 = radius("map-group", "bad group!", "--no-apply")
code3, _, err3 = radius("map-group", "sales", "--priority", "10000", "--no-apply")
# covers: cli:radius.map-group -
check("map-group refused: VLAN 5000, a name that is no group's, priority 10000 -> exit 1, why, nothing saved",
      (code, code2, code3) == (1, 1, 1) and "radius_people: sales: VLAN must be 1-4094" in err
      and "is not a group name" in err2 and "priority must be 0-9999" in err3 and stored() == before,
      (err, err2, err3))
code, out, err = radius("map-group", "sales", "--vlan", "60", "--priority", "40", "--no-apply")
apply_radius()
ok, vlan, ttls_out = eap_ttls("nora", PW)
# covers: cli:radius.map-group +
check("map-group: after apply a member of the newly mapped group (nora, sales) is accepted on its VLAN (60)",
      code == 0 and "members of sales may join by password on VLAN 60" in out and ok and vlan == "60",
      (code, out, err, vlan, logs()[-400:]))
code, out, err = radius("unmap-group", "sales", "--no-apply")
apply_radius()
ok, _, ttls_out = eap_ttls("nora", PW)
# covers: cli:radius.unmap-group +
check("unmap-group: after apply that group's member is refused again (in no mapped group)",
      code == 0 and "members of sales may no longer join by password" in out and not ok
      and "person=nora reason=in_no_group_mapped_for_802.1X" in logs(), (code, out, err, logs()[-400:]))
before = stored()
code, out, err = radius("unmap-group", "sales", "--no-apply")
# covers: cli:radius.unmap-group -
check("unmap-group refused: a group that is not mapped -> exit 1, why, nothing changed",
      code == 1 and "error: group sales is not mapped for 802.1X" in err and stored() == before, (code, err))

save_vars({**load_vars(VARS_FILE), "install_freeradius": False}, VARS_FILE)
before = stored()
code, out, err = radius("status")
# covers: setting:install_freeradius +
check("install_freeradius false: status says 802.1X is off (true: the clients and groups above)",
      code == 0 and out.strip() == "802.1X is off (install_freeradius: false)", (code, out, err))
code, out, err = radius("add-client", "switch4", STRANGER_IP, "--no-apply")
code2, _, err2 = radius("map-group", "sales", "--no-apply")
# covers: cli:radius.add-client cli:radius.map-group -
check("802.1X off: add-client and map-group are refused (exit 1, why), nothing saved",
      code == 1 and code2 == 1 and "error: 802.1X is off (install_freeradius: false)" in err
      and "error: 802.1X is off (install_freeradius: false)" in err2 and stored() == before, (err, err2))

# ------------------------------------------------------------------ hardening
import json  # noqa: E402
h = json.loads(sh("docker inspect rt-radius").stdout)[0]
check("container: uid 610, no capabilities, read-only, no-new-privileges",
      h["Config"]["User"] == "610:610" and h["HostConfig"]["CapDrop"] == ["ALL"] and not h["HostConfig"].get("CapAdd")
      and h["HostConfig"]["ReadonlyRootfs"] and "no-new-privileges:true" in h["HostConfig"]["SecurityOpt"])
net = h["NetworkSettings"]["Networks"][NET]
# covers: setting:ip_freeradius setting:freeradius_mem_limit +
check("the container on the address and memory limit fabric's compose file gives it (ip_freeradius, the address every "
      "request above went to; freeradius_mem_limit 96m)",
      net["IPAddress"] == RADIUS_IP == rv["ip_freeradius"] and h["HostConfig"]["Memory"] == 96 * 1024 * 1024,
      (net["IPAddress"], h["HostConfig"]["Memory"]))
check("no RADIUS secret and no person's password in the logs",
      SECRET not in logs() and PW not in logs() and ONE_TIME not in logs() and "wrong-password" not in logs()
      and SECRETS["ad_radius_password"] not in logs() and MACHINE_PW not in logs())

cleanup()
print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
