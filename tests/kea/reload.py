#!/usr/bin/env python3
"""Kea taking a changed file without a restart, and Kea's DNS key replaced, against real Kea 3.0 and BIND on fabric's
images and templates (decisions 2.1.10.45 and 2.1.10.42, manual 1.10.4.42 and 1.10.4.43):

- kea-dhcp4 and kea-dhcp-ddns run as their compose file says, each control socket reachable from the host;
- a changed kea-dhcp4.conf taken by `config-reload` (reload_kea): the container not restarted, its leases kept, the
  next client given the new option; a file Kea does not take: reload_kea restarts Kea instead, saying why, and Kea
  kept serving its old configuration until then;
- kea-ddns restarted over its run folder (the old PID file) comes back;
- the key replaced: BIND knowing both keys (fabric's templates), kea-dhcp-ddns reloaded on the new one and a client
  registered with it, the old key still accepted until drop_old_key renders BIND without it; then the old key
  refused and the new one accepted.

    sudo python3 tests/kea/reload.py          (needs Docker, dig, nsupdate, root)
"""
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "tests", "common"))
import test_run as testrun  # noqa: E402
P = testrun.PREFIX                  # this run's 10.<n>; names <base>-<run id> (manual 3.1.2.6)
KR_DHCP4, KR_DDNS, KR_BIND, KR_C1, KR_C2, KR_C3, KR_C4 = (testrun.name(f"kr-{n}") for n in ("dhcp4", "ddns", "bind", "c1", "c2", "c3", "c4"))
ALL = (KR_DHCP4, KR_DDNS, KR_BIND, KR_C1, KR_C2, KR_C3, KR_C4)
BIND_IMAGE = "fabric/bind9:" + testrun.name("kearl")
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/kea-reload"
NET, SUBNET = testrun.name("kearl_net"), f"{P}.27.0/24"
BIND_IP, DDNS_IP = f"{P}.27.30", f"{P}.27.97"
FAILED = 0
sys.path[0:0] = [os.path.join(REPO, "src"), REPO]
from tests.common.kea_image import TAG as KEA_IMAGE, build_kea_image  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.common.read_packages_lock import read_packages_lock  # noqa: E402
from fabriclib.dhcp.deploy_kea import deploy_kea  # noqa: E402
from fabriclib.dhcp.dhcp_reverse_zones import dhcp_reverse_zones  # noqa: E402
from fabriclib.dhcp.kea_command import kea_command  # noqa: E402
from fabriclib.dhcp.kea_key.drop_old_key import drop_old_key  # noqa: E402
from fabriclib.dhcp.list_leases import list_leases  # noqa: E402
from fabriclib.dhcp.normalize_dhcp import normalize_dhcp  # noqa: E402
from fabriclib.dhcp.reload_kea import reload_kea  # noqa: E402


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:600]}"))


def sh(cmd, ok=True, **kw):
    res = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)
    if ok and res.returncode != 0:
        raise SystemExit(f"failed: {cmd}\n{res.stdout[-1500:]}{res.stderr[-1500:]}")
    return res


def until(pred, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(1)
    return False


def started(name):
    return sh(["docker", "inspect", "-f", "{{.State.StartedAt}}", name], ok=False).stdout.strip()


def dig(name, rtype="A"):
    return sh(["dig", "+short", f"@{BIND_IP}", name, rtype], ok=False).stdout.strip()


def nsupdate(name, secret, record):
    """One signed update from the host, the key in a 0600 file (never on the command line)."""
    fd, path = tempfile.mkstemp(suffix=".key")
    with os.fdopen(fd, "w") as f:
        f.write(f'key "{name}" {{ algorithm hmac-sha256; secret "{secret}"; }};\n')
    try:
        script = f"server {BIND_IP}\nzone dhcp.lan.test\nupdate add {record}\nsend\n"
        res = sh(["nsupdate", "-k", path], ok=False, input=script)
    finally:
        os.remove(path)
    return res.returncode, res.stdout + res.stderr


def cleanup():
    testrun.remove("container", *ALL)            # this run's only
    testrun.remove("network", NET)


cleanup()
shutil.rmtree(W, ignore_errors=True)
os.makedirs(f"{W}/bind9/data")
os.makedirs(f"{W}/bind9/config")
lock, pkgs = read_images_lock(os.path.join(REPO, "config")), read_packages_lock(os.path.join(REPO, "config"))
BUSYBOX = "busybox:1.37@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"
check("Kea's image builds (fabric's packaging, the pinned version)", build_kea_image().returncode == 0)
sh(["docker", "build", "-q", "-t", BIND_IMAGE, "--build-arg", f"BASE_IMAGE={lock['debian']['ref']}",
    f"{REPO}/packaging/images/bind9"])

env = jinja_env(os.path.join(REPO, "templates"))
V = {"deploy_base_dir": W, "domain": "lan.test", "install_kea": True, "ip_kea_ddns": DDNS_IP, "ip_bind9": BIND_IP,
     "host_ip": BIND_IP, "image_kea": KEA_IMAGE,
     "service_users": {"kea": {"uid": 915, "gid": 915}, "bind": {"uid": 53, "gid": 53}},
     "dhcp": {"interfaces": ["eth0"], "lease_time": 3600, "options": [{"name": "time-offset", "data": "3600"}],
              "subnets": [{"subnet": SUBNET, "name": "lab", "id": 7, "pools": [f"{P}.27.100 - {P}.27.150"],
                           "routers": f"{P}.27.1"}]}}
V["dhcp"] = normalize_dhcp(V)
V["dhcp_reverse_zones"] = dhcp_reverse_zones(V)
S1 = sh("openssl rand -base64 32").stdout.strip()
S2 = sh("openssl rand -base64 32").stdout.strip()
NEW = "kea-ddns-20261024"
secrets1 = {"kea_ddns_secret": S1}
changed = deploy_kea(V, secrets1, env, 53, 53)
check("Kea's files written: the set of changed files, the two control-socket folders (run-ddns kea's own)",
      changed == {"kea-dhcp4.conf", "kea-dhcp-ddns.conf"} and os.stat(f"{W}/kea/run-ddns").st_uid == 915
      and oct(os.stat(f"{W}/kea/run-ddns").st_mode & 0o777) == "0o750", (changed, os.stat(f"{W}/kea/run-ddns")))
check("written again unchanged: nothing to reload", deploy_kea(V, secrets1, env, 53, 53) == set())

CTX = {**V, "dns": {}, "bind_acls": {"lan": ["any"]}, "tsig_keys": [], "tsig_secrets": {},
       "reverse_zone_names": V["dhcp_reverse_zones"], "reverse_by_hand": {}}


def bind_files(**keys):
    """BIND's keys and zone list from fabric's templates (as an apply renders them), with Kea's key(s) given."""
    ctx = {**CTX, **keys}
    for name in ("named.conf.keys", "named.conf.zones"):
        with open(f"{W}/bind9/config/{name}", "w") as f:
            f.write(env.get_template(f"bind9/config/{name}.j2").render(**ctx))
    sh(f"chown -R 53:53 {W}/bind9")


with open(f"{W}/bind9/config/named.conf", "w") as f:
    f.write('options { directory "/var/cache/bind"; listen-on { any; }; listen-on-v6 { none; }; recursion no; };\n'
            'acl "lan" { any; };\ninclude "/etc/bind/named.conf.keys";\ninclude "/etc/bind/named.conf.zones";\n')
for zone in V["dhcp_reverse_zones"]:
    with open(f"{W}/bind9/data/db.{zone}", "w") as f:
        f.write(env.get_template("bind9/data/reverse-zone.j2").render(**CTX, reverse_zone_name=zone, ptr_records=[]))
bind_files(kea_ddns_secret=S1)


def reload_bind():
    """BIND re-reads its configuration (SIGHUP: what `rndc reconfig` does for fabric's bind9); as rndc's result."""
    res = sh(f"docker kill -s HUP {KR_BIND}", ok=False)
    time.sleep(2)
    return subprocess.CompletedProcess(["reconfig"], res.returncode, res.stdout, res.stderr)


COMPOSE = __import__("yaml").safe_load(env.get_template("kea/docker-compose.yml.j2").render(
    **V, image_debian="debian", packages_lock=pkgs))["services"]
testrun.create_network(NET, SUBNET, f"{P}.27.1")
sh(f"docker run -d --name {KR_BIND} --label {testrun.LABEL} --network {NET} --ip {BIND_IP} --user 53:53 --cap-drop ALL "
   f"-v {W}/bind9/config:/etc/bind:ro -v {W}/bind9/data:/var/lib/bind --tmpfs /var/cache/bind:uid=53,gid=53 "
   f"--tmpfs /run/named:uid=53,gid=53 {BIND_IMAGE}")
sh(f"docker run -d --name {KR_DHCP4} --label {testrun.LABEL} --network {NET} --ip {P}.27.2 --read-only --security-opt no-new-privileges:true "
   f"--cap-drop ALL --cap-add NET_RAW --cap-add NET_BIND_SERVICE --tmpfs /tmp -v {W}/kea/config:/config:ro "
   f"-v {W}/kea/leases:/var/lib/kea -v {W}/kea/run:/run/kea {KEA_IMAGE} "
   f"{shlex.join(COMPOSE['kea-dhcp4']['command'])}")


def start_ddns():
    sh(f"docker run -d --name {KR_DDNS} --label {testrun.LABEL} --network {NET} --ip {DDNS_IP} --user 915:915 --read-only "
       f"--security-opt no-new-privileges:true --cap-drop ALL --tmpfs /tmp -v {W}/kea/run-ddns:/run/kea "
       f"-v {W}/kea/config:/config:ro {KEA_IMAGE} {shlex.join(COMPOSE['kea-ddns']['command'])}")


start_ddns()
up = until(lambda: os.path.exists(f"{W}/kea/run/kea4-ctrl-socket")
           and os.path.exists(f"{W}/kea/run-ddns/kea-ddns-ctrl-socket"))
check("kea-dhcp4 and kea-dhcp-ddns run as their compose file says; both control sockets on the host", up,
      sh(f"docker logs {KR_DDNS}", ok=False).stderr[-600:])
health = COMPOSE["kea-ddns"]["healthcheck"]["test"]
check("kea-ddns's health check (its control socket) passes in its container",
      sh(["docker", "exec", KR_DDNS, *health[1:]], ok=False).returncode == 0, health)
status = kea_command(V, "status-get", daemon="ddns")
check("the host asks kea-dhcp-ddns over its socket (status-get)", "pid" in status, status)


def client(name, mac, hostname):
    cmd = ["udhcpc", "-i", "eth0", "-n", "-q", "-f", "-t", "5", "-s", "/tmp/s", "-O", "timezone",
           "-x", f"hostname:{hostname}"]
    out = sh(["docker", "run", "--name", name, *testrun.labels(), "--network", NET, "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
              "--mac-address", mac, BUSYBOX, "sh", "-c", "printf '#!/bin/sh\\nenv | grep -E \"^timezone=\"\\n' > "
              "/tmp/s; chmod +x /tmp/s; exec " + shlex.join(cmd)], ok=False)
    text = out.stdout + out.stderr
    got = [ln.split("lease of ")[1].split()[0] for ln in text.splitlines() if "lease of " in ln]
    return (got[-1] if got else None), text


ip1, out1 = client(KR_C1, "02:00:00:00:27:11", "one")
check("a client leases, and its name is registered with Kea's key (kea-ddns)", ip1 and until(
      lambda: dig("one.dhcp.lan.test") == ip1, 30), (out1[-300:], sh(f"docker logs {KR_DDNS}", ok=False).stdout[-500:]))

# ---- a changed kea-dhcp4.conf taken without a restart (2.1.10.45)
before = started(KR_DHCP4)
V2 = {**V, "dhcp": normalize_dhcp({**V, "dhcp": {**V["dhcp"], "options": [{"name": "time-offset", "data": "7200"}]}})}
V2["dhcp_reverse_zones"] = V["dhcp_reverse_zones"]
changed = deploy_kea(V2, secrets1, env, 53, 53)
RESTARTS = []
took = reload_kea(V2, changed, restart=lambda unit, container, restart=False: RESTARTS.append(unit))
ip2, out2 = client(KR_C2, "02:00:00:00:27:12", "two")
check("a changed kea-dhcp4.conf: Kea reloads it over its socket, not restarted; its leases kept; the next client "
      "gets the new option", changed == {"kea-dhcp4.conf"} and took == {"reloaded": ["dhcp4"], "restarted": False,
                                                                        "why": ""}
      and started(KR_DHCP4) == before and not RESTARTS and any(x["ip"] == ip1 for x in list_leases(V))
      and "timezone=7200" in out2, (changed, took, out2[-300:]))
good = open(f"{W}/kea/config/kea-dhcp4.conf").read()
with open(f"{W}/kea/config/kea-dhcp4.conf", "w") as f:
    f.write(good.replace('"Dhcp4": {', '"Dhcp4": { "no-such-parameter": 1,', 1))
took = reload_kea(V2, {"kea-dhcp4.conf"}, restart=lambda unit, container, restart=False: RESTARTS.append(unit))
check("a file Kea does not take: Kea restarted instead (reload_kea's fallback), saying why; until then Kea kept "
      "serving its last configuration", took["restarted"] is True and RESTARTS == ["kea"]
      and "Kea refused config-reload" in took["why"] and "no-such-parameter" in took["why"]
      and "pid" in kea_command(V, "status-get"), took)
with open(f"{W}/kea/config/kea-dhcp4.conf", "w") as f:
    f.write(good)
check("the file put right: taken by a reload again", reload_kea(V2, {"kea-dhcp4.conf"})["restarted"] is False)

# ---- kea-ddns over its kept run folder (an upgrade recreates it): the old PID file does not stop it
testrun.remove("container", KR_DDNS)
start_ddns()
check("kea-ddns starts again over the previous container's run folder (its PID file removed first)",
      until(lambda: sh(f"docker inspect -f {{{{.State.Running}}}} {KR_DDNS}", ok=False).stdout.strip() == "true"
            and time.sleep(3) is None and "pid" in (kea_command(V, "status-get", daemon="ddns") or {})),
      sh(f"docker logs {KR_DDNS}", ok=False).stderr[-600:])

# ---- Kea's DNS key replaced (2.1.10.42): BIND knows both, Kea reloaded on the new one, the old one dropped
OLD = {"name": "kea-ddns", "secret": S1, "made": "2025-11-28"}
bind_files(kea_ddns_key=NEW, kea_ddns_secret=S2, kea_ddns_old=OLD)
reload_bind()
check("BIND rendered knowing both keys: an update signed with either is accepted",
      nsupdate("kea-ddns", S1, f"t-old.dhcp.lan.test 60 A {P}.27.201")[0] == 0
      and nsupdate(NEW, S2, f"t-new.dhcp.lan.test 60 A {P}.27.202")[0] == 0
      and dig("t-old.dhcp.lan.test") == f"{P}.27.201" and dig("t-new.dhcp.lan.test") == f"{P}.27.202")
before = started(KR_DDNS)
secrets2 = {"kea_ddns_key": NEW, "kea_ddns_secret": S2, "kea_ddns_old": OLD}
changed = deploy_kea(V2, secrets2, env, 53, 53)
took = reload_kea(V2, changed)
cfg = json.loads("\n".join(ln for ln in open(f"{W}/kea/config/kea-dhcp-ddns.conf").read().splitlines()
                           if not ln.strip().startswith("//")))["DhcpDdns"]
ip3, out3 = client(KR_C3, "02:00:00:00:27:13", "three")
check("Kea on the new key: only kea-dhcp-ddns's file changed, reloaded over its socket (not restarted); a client "
      "registered with the new key", changed == {"kea-dhcp-ddns.conf"} and took["reloaded"] == ["ddns"]
      and started(KR_DDNS) == before and cfg["tsig-keys"][0]["name"] == NEW
      and until(lambda: dig("three.dhcp.lan.test") == ip3, 30),
      (changed, took, sh(f"docker logs {KR_DDNS}", ok=False).stdout[-600:]))
AUDIT, SAVED = [], []
dropped = drop_old_key(V2, {**CTX, "kea_ddns_key": NEW, "kea_ddns_secret": S2, "kea_ddns_old": OLD}, env, OLD,
                       rndc_call=lambda args, timeout=90: reload_bind(), save=lambda u, p: SAVED.append(u),
                       audit=lambda *a: AUDIT.append(a[1]), secrets_path="/nowhere")
code_old, said_old = nsupdate("kea-ddns", S1, f"t-old2.dhcp.lan.test 60 A {P}.27.203")
code_new, said_new = nsupdate(NEW, S2, f"t-new2.dhcp.lan.test 60 A {P}.27.204")
check("the old key dropped (drop_old_key on fabric's templates): BIND refuses it now and accepts the new one; the "
      "secrets lose the old key, audited", dropped == "kea-ddns" and code_old != 0 and dig("t-old2.dhcp.lan.test")
      == "" and code_new == 0 and dig("t-new2.dhcp.lan.test") == f"{P}.27.204"
      and SAVED == [{"kea_ddns_old": None}] and AUDIT == ["KEA_KEY_ROTATE"], (said_old[-300:], said_new[-300:]))
ip4, out4 = client(KR_C4, "02:00:00:00:27:14", "four")
check("after the old key is gone, Kea still registers clients (it signs with the new key only)",
      until(lambda: dig("four.dhcp.lan.test") == ip4, 30), sh(f"docker logs {KR_DDNS}", ok=False).stdout[-600:])
try:
    kea_command({"deploy_base_dir": W + "/nowhere"}, "config-reload", daemon="ddns", timeout=2)
    check("no socket: refused", False)
except ValidationError as e:
    check("a socket that is not there: refused, saying Kea is not answering", "not answering" in str(e), e)

cleanup()
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
