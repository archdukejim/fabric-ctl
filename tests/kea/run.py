#!/usr/bin/env python3
"""Kea 3.0 LTS (optional DHCP, design §5 / 2.1.4.1) on fabric's own image, from
fabric's templates, with real DHCP clients: a client gets a pool address and
its hostname lands in the DHCP subzone (BIND, fabric's zone and key
templates); a reserved MAC gets its fixed address; another client cannot
take over that name (DHCID); the lease list comes over the control socket;
the containers are hardened (two capabilities for DHCP, none for DDNS).

    sudo python3 tests/kea/run.py          (needs Docker, dig, root)
"""
import copy
import json
import os
import shutil
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "tests", "common"))
import test_run as testrun  # noqa: E402
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/kea"
NET, SUBNET = testrun.name("keatest_net"), f"{testrun.PREFIX}.23.0/24"      # per run (manual 3.1.2.6)
KT_DHCP4, KT_DDNS, KT_BIND = testrun.name("kt-dhcp4"), testrun.name("kt-ddns"), testrun.name("kt-bind")
KT_C1, KT_C2, KT_C3, KT_BOOT = (testrun.name(f"kt-{n}") for n in ("c1", "c2", "c3", "boot"))
KEA_IMAGE, BIND_IMAGE = "fabric/kea:" + testrun.name("test"), "fabric/bind9:" + testrun.name("keatest")
BIND_IP, DDNS_IP = f"{testrun.PREFIX}.23.30", f"{testrun.PREFIX}.23.97"
FAILED = 0
sys.path[0:0] = [os.path.join(REPO, "src"), REPO]
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.common.read_packages_lock import read_packages_lock  # noqa: E402
from fabriclib.dhcp.check_kea_config import check_kea_config  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.dhcp.deploy_kea import deploy_kea  # noqa: E402
from fabriclib.dhcp.list_leases import list_leases  # noqa: E402
from fabriclib.dhcp.dhcp_reverse_zones import dhcp_reverse_zones  # noqa: E402
from fabriclib.dhcp.normalize_dhcp import normalize_dhcp  # noqa: E402


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:500]}"))


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


def cleanup():
    testrun.remove("container", KT_DHCP4, KT_DDNS, KT_BIND, KT_C1, KT_C2, KT_C3, KT_BOOT)   # this run's only
    testrun.remove("network", NET)


cleanup()
shutil.rmtree(W, ignore_errors=True)
os.makedirs(f"{W}/bind9/data")
lock, pkgs = read_images_lock(os.path.join(REPO, "config")), read_packages_lock(os.path.join(REPO, "config"))
DEBIAN, BUSYBOX = lock["debian"]["ref"], \
    "busybox:1.37@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"
k = pkgs["kea"]

# ------------------------------------------------------------------ images
build = sh(["docker", "build", "-q", "-t", KEA_IMAGE, "--build-arg", f"BASE_IMAGE={DEBIAN}",
            "--build-arg", f"KEA_VERSION={k['version']}", "--build-arg", f"KEA_REPO={k['repo']}",
            "--build-arg", f"KEA_SUITE={k['suite']}", "--build-arg", f"KEA_KEY_URL={k['key_url']}",
            "--build-arg", f"KEA_KEY_FINGERPRINT={k['key_fingerprint']}", f"{REPO}/packaging/images/kea"], ok=False)
check("Kea image builds from ISC's repository (signing key pinned, exact version)", build.returncode == 0,
      build.stderr[-600:])
bad = sh(["docker", "build", "-q", "--build-arg", f"BASE_IMAGE={DEBIAN}", "--build-arg", f"KEA_VERSION={k['version']}",
          "--build-arg", f"KEA_REPO={k['repo']}", "--build-arg", f"KEA_SUITE={k['suite']}",
          "--build-arg", f"KEA_KEY_URL={k['key_url']}", "--build-arg", "KEA_KEY_FINGERPRINT=" + "0" * 40,
          f"{REPO}/packaging/images/kea"], ok=False)
check("the build refuses a repository key that is not the pinned one", bad.returncode != 0
      and "is not the pinned" in bad.stderr + bad.stdout, bad.stderr[-300:])
version = sh(f"docker run --rm --entrypoint /usr/sbin/kea-dhcp4 {KEA_IMAGE} -V", ok=False).stdout
check("Kea 3.0 LTS inside (the pinned version)", version.startswith("3.0."), version[:80])
sh(["docker", "build", "-q", "-t", BIND_IMAGE, "--build-arg", f"BASE_IMAGE={DEBIAN}",
    f"{REPO}/packaging/images/bind9"])

# ------------------------------------------------------------------ fabric's files
V = {"deploy_base_dir": W, "domain": "lan.test", "install_kea": True, "ip_kea_ddns": DDNS_IP, "ip_bind9": BIND_IP,
     "host_ip": BIND_IP, "service_users": {"kea": {"uid": 915, "gid": 915}}, "image_kea": KEA_IMAGE,
     "dhcp": {"interfaces": ["eth0"], "lease_time": 3600,
              "options": [{"name": "time-offset", "data": "3600"}],
              # network boot for clients that say they are "fabricboot" (option 60): next-server, file, TFTP name
              "client_classes": [{"name": "boot-test", "test": "substring(option[60].hex,0,10) == 'fabricboot'",
                                  "next_server": f"{testrun.PREFIX}.23.30", "boot_file_name": "ipxe.efi",
                                  "options": [{"name": "tftp-server-name", "data": f"{testrun.PREFIX}.23.30"}]}],
              "subnets": [{"subnet": SUBNET, "name": "lab", "vlan": 23, "notes": "the test bridge", "id": 7,
                           "pools": [f"{testrun.PREFIX}.23.100 - {testrun.PREFIX}.23.150"], "routers": f"{testrun.PREFIX}.23.1",
                           "reservations": [{"mac": "02:00:00:00:00:42", "ip": f"{testrun.PREFIX}.23.42",
                                             "hostname": "printer"}]}]}}
V["dhcp"] = normalize_dhcp(V)
V["dhcp_reverse_zones"] = dhcp_reverse_zones(V)          # as check_settings sets it (2.1.10.7)
REV = V["dhcp_reverse_zones"][0]
env = jinja_env(os.path.join(REPO, "templates"))
secret = sh("openssl rand -base64 32").stdout.strip()
check("Kea's configs, lease and socket folders, and the DHCP subzone file written",
      deploy_kea(V, {"kea_ddns_secret": secret}, env, 53, 53) and os.path.exists(f"{W}/bind9/data/db.dhcp.lan.test")
      and oct(os.stat(f"{W}/kea/config/kea-dhcp-ddns.conf").st_mode & 0o777) == "0o640")
cfg4 = open(f"{W}/kea/config/kea-dhcp4.conf").read()
# covers: setting:dhcp +
check("Kea checked them first (kea-dhcp4 -t) and accepted: options, a client class, the subnet's id, name, VLAN",
      check_kea_config(KEA_IMAGE, "kea-dhcp4.conf", cfg4) is True and '"id": 7' in cfg4
      and '"vlan": 23' in cfg4 and '"boot-test"' in cfg4)
bad_v = {**V, "dhcp": normalize_dhcp({**V, "dhcp": {**V["dhcp"], "options": [{"name": "no-such-option", "data": "1"}]}})}
try:
    deploy_kea(bad_v, {"kea_ddns_secret": secret}, env, 53, 53)
    refused = ""
except ValidationError as e:
    refused = str(e)
# covers: setting:dhcp -
check("an option Kea does not know is refused by Kea's own check, and nothing is written",
      "Kea refused" in refused and open(f"{W}/kea/config/kea-dhcp4.conf").read() == cfg4, refused[-300:])
try:                                                  # ip_kea_ddns: Kea's own check refuses what is no address
    deploy_kea({**V, "ip_kea_ddns": f"{testrun.PREFIX}.23.300"}, {"kea_ddns_secret": secret}, env, 53, 53)
    refused = ""
except ValidationError as e:
    refused = str(e)
# covers: setting:ip_kea_ddns -
check("an ip_kea_ddns that is not an address is refused by Kea's own check, and nothing is written",
      "Kea refused" in refused and open(f"{W}/kea/config/kea-dhcp4.conf").read() == cfg4, refused[-300:])
from fabriclib.deploy.check_settings import check_settings  # noqa: E402
try:
    check_settings({"install_kea": True, "domain": "lan.test", "dhcp": {"interfaces": ["eth0"]}})
    refused = ""
except ValidationError as e:
    refused = str(e)
# covers: setting:install_kea -
check("install_kea: true without a subnet to serve is refused before anything is rendered (check_settings)",
      "at least one subnet with a pool" in refused, refused)
os.makedirs(f"{W}/bind9/config", exist_ok=True)
bv = {**V, "dns": {}, "bind_acls": {"lan": ["any"]}, "tsig_keys": [], "tsig_secrets": {}, "kea_ddns_secret": secret,
      "reverse_zone_names": [REV]}
open(f"{W}/bind9/data/db.{REV}", "w").write(env.get_template("bind9/data/reverse-zone.j2").render(
    **bv, reverse_zone_name=REV, ptr_records=[]))
open(f"{W}/bind9/config/named.conf", "w").write(
    'options { directory "/var/cache/bind"; listen-on { any; }; listen-on-v6 { none; }; recursion no; };\n'
    'acl "lan" { any; };\n'
    + env.get_template("bind9/config/named.conf.keys.j2").render(**bv)
    + env.get_template("bind9/config/named.conf.zones.j2").render(**bv))
ddns_zone = open(f"{W}/bind9/data/db.dhcp.lan.test").read()
check("a new DHCP subzone keeps 'no such name' 30 s (its SOA minimum, 2.1.4.9)",
      "604800 30)" in ddns_zone, ddns_zone)
# an older install's subzone, made with 300 s: the apply after the upgrade sets 30 s under the running BIND (below)
open(f"{W}/bind9/data/db.dhcp.lan.test", "w").write(ddns_zone.replace("604800 30)", "604800 300)"))
open(f"{W}/bind9/config/rndc.key", "w").write(env.get_template("bind9/config/rndc.key.j2").render(
    rndc_secret=sh("openssl rand -base64 32").stdout.strip()))
sh(f"chown -R 53:53 {W}/bind9/data {W}/bind9/config/rndc.key")

# ------------------------------------------------------------------ containers
testrun.create_network(NET, SUBNET, f"{testrun.PREFIX}.23.1")
sh(f"docker run -d --name {KT_BIND} --label {testrun.LABEL} --network {NET} --ip {BIND_IP} --user 53:53 --cap-drop ALL "
   f"-v {W}/bind9/config:/etc/bind:ro -v {W}/bind9/data:/var/lib/bind --tmpfs /var/cache/bind:uid=53,gid=53 "
   f"--tmpfs /run/named:uid=53,gid=53 {BIND_IMAGE}")
# production runs kea-dhcp4 in the host network; here it serves the test bridge's eth0,
# with the command from fabric's compose template
import shlex  # noqa: E402
import yaml  # noqa: E402
COMPOSE = yaml.safe_load(env.get_template("kea/docker-compose.yml.j2").render(
    **V, image_debian="debian", kea_mem_limit="96m", packages_lock=pkgs))["services"]
KEA_CMD, KEA_MEM = COMPOSE["kea-dhcp4"]["command"], COMPOSE["kea-dhcp4"]["mem_limit"]


def start_dhcp4():
    sh(f"docker run -d --name {KT_DHCP4} --label {testrun.LABEL} --network {NET} --ip {testrun.PREFIX}.23.2 --read-only --memory {KEA_MEM} "
       f"--security-opt no-new-privileges:true --cap-drop ALL --cap-add NET_RAW --cap-add NET_BIND_SERVICE --tmpfs /tmp "
       f"-v {W}/kea/config:/config:ro -v {W}/kea/leases:/var/lib/kea -v {W}/kea/run:/run/kea "
       f"{KEA_IMAGE} {shlex.join(KEA_CMD)}")


start_dhcp4()
sh(f"docker run -d --name {KT_DDNS} --label {testrun.LABEL} --network {NET} --ip {DDNS_IP} --user 915:915 --read-only "
   f"--security-opt no-new-privileges:true --cap-drop ALL --tmpfs /tmp --tmpfs /run/kea:uid=915,gid=915 "
   f"-v {W}/kea/config:/config:ro {KEA_IMAGE} /usr/sbin/kea-dhcp-ddns -c /config/kea-dhcp-ddns.conf")
check("kea-dhcp4 runs and creates its control socket", until(lambda: os.path.exists(f"{W}/kea/run/kea4-ctrl-socket")),
      sh(f"docker logs {KT_DHCP4}", ok=False).stdout[-800:] + sh(f"docker logs {KT_DHCP4}", ok=False).stderr[-800:])


def client(name, mac=None, hostname=None, vendor=None):
    """One DHCP client run; its script prints what it was given (udhcpc's environment: tftp, bootfile, siaddr…)."""
    args = ["docker", "run", "--name", name, *testrun.labels(), "--network", NET, "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW"]
    if mac:
        args += ["--mac-address", mac]
    cmd = ["udhcpc", "-i", "eth0", "-n", "-q", "-f", "-t", "5", "-s", "/tmp/s", "-O", "tftp", "-O", "timezone"]
    if hostname:
        cmd += ["-x", f"hostname:{hostname}"]
    if vendor:
        cmd += ["-V", vendor]
    args += [BUSYBOX, "sh", "-c", "printf '#!/bin/sh\nenv | grep -E \"^(tftp|timezone|siaddr|boot_file)=\"\n' > /tmp/s; "
             "chmod +x /tmp/s; exec " + shlex.join(cmd)]
    out = sh(args, ok=False)
    text = out.stdout + out.stderr
    got = [ln.split("lease of ")[1].split()[0] for ln in text.splitlines() if "lease of " in ln]
    return got[-1] if got else None, text


ip1, out1 = client(KT_C1, "02:00:00:00:00:11", "laptop1")
check("a client gets an address from the pool", ip1 is not None and ip1.startswith(f"{testrun.PREFIX}.23.1"), out1[-400:])


def dig(name):
    return sh(["dig", "+short", f"@{BIND_IP}", name], ok=False).stdout.strip()


check("its hostname is registered in the DHCP subzone (Kea DDNS -> BIND, kea-ddns key)",
      until(lambda: dig("laptop1.dhcp.lan.test") == ip1, 30),
      (dig("laptop1.dhcp.lan.test"), sh(f"docker logs {KT_DDNS}", ok=False).stdout[-600:]))
cfg_ddns = open(f"{W}/kea/config/kea-dhcp-ddns.conf").read()
# covers: setting:ip_kea_ddns +
check("ip_kea_ddns is where kea-ddns runs (compose) and listens, and where kea-dhcp4 sends its updates",
      COMPOSE["kea-ddns"]["networks"]["fabric_net"]["ipv4_address"] == DDNS_IP
      and f'"ip-address": "{DDNS_IP}"' in cfg_ddns and f'"server-ip": "{DDNS_IP}"' in cfg4
      and dig("laptop1.dhcp.lan.test") == ip1, (COMPOSE["kea-ddns"]["networks"], cfg_ddns[:300]))
check("every client gets the global option (time-offset 3600 s), no boot settings",
      "timezone=3600" in out1 and "tftp=" not in out1, out1[-400:])
ipb, outb = client(KT_BOOT, "02:00:00:00:00:31", vendor="fabricboot-x86")
check("a client in the boot class gets next-server, the boot file and the TFTP server option",
      ipb is not None and f"siaddr={testrun.PREFIX}.23.30" in outb and "boot_file=ipxe.efi" in outb
      and f"tftp={testrun.PREFIX}.23.30" in outb, outb[-500:])
ip2, out2 = client(KT_C2, "02:00:00:00:00:42")
check("a reserved MAC gets its fixed address", ip2 == f"{testrun.PREFIX}.23.42", out2[-400:])
check(f"the lease's PTR is registered too, in fabric's reverse zone {REV} (2.1.10.7)",
      until(lambda: sh(["dig", "+short", f"@{BIND_IP}", "-x", ip1], ok=False).stdout.strip()
            == "laptop1.dhcp.lan.test.", 30), (sh(["dig", "+short", f"@{BIND_IP}", "-x", ip1], ok=False).stdout,
                                               sh(f"docker logs {KT_DDNS}", ok=False).stdout[-600:]))
ip3, out3 = client(KT_C3, "02:00:00:00:00:13", "laptop1")
time.sleep(3)
check("another client asking for the same name cannot take it over (DHCID)", ip3 and ip3 != ip1
      and dig("laptop1.dhcp.lan.test") == ip1, (ip3, dig("laptop1.dhcp.lan.test")))
leases = list_leases(V)
check("lease list over the control socket shows the clients", any(lease["ip"] == ip1 and lease["hostname"].startswith("laptop1")
      for lease in leases) and any(lease["ip"] == f"{testrun.PREFIX}.23.42" for lease in leases), leases)
evil = sh(f"printf 'server {BIND_IP}\\nzone lan.test\\nupdate add evil.lan.test 60 A 1.2.3.4\\nsend\\n' "
          f"| nsupdate -y hmac-sha256:kea-ddns:{secret} 2>&1", ok=False).stdout
check("the key may not touch anything but the DHCP subzone", "REFUSED" in evil or "NOTAUTH" in evil, evil[-300:])
evil_rev = sh(f"printf 'server {BIND_IP}\\nzone {REV}\\nupdate add 9.{REV} 60 TXT evil\\nsend\\n' "
              f"| nsupdate -y hmac-sha256:kea-ddns:{secret} 2>&1", ok=False).stdout
check("in the reverse zone the key may write PTR and DHCID only (a TXT refused)", "REFUSED" in evil_rev, evil_rev[-300:])

# the DHCP subzone of an older install (300 s) given 30 s by the next apply, under the running BIND (2.1.4.9)
from fabriclib.dhcp.ensure_ddns_zone import ensure_ddns_zone  # noqa: E402


def bind_rndc(args, timeout=15):
    return subprocess.run(["docker", "exec", KT_BIND, "rndc", *args], capture_output=True, text=True, timeout=timeout)


def soa_minimum():
    return (sh(["dig", "+short", f"@{BIND_IP}", "dhcp.lan.test", "SOA"], ok=False).stdout.split() or ["?"])[-1]


serial0 = (sh(["dig", "+short", f"@{BIND_IP}", "dhcp.lan.test", "SOA"], ok=False).stdout.split() or ["", "", "0"])[2]
check("an older install's DHCP subzone answers with a 300 s minimum, laptop1 registered in its journal",
      soa_minimum() == "300" and dig("laptop1.dhcp.lan.test") == ip1, (soa_minimum(), dig("laptop1.dhcp.lan.test")))
created = ensure_ddns_zone(V, 53, 53, call=bind_rndc)
serial1 = (sh(["dig", "+short", f"@{BIND_IP}", "dhcp.lan.test", "SOA"], ok=False).stdout.split() or ["", "", "0"])[2]
check("the apply sets 30 s under the running BIND (frozen, edited, thawed): served at once with a higher serial, "
      "laptop1's registration kept, the file not made again",
      not created and soa_minimum() == "30" and int(serial1) > int(serial0) and dig("laptop1.dhcp.lan.test") == ip1,
      (created, soa_minimum(), serial0, serial1, dig("laptop1.dhcp.lan.test")))
after = sh(f"printf 'server {BIND_IP}\\nzone dhcp.lan.test\\nupdate add late.dhcp.lan.test 60 A 10.1.2.3\\nsend\\n' "
           f"| nsupdate -y hmac-sha256:kea-ddns:{secret} 2>&1", ok=False)
check("the zone takes DHCP's updates again after it (thawed)",
      after.returncode == 0 and dig("late.dhcp.lan.test") == "10.1.2.3", after.stdout[-300:])


def no_rndc(args, timeout=15):
    raise AssertionError(f"rndc asked: {args}")


check("a subzone that already has 30 s is left alone (rndc not asked)",
      ensure_ddns_zone(V, 53, 53, call=no_rndc) is False and soa_minimum() == "30")


def leases_or_none():
    try:
        return list_leases(V)
    except Exception:
        return []


# a new container over the same run folder (restart, upgrade): the old PID file must not stop it
testrun.remove("container", KT_DHCP4)
start_dhcp4()
check("kea-dhcp4 starts again over the previous container's run folder; leases kept",
      until(lambda: sh(f"docker inspect -f {{{{.State.Running}}}} {KT_DHCP4}", ok=False).stdout.strip() == "true"
            and os.path.exists(f"{W}/kea/run/kea4-ctrl-socket") and time.sleep(3) is None
            and sh(f"docker inspect -f {{{{.State.Running}}}} {KT_DHCP4}", ok=False).stdout.strip() == "true"
            and any(lease["ip"] == ip1 for lease in leases_or_none())),
      sh(f"docker logs {KT_DHCP4}", ok=False).stderr[-600:])

insp = {c: json.loads(sh(f"docker inspect {c}").stdout)[0] for c in (KT_DHCP4, KT_DDNS)}
h4, hd = insp[KT_DHCP4]["HostConfig"], insp[KT_DDNS]["HostConfig"]
check("kea-dhcp4: only NET_RAW + NET_BIND_SERVICE, read-only, no-new-privileges",
      sorted(c.replace("CAP_", "") for c in h4.get("CapAdd") or []) == ["NET_BIND_SERVICE", "NET_RAW"]
      and h4["CapDrop"] == ["ALL"]
      and h4["ReadonlyRootfs"] and "no-new-privileges:true" in h4["SecurityOpt"], h4.get("CapAdd"))
# covers: setting:kea_mem_limit +
check("kea_mem_limit is both Kea services' memory limit, and kea-dhcp4 runs under it",
      KEA_MEM == "96m" and COMPOSE["kea-ddns"]["mem_limit"] == "96m" and h4["Memory"] == 96 * 1024 * 1024,
      (KEA_MEM, h4.get("Memory")))
check("kea-ddns: uid 915, no capabilities, read-only",
      insp[KT_DDNS]["Config"]["User"] == "915:915" and not hd.get("CapAdd") and hd["ReadonlyRootfs"])


# ------------------------------------------------------------------ commands (manual 1.10.2.5)
# The vars file is a scratch copy: edit_dhcp's load/save/lock/audit are pointed at it.
import contextlib  # noqa: E402
from fabriclib.dhcp.common import edit_dhcp as ed  # noqa: E402
from fabriclib.dhcp.add_subnet import add_subnet  # noqa: E402
from fabriclib.dhcp.update_subnet import update_subnet  # noqa: E402
from fabriclib.dhcp.remove_subnet import remove_subnet  # noqa: E402
from fabriclib.dhcp.set_option import set_option  # noqa: E402
from fabriclib.dhcp.unset_option import unset_option  # noqa: E402
from fabriclib.dhcp.add_client_class import add_client_class  # noqa: E402
from fabriclib.dhcp.remove_client_class import remove_client_class  # noqa: E402
STORE = {"vars": {"install_kea": True, "domain": "lan.test", "host_ip": BIND_IP, "ip_kea_ddns": DDNS_IP,
                  "image_kea": KEA_IMAGE, "dhcp": {"interfaces": ["eth0"], "subnets": [
    {"subnet": "10.1.0.0/24", "pools": ["10.1.0.100 - 10.1.0.150"]},
    {"subnet": "10.2.0.0/24", "pools": ["10.2.0.100 - 10.2.0.150"]},
    {"subnet": "10.3.0.0/24", "pools": ["10.3.0.100 - 10.3.0.150"]}]}}}
AUDIT = []
ed.load_vars = lambda: copy.deepcopy(STORE["vars"])
ed.save_vars = lambda data: STORE.update(vars=copy.deepcopy(data))
ed.vars_lock = contextlib.nullcontext
ed.write_audit = lambda actor, event, detail, source: AUDIT.append(event)


def refused(fn):
    try:
        fn()
    except ValidationError as e:
        return str(e)
    return ""


def subnets():
    return {x["subnet"]: x for x in STORE["vars"]["dhcp"]["subnets"]}


new = add_subnet("root", "10.4.0.0/24", "iot", vlan=40, router="10.4.0.1", pools=["10.4.0.100 - 10.4.0.200"],
                 notes="IoT: internet only")
check("add-subnet: the new subnet gets the next id; existing ones keep the ids their position gave them",
      new["id"] == 4 and [x["id"] for x in STORE["vars"]["dhcp"]["subnets"]] == [1, 2, 3, 4], subnets())
remove_subnet("root", "10.2.0.0/24", [])
check("remove-subnet: the others keep their ids (their leases stay theirs)",
      {k: x["id"] for k, x in subnets().items()} == {"10.1.0.0/24": 1, "10.3.0.0/24": 3, "10.4.0.0/24": 4})
check("remove-subnet with active leases in it is refused without --force; Kea not answering needs --force too",
      "active lease" in refused(lambda: remove_subnet("root", "iot", [{"ip": "10.4.0.120", "state": "active"}]))
      and "--force" in refused(lambda: remove_subnet("root", "iot", None)))
check("a name or VLAN already in use, an overlapping pool, and a missing subnet are refused",
      "unique" in refused(lambda: add_subnet("root", "10.5.0.0/24", "iot"))
      and "unique" in refused(lambda: add_subnet("root", "10.5.0.0/24", "cams", vlan=40))
      and "overlaps" in refused(lambda: update_subnet("root", "iot", add_pools=["10.4.0.150 - 10.4.0.220"]))
      and "no DHCP subnet" in refused(lambda: update_subnet("root", "nope", notes="x")))
update_subnet("root", "iot", vlan=41, notes=None, remove_pools=["10.4.0.100 - 10.4.0.200"],
              add_pools=["10.4.0.50 - 10.4.0.60"])
s4 = subnets()["10.4.0.0/24"]
check("set-subnet: VLAN changed, notes cleared, pools replaced; the id stays",
      s4["vlan"] == 41 and "notes" not in s4 and s4["pools"] == ["10.4.0.50 - 10.4.0.60"] and s4["id"] == 4, s4)
set_option("root", "ntp-servers", "10.4.0.1", subnet="iot")
set_option("root", "66", "10.1.0.30")
add_client_class("root", "pxe-uefi", "option[93].hex == 0x0007", next_server="10.1.0.30", boot_file_name="ipxe.efi")
set_option("root", "boot-file-name", "ipxe.efi", client_class="pxe-uefi")
d = STORE["vars"]["dhcp"]
check("options at every level and a client class are saved",
      d["options"] == [{"code": 66, "data": "10.1.0.30"}] and s4 is not None
      and subnets()["10.4.0.0/24"]["options"] == [{"name": "ntp-servers", "data": "10.4.0.1"}]
      and d["client_classes"][0]["options"] == [{"name": "boot-file-name", "data": "ipxe.efi"}], d)
cfg = env.get_template("kea/kea-dhcp4.conf.j2").render(**{**V, "dhcp": normalize_dhcp({**V, "dhcp": {**d, "interfaces": ["eth0"]}})})
check("Kea accepts what the commands made", check_kea_config(KEA_IMAGE, "kea-dhcp4.conf", cfg) is True)
before = copy.deepcopy(STORE["vars"])
msg = refused(lambda: set_option("root", "no-such-option", "1", subnet="iot"))
check("a command Kea would refuse is refused before anything is saved (the next apply stays clean)",
      "Kea refused" in msg and STORE["vars"] == before, msg[-300:])
unset_option("root", "66")
remove_client_class("root", "pxe-uefi")
check("option unset and class removal; unsetting an option that is not set is refused",
      "options" not in STORE["vars"]["dhcp"] and "client_classes" not in STORE["vars"]["dhcp"]
      and "not set" in refused(lambda: unset_option("root", "66")))
check("every change was audited", AUDIT.count("DHCP_SUBNET_ADD") == 1 and "DHCP_CLASS_REMOVE" in AUDIT
      and "DHCP_OPTION_SET" in AUDIT, AUDIT)

# ---- fabricctl dhcp … as the CLI routes it (run_dhcp_command), on the same scratch STORE; changes with --no-apply
import io  # noqa: E402
from contextlib import redirect_stderr, redirect_stdout  # noqa: E402
import fabriclib.dhcp.add_reservation as m_reserve  # noqa: E402
import fabriclib.dhcp.remove_reservation as m_unreserve  # noqa: E402
import fabriclib.dhcp.set_dhcp_on as m_on  # noqa: E402
from fabriclib.dhcp.run_dhcp_command import run_dhcp_command  # noqa: E402
for m in (m_reserve, m_unreserve, m_on):            # these read and write vars.yaml themselves, not via edit_dhcp
    m.load_vars, m.save_vars, m.vars_lock, m.write_audit = ed.load_vars, ed.save_vars, ed.vars_lock, ed.write_audit


def dhcp_cli(v, *argv):
    """fabricctl dhcp …: its exit status, stdout and stderr."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = run_dhcp_command(v, list(argv))
    return code, out.getvalue(), err.getvalue()


def refused_cli(v, *argv):
    """A refused change: (exit status, stderr, STORE unchanged)."""
    before = copy.deepcopy(STORE["vars"])
    code, _, err = dhcp_cli(v, *argv)
    return code, err, STORE["vars"] == before


NO_KEA = {**V, "deploy_base_dir": f"{W}/no-such-install"}
code, out, err = dhcp_cli(V)
# covers: cli:dhcp +
check("fabricctl dhcp (no subcommand) shows the status: the subnet, its name and VLAN, the reservation, the class",
      code == 0 and f"{testrun.PREFIX}.23.0/24" in out and "lab" in out and "VLAN 23" in out and "printer" in out
      and "class boot-test" in out, (code, out, err))
code, err, same = refused_cli(V, "add-subnet", "10.9.0.0/24", "--no-apply", "--name")
code2, _, err2 = dhcp_cli(V, "frobnicate")
# covers: cli:dhcp -
check("fabricctl dhcp refuses a flag without its value (saying which) and an unknown subcommand (usage)",
      code == 1 and "error: --name needs a value" in err and same
      and code2 == 2 and "usage: fabricctl dhcp" in err2, (code, err, code2, err2[:200]))
code, out, err = dhcp_cli(V, "status", "extra")
# covers: cli:dhcp.status -
check("dhcp status with an argument it does not take: usage on stderr, exit 2",
      code == 2 and "usage: fabricctl dhcp status" in err and not out, (code, out, err[:200]))
code, out, err = dhcp_cli(NO_KEA, "leases")
# covers: cli:dhcp.leases -
check("dhcp leases when Kea is not answering: refused with why, exit 1",
      code == 1 and "error: Kea is not answering" in err and not out, (code, out, err))

code, out, err = dhcp_cli(V, "reserve", "02:00:00:00:00:77", "10.1.0.20", "cam1", "--no-apply")
r10 = subnets()["10.1.0.0/24"].get("reservations") or []
check("dhcp reserve: saved in the subnet holding the address; recorded, not applied (--no-apply)",
      code == 0 and "reserved 10.1.0.20 for 02:00:00:00:00:77" in out and "recorded" in out
      and r10 == [{"mac": "02:00:00:00:00:77", "ip": "10.1.0.20", "hostname": "cam1"}], (code, out, err, r10))
code, err, same = refused_cli(V, "reserve", "02:00:00:00:00:78", "10.9.0.5", "--no-apply")
code2, err2, same2 = refused_cli(V, "reserve", "02:00:00:00:00:78", "10.1.0.120", "--no-apply")
code3, err3, same3 = refused_cli(V, "reserve", "02:00:00:00:00:78", "10.1.0.20", "--no-apply")
# covers: cli:dhcp.reserve -
check("dhcp reserve refuses an address in no subnet, one inside a pool, one already reserved; nothing saved",
      (code, code2, code3) == (1, 1, 1) and "10.9.0.5 is in none of the DHCP subnets" in err
      and "outside its pools" in err2 and "must be unique" in err3 and same and same2 and same3, (err, err2, err3))
code, out, err = dhcp_cli(V, "unreserve", "02-00-00-00-00-77", "--no-apply")
# covers: cli:dhcp.unreserve +
check("dhcp unreserve (any MAC spelling): the reservation is gone",
      code == 0 and "reservation for 02-00-00-00-00-77 removed" in out
      and not subnets()["10.1.0.0/24"].get("reservations"), (code, out, err, subnets()["10.1.0.0/24"]))
code, err, same = refused_cli(V, "unreserve", "02:00:00:00:00:77", "--no-apply")
# covers: cli:dhcp.unreserve -
check("dhcp unreserve of a MAC with no reservation is refused; nothing saved",
      code == 1 and "error: no reservation for 02:00:00:00:00:77" in err and same, (code, err))

code, err, same = refused_cli(V, "add-subnet", "10.5.0.0/24", "--name", "iot", "--no-apply")
code2, err2, same2 = refused_cli(V, "add-subnet", "10.5.0.0/24", "--name", "cams", "--vlan", "abc", "--no-apply")
code3, err3, same3 = refused_cli(V, "add-subnet", "10.5.0.0/24", "--name", "cams", "--router", "10.6.0.1",
                                 "--no-apply")
# covers: cli:dhcp.add-subnet -
check("dhcp add-subnet refuses a name in use, a VLAN that is no number, a router outside it; nothing saved",
      (code, code2, code3) == (1, 1, 1) and "unique" in err and "--vlan abc: a number from 1 to 4094" in err2
      and "router 10.6.0.1 is outside the subnet" in err3 and same and same2 and same3, (err, err2, err3))
code, out, err = dhcp_cli(V, "set-subnet", "iot", "--notes", "door cameras", "--vlan", "none", "--router", "10.4.0.1",
                          "--add-pool", "10.4.0.70 - 10.4.0.80", "--no-apply")
s4 = subnets()["10.4.0.0/24"]
# covers: cli:dhcp.set-subnet +
check("dhcp set-subnet: notes set, VLAN cleared, router set, a pool added; the id stays; Kea accepted it",
      code == 0 and "subnet 10.4.0.0/24 changed" in out and "recorded" in out and s4["notes"] == "door cameras"
      and "vlan" not in s4 and s4["routers"] == "10.4.0.1" and s4["id"] == 4
      and [p.replace(" ", "") for p in s4["pools"]] == ["10.4.0.50-10.4.0.60", "10.4.0.70-10.4.0.80"],
      (code, out, err, s4))
code, err, same = refused_cli(V, "set-subnet", "iot", "--router", "10.9.9.9", "--no-apply")
code2, err2, same2 = refused_cli(V, "set-subnet", "nope", "--notes", "x", "--no-apply")
code3, err3, same3 = refused_cli(V, "set-subnet", "iot", "--remove-pool", "10.4.0.1 - 10.4.0.2", "--no-apply")
# covers: cli:dhcp.set-subnet -
check("dhcp set-subnet refuses a router outside the subnet, a subnet that does not exist, removing a pool it "
      "lacks; nothing saved", (code, code2, code3) == (1, 1, 1) and "outside the subnet" in err
      and "no DHCP subnet 'nope'" in err2 and "has no pool 10.4.0.1 - 10.4.0.2" in err3
      and same and same2 and same3, (err, err2, err3))
code, err, same = refused_cli(NO_KEA, "remove-subnet", "iot", "--no-apply")
code2, err2, same2 = refused_cli(V, "remove-subnet", "nope", "--no-apply")
# covers: cli:dhcp.remove-subnet -
check("dhcp remove-subnet refuses while Kea's leases cannot be read (needs --force) and a subnet that does not "
      "exist; nothing saved", code == 1 and "--force" in err and code2 == 1 and "no DHCP subnet 'nope'" in err2
      and same and same2 and "10.4.0.0/24" in subnets(), (err, err2))
code, err, same = refused_cli(V, "class", "remove", "nosuch", "--no-apply")
code2, err2, same2 = refused_cli(V, "class", "add", "broken", "--test", "option[93].hex ==", "--no-apply")
code3, _, err3 = dhcp_cli(V, "class", "add", "notest", "--no-apply")
# covers: cli:dhcp.class -
check("dhcp class refuses removing a class that does not exist, an expression Kea cannot parse (Kea's own check), "
      "and add without --test (usage); nothing saved", code == 1 and "no client class 'nosuch'" in err
      and code2 == 1 and "Kea refused" in err2 and same and same2 and code3 == 2 and "usage:" in err3
      and "client_classes" not in STORE["vars"]["dhcp"], (err, err2[-300:], code3))

code, err, same = refused_cli(V, "on", "--no-apply")
check("dhcp on while it is on is refused; nothing saved", code == 1 and "DHCP is already on" in err and same, err)
code, out, err = dhcp_cli(V, "off", "--no-apply")
# covers: cli:dhcp.off +
check("dhcp off: install_kea false, the subnets kept for the next on",
      code == 0 and "DHCP off (its settings and leases kept)" in out and STORE["vars"]["install_kea"] is False
      and "10.4.0.0/24" in subnets() and "DHCP_OFF" in AUDIT, (code, out, err))
code, err, same = refused_cli(V, "off", "--no-apply")
# covers: cli:dhcp.off -
check("dhcp off while it is off is refused; nothing saved", code == 1 and "error: DHCP is already off" in err and same,
      err)

cleanup()
print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
