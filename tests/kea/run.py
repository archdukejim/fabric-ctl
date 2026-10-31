#!/usr/bin/env python3
"""Kea 3.0 LTS (optional DHCP, design §5 / 2.1.4.1) on fabric's own image, from
fabric's templates, with real DHCP clients: a client gets a pool address and
its hostname lands in the DHCP subzone (BIND, fabric's zone and key
templates); a reserved MAC gets its fixed address; another client cannot
take over that name (DHCID); the lease list comes over the control socket;
the containers are hardened (two capabilities for DHCP, none for DDNS); the address
plan's DHCP options and netboot presets (2.1.10.23, 2.1.10.25): Kea takes the rendered
classes, BIOS, UEFI, iPXE and HTTP boot clients each get their own boot file, and a
reservation's options and preset win over its subnet's, its subnet's over the site's.

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
P = testrun.PREFIX                  # this run's 10.<n>; names <base>-<run id> (manual 3.1.2.6)
KT_DHCP4, KT_DDNS, KT_BIND, KT_C1, KT_C2, KT_C3, KT_C4, KT_BOOT, KT_NB1, KT_NB2, KT_NB3, KT_NB4, KT_NB5, KT_NB6 = (testrun.name(f"kt-{n}") for n in ("dhcp4", "ddns", "bind", "c1", "c2", "c3", "c4", "boot", "nb1", "nb2", "nb3", "nb4", "nb5", "nb6"))
ALL = (KT_DHCP4, KT_DDNS, KT_BIND, KT_C1, KT_C2, KT_C3, KT_C4, KT_BOOT, KT_NB1, KT_NB2, KT_NB3, KT_NB4, KT_NB5, KT_NB6)
BIND_IMAGE = "fabric/bind9:" + testrun.name("keatest")
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/kea"
NET, SUBNET = testrun.name("keatest_net"), f"{P}.23.0/24"
BIND_IP, DDNS_IP = f"{P}.23.30", f"{P}.23.97"
FAILED = 0
sys.path[0:0] = [os.path.join(REPO, "src"), REPO]
from tests.common.kea_image import TAG as KEA_IMAGE, build_kea_image  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.common.read_packages_lock import read_packages_lock  # noqa: E402
from fabriclib.dhcp.check_kea_config import check_kea_config  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.dhcp.deploy_kea import deploy_kea  # noqa: E402
from fabriclib.dhcp.list_leases import list_leases  # noqa: E402
from fabriclib.dhcp.dhcp_reverse_zones import dhcp_reverse_zones  # noqa: E402
from fabriclib.dhcp.normalize_dhcp import normalize_dhcp  # noqa: E402
from fabriclib.ipam.plan_to_dhcp import plan_to_dhcp  # noqa: E402


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
    testrun.remove("container", *ALL)            # this run's only
    testrun.remove("network", NET)


cleanup()
shutil.rmtree(W, ignore_errors=True)
os.makedirs(f"{W}/bind9/data")
lock, pkgs = read_images_lock(os.path.join(REPO, "config")), read_packages_lock(os.path.join(REPO, "config"))
DEBIAN, BUSYBOX = lock["debian"]["ref"], \
    "busybox:1.37@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"
k = pkgs["kea"]

# ------------------------------------------------------------------ images
build = build_kea_image()
check("Kea image builds from ISC's repository (signing key pinned, exact version)", build.returncode == 0,
      build.stderr[-600:])
installed = sh(["docker", "run", "--rm", "--entrypoint", "dpkg-query", KEA_IMAGE, "-W", "-f",
                "${db:Status-Abbrev} ${Package} ${Version}\\n", "isc-kea-*"], ok=False).stdout.split("\n")
installed = dict(line.split()[1:3] for line in installed if line.startswith("ii "))   # installed ones only
# a newer ISC release in the repository is not taken: isc-kea-common left to apt broke the build (2.3.1.32)
check("every isc-kea package in the image is the pinned version, isc-kea-common included",
      "isc-kea-common" in installed and set(installed.values()) == {k["version"]}, installed)
bad = build_kea_image(tag=None, fingerprint="0" * 40)
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
                                  "next_server": f"{P}.23.30", "boot_file_name": "ipxe.efi",
                                  "options": [{"name": "tftp-server-name", "data": f"{P}.23.30"}]}],
              "subnets": [{"subnet": SUBNET, "name": "lab", "vlan": 23, "notes": "the test bridge", "id": 7,
                           "pools": [f"{P}.23.100 - {P}.23.150"], "routers": f"{P}.23.1",
                           "reservations": [{"mac": "02:00:00:00:00:42", "ip": f"{P}.23.42",
                                             "hostname": "printer"},
                                            # its names are set by hand: DHCP never registers them (2.1.10.20)
                                            {"mac": "02:00:00:00:00:44", "ip": f"{P}.23.44",
                                             "hostname": "cam3", "ddns": False}]}]}}
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
check("Kea checked them first (kea-dhcp4 -t) and accepted: options, a client class, the subnet's id, name, VLAN, "
      "the reservation whose names are set by hand in SKIP_DDNS with the ddns-tuning hook (2.1.10.20)",
      check_kea_config(KEA_IMAGE, "kea-dhcp4.conf", cfg4) is True and '"id": 7' in cfg4
      and "libdhcp_ddns_tuning.so" in cfg4 and '"SKIP_DDNS"' in cfg4.split(f'"{P}.23.44"')[1].split("}")[0]
      and '"SKIP_DDNS"' not in cfg4.split(f'"{P}.23.42"')[1].split("}")[0]
      and '"vlan": 23' in cfg4 and '"boot-test"' in cfg4)
# why the file goes in on stdin: fabric-agent (every console apply) runs with a private /tmp, which the Docker daemon
# cannot see; a mounted temp folder made Kea refuse every console apply that changed its file (2.3.10.11.16)
priv = subprocess.run(["unshare", "--mount", "--propagation", "private", "sh", "-c",
                       'mount -t tmpfs none /tmp && exec "$0" -c "$1"', sys.executable,
                       f"import sys; sys.path[0:0] = [{os.path.join(REPO, 'src')!r}]; "
                       "from fabriclib.dhcp.check_kea_config import check_kea_config; "
                       f"print(check_kea_config('{KEA_IMAGE}', 'kea-dhcp4.conf', sys.stdin.read()))"],
                      input=cfg4, capture_output=True, text=True, timeout=120)
check("Kea's check works from a process with a private /tmp, as fabric-agent runs (the console's applies)",
      priv.stdout.strip() == "True", priv.stdout + priv.stderr)
bad_v = {**V, "dhcp": normalize_dhcp({**V, "dhcp": {**V["dhcp"], "options": [{"name": "no-such-option", "data": "1"}]}})}
try:
    deploy_kea(bad_v, {"kea_ddns_secret": secret}, env, 53, 53)
    refused = ""
except ValidationError as e:
    refused = str(e)
# covers: setting:dhcp -
check("an option Kea does not know is refused by Kea's own check, and nothing is written",
      "Kea refused" in refused and open(f"{W}/kea/config/kea-dhcp4.conf").read() == cfg4, refused[-300:])
# the address manager (1.10.4.14): Kea rendered from a site's plan; a reservation inside a dhcp range (1.10.4.3.2)
PLAN = {"vlans": [{"id": 23, "name": "lab", "access": "full"}, {"id": 24, "name": "guests", "access": "guest"}],
        "subnets": [{"name": "lab", "cidr": SUBNET, "vlan": 23, "gateway": f"{P}.23.1", "dhcp": True, "id": 7,
                     "relay": "", "notes": "", "allow_overlap": "", "options": [{"name": "time-offset", "data": "60"}],
                     "ranges": [{"kind": "dhcp", "first": f"{P}.23.100", "last": f"{P}.23.150"}],
                     "addresses": [{"ip": f"{P}.23.120", "kind": "reservation", "name": "inpool",
                                    "mac": "02:00:00:00:00:43", "dns": True,
                                    "options": [{"name": "boot-file-name", "data": "x.efi"}]},
                                   {"ip": f"{P}.23.9", "kind": "static", "name": "nas", "mac": "", "dns": True,
                                    "options": []}]},
                    {"name": "guests", "cidr": f"{P}.24.0/24", "vlan": 24, "gateway": f"{P}.24.1", "dhcp": True,
                     "id": 8, "relay": "", "notes": "", "allow_overlap": "", "options": [],
                     "ranges": [{"kind": "dhcp", "first": f"{P}.24.100", "last": f"{P}.24.200"}],
                     "addresses": []},
                    {"name": "lab-2", "cidr": f"{P}.25.0/24", "vlan": 23, "gateway": f"{P}.25.1", "dhcp": True,
                     "id": 9, "relay": "", "notes": "", "allow_overlap": "", "options": [],
                     "ranges": [{"kind": "dhcp", "first": f"{P}.25.100", "last": f"{P}.25.200"}],
                     "addresses": []}]}
RENDERED = plan_to_dhcp(PLAN)        # a reservation published in DNS (2.1.10.17); two subnets on VLAN 23 (2.1.10.18)
pv = {**V, "dns": {"dynamic_zone_var": {"A": RENDERED["records"]}}}
pv["dhcp"] = normalize_dhcp({**pv, "dhcp": {**V["dhcp"], "subnets": RENDERED["subnets"]}})
plan_cfg = env.get_template("kea/kea-dhcp4.conf.j2").render(**pv)
try:
    plan_ok = check_kea_config(KEA_IMAGE, "kea-dhcp4.conf", plan_cfg) is True
except ValidationError as e:
    plan_ok = str(e)
try:      # why the class and the hook: Kea 3.0 takes no DDNS settings in a client class (2.1.10.20)
    in_class = check_kea_config(KEA_IMAGE, "kea-dhcp4.conf", plan_cfg.replace(
        '"name": "SKIP_DDNS"', '"name": "SKIP_DDNS", "ddns-send-updates": false'))
except ValidationError as e:
    in_class = str(e)
check("Kea 3.0 refuses ddns-send-updates in a client class: a reservation's DNS updates are skipped through the "
      "SKIP_DDNS class and the ddns-tuning hook instead", "ddns-send-updates" in str(in_class)
      and '"SKIP_DDNS"' in plan_cfg and "libdhcp_ddns_tuning.so" in plan_cfg, in_class)
check("Kea accepts a configuration rendered from an address plan: three subnets (two on one VLAN), a reservation "
      "inside the DHCP range published in the site's zone, options on a subnet and a reservation",
      plan_ok is True and f'"{P}.23.120"' in plan_cfg and '"id": 9' in plan_cfg
      and {"name": "inpool", "ip": f"{P}.23.120"} in RENDERED["records"], plan_ok)
try:                                                  # ip_kea_ddns: Kea's own check refuses what is no address
    deploy_kea({**V, "ip_kea_ddns": f"{P}.23.300"}, {"kea_ddns_secret": secret}, env, 53, 53)
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
      "reverse_zone_names": [REV], "reverse_by_hand": {REV: ["9"]}}
# a PTR set by hand (from a forward record of fabric's zones): 10.<n>.23.9 is nas.lan.test (2.1.10.20)
open(f"{W}/bind9/data/db.{REV}", "w").write(env.get_template("bind9/data/reverse-zone.j2").render(
    **bv, reverse_zone_name=REV, ptr_records=[{"label": "9", "target": "nas.lan.test."}]))
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
testrun.create_network(NET, SUBNET, f"{P}.23.1")
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
    sh(f"docker run -d --name {KT_DHCP4} --label {testrun.LABEL} --network {NET} --ip {P}.23.2 --read-only --memory {KEA_MEM} "
       f"--security-opt no-new-privileges:true --cap-drop ALL --cap-add NET_RAW --cap-add NET_BIND_SERVICE --tmpfs /tmp "
       f"-v {W}/kea/config:/config:ro -v {W}/kea/leases:/var/lib/kea -v {W}/kea/run:/run/kea "
       f"{KEA_IMAGE} {shlex.join(KEA_CMD)}")


start_dhcp4()
# kea-ddns as its compose file runs it: its run folder shared with the host (its control socket, 2.1.10.45)
sh(f"docker run -d --name {KT_DDNS} --label {testrun.LABEL} --network {NET} --ip {DDNS_IP} --user 915:915 --read-only "
   f"--security-opt no-new-privileges:true --cap-drop ALL --tmpfs /tmp -v {W}/kea/run-ddns:/run/kea "
   f"-v {W}/kea/config:/config:ro {KEA_IMAGE} {shlex.join(COMPOSE['kea-ddns']['command'])}")
check("kea-dhcp4 runs and creates its control socket", until(lambda: os.path.exists(f"{W}/kea/run/kea4-ctrl-socket")),
      sh(f"docker logs {KT_DHCP4}", ok=False).stdout[-800:] + sh(f"docker logs {KT_DHCP4}", ok=False).stderr[-800:])


def client(name, mac=None, hostname=None, vendor=None, extra=()):
    """One DHCP client run; its script prints what it was given (udhcpc's environment: tftp, bootfile, siaddr…);
    extra: more udhcpc options sent (`-x 0x5d:0007`: the client's architecture, option 93)."""
    args = ["docker", "run", "--name", name, *testrun.labels(), "--network", NET, "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW"]
    if mac:
        args += ["--mac-address", mac]
    cmd = ["udhcpc", "-i", "eth0", "-n", "-q", "-f", "-t", "5", "-s", "/tmp/s", "-O", "tftp", "-O", "timezone"]
    if hostname:
        cmd += ["-x", f"hostname:{hostname}"]
    if vendor:
        cmd += ["-V", vendor]
    for x in extra:
        cmd += ["-x", x]
    args += [BUSYBOX, "sh", "-c", "printf '#!/bin/sh\nenv | grep -E \"^(tftp|timezone|siaddr|boot_file)=\"\n' > /tmp/s; "
             "chmod +x /tmp/s; exec " + shlex.join(cmd)]
    out = sh(args, ok=False)
    text = out.stdout + out.stderr
    got = [ln.split("lease of ")[1].split()[0] for ln in text.splitlines() if "lease of " in ln]
    return got[-1] if got else None, text


ip1, out1 = client(KT_C1, "02:00:00:00:00:11", "laptop1")
check("a client gets an address from the pool", ip1 is not None and ip1.startswith(f"{P}.23.1"), out1[-400:])


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
      ipb is not None and f"siaddr={P}.23.30" in outb and "boot_file=ipxe.efi" in outb
      and f"tftp={P}.23.30" in outb, outb[-500:])
ip2, out2 = client(KT_C2, "02:00:00:00:00:42")
check("a reserved MAC gets its fixed address", ip2 == f"{P}.23.42", out2[-400:])
check(f"the lease's PTR is registered too, in fabric's reverse zone {REV} (2.1.10.7)",
      until(lambda: sh(["dig", "+short", f"@{BIND_IP}", "-x", ip1], ok=False).stdout.strip()
            == "laptop1.dhcp.lan.test.", 30), (sh(["dig", "+short", f"@{BIND_IP}", "-x", ip1], ok=False).stdout,
                                               sh(f"docker logs {KT_DDNS}", ok=False).stdout[-600:]))
check("a reservation DHCP registers: its name and PTR come from Kea (the reserved hostname)",
      until(lambda: dig("printer.dhcp.lan.test") == f"{P}.23.42"
            and sh(["dig", "+short", f"@{BIND_IP}", "-x", f"{P}.23.42"], ok=False).stdout.strip()
            == "printer.dhcp.lan.test.", 30), sh(f"docker logs {KT_DDNS}", ok=False).stdout[-600:])
# covers: cli:ipam.address +
ip4, out4 = client(KT_C4, "02:00:00:00:00:44", "cam3")
time.sleep(8)                                        # longer than the printer's registration took
check("a reservation whose names are set by hand gets its address, and Kea registers nothing for it, forward or "
      "reverse (2.1.10.20)", ip4 == f"{P}.23.44" and dig("cam3.dhcp.lan.test") == ""
      and sh(["dig", "+short", f"@{BIND_IP}", "-x", f"{P}.23.44"], ok=False).stdout.strip() == "",
      (ip4, dig("cam3.dhcp.lan.test"), sh(f"docker logs {KT_DHCP4}", ok=False).stdout[-800:]))
# covers: cli:ipam.address -
grab = sh(f"printf 'server {BIND_IP}\\nzone {REV}\\nupdate delete 9.{REV} PTR\\nupdate add 9.{REV} 60 PTR "
          f"evil.dhcp.lan.test.\\nsend\\n' | nsupdate -y hmac-sha256:kea-ddns:{secret} 2>&1", ok=False).stdout
check("refused: DHCP's key replacing a PTR set by hand (BIND denies it that name); the hand-set PTR stays",
      "REFUSED" in grab and sh(["dig", "+short", f"@{BIND_IP}", "-x", f"{P}.23.9"], ok=False).stdout.strip()
      == "nas.lan.test.", grab[-300:])
ip3, out3 = client(KT_C3, "02:00:00:00:00:13", "laptop1")
time.sleep(3)
check("another client asking for the same name cannot take it over (DHCID)", ip3 and ip3 != ip1
      and dig("laptop1.dhcp.lan.test") == ip1, (ip3, dig("laptop1.dhcp.lan.test")))
leases = list_leases(V)
check("lease list over the control socket shows the clients", any(lease["ip"] == ip1 and lease["hostname"].startswith("laptop1")
      for lease in leases) and any(lease["ip"] == f"{P}.23.42" for lease in leases), leases)
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


# ------------------------------------------------------------------ DHCP names left behind (2.1.10.22, manual 1.10.4.20)
import fabriclib.dhcp.clean_dhcp_names as cdn  # noqa: E402
import fabriclib.dhcp.clear_stale_dhcp_names as csn  # noqa: E402
import fabriclib.dns.constants as dns_constants  # noqa: E402
from fabriclib.dhcp.hand_set_addresses import hand_set_addresses  # noqa: E402
from fabriclib.dhcp.keep_hand_set_addresses import keep_hand_set_addresses  # noqa: E402
from fabriclib.dhcp.run_dhcp_command import run_dhcp_command  # noqa: E402
from fabriclib.dns.merge_dynamic_records import merge_dynamic_records  # noqa: E402
dns_constants.BIND_CONTAINER = KT_BIND              # BIND's container here; production's is bind9
CLEARED = []
csn.write_audit = lambda actor, action, detail, source, path=None: CLEARED.append((action, detail, source))
cdn.load_secrets = lambda: {"kea_ddns_secret": secret}
KEYFILE = f"{W}/kea-ddns.key"                         # the test's own updates: the key in a 0600 file
fd = os.open(KEYFILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    f.write(f'key "kea-ddns" {{ algorithm hmac-sha256; secret "{secret}"; }};\n')
DHCID = "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA="     # RFC 4701's example


def kea_update(*lines):
    """What Kea would have registered: an update signed with its key."""
    text = "\n".join([f"server {BIND_IP}", "zone dhcp.lan.test", *lines, "send", ""])
    return sh(["nsupdate", "-k", KEYFILE], ok=False, input=text)


def dig_t(rtype, name):
    return sh(["dig", "+short", f"@{BIND_IP}", rtype, name], ok=False).stdout.strip()


def call(fn):
    try:
        return fn(), ""
    except ValidationError as e:
        return None, str(e)


# the printer was registered by Kea above; now an admin names 10.<n>.23.42 by hand (printer.lan.test)
HV = {**V, "dns": {"dynamic_zone_var": {"A": [{"name": "printer", "ip": f"{P}.23.42"},
                                              {"name": "nas", "ip": f"{P}.23.9"}]}}}
check("before: Kea's name and DHCID for the address now named by hand are in dhcp.lan.test",
      dig("printer.dhcp.lan.test") == f"{P}.23.42" and dig_t("DHCID", "printer.dhcp.lan.test") != "",
      dig("printer.dhcp.lan.test"))
gone, err = call(lambda: csn.clear_stale_dhcp_names(HV, hand_set_addresses(HV), secret, "root", "apply"))
check("at the apply: Kea's name for an address named by hand is deleted, its DHCID with it, and audited",
      err == "" and dig("printer.dhcp.lan.test") == "" and dig_t("DHCID", "printer.dhcp.lan.test") == ""
      and [c[0] for c in CLEARED] == ["DHCP_NAME_CLEAR", "DHCP_NAME_CLEAR"]
      and all(c[2] == "apply" for c in CLEARED) and f"printer.dhcp.lan.test A {P}.23.42" in CLEARED[0][1],
      (err, gone, CLEARED))
check("not deleted: a DHCP name whose address nothing names by hand (laptop1 keeps its name)",
      dig("laptop1.dhcp.lan.test") == ip1, dig("laptop1.dhcp.lan.test"))
check("not touched: the PTR set by hand (nas.lan.test), a record outside DHCP's zone",
      sh(["dig", "+short", f"@{BIND_IP}", "-x", f"{P}.23.9"], ok=False).stdout.strip() == "nas.lan.test.")
again, err = call(lambda: csn.clear_stale_dhcp_names(HV, hand_set_addresses(HV), secret, "root", "apply"))
check("a second run finds nothing and sends nothing (idempotent)", again == [] and err == "" and len(CLEARED) == 2,
      (again, err, CLEARED))
merged = merge_dynamic_records(REV, env.get_template("bind9/data/reverse-zone.j2").render(
    **bv, reverse_zone_name=REV, ptr_records=[{"label": "9", "target": "nas.lan.test."},
                                             {"label": "42", "target": "printer.lan.test."}]),
    csn._served_zone(REV))
check("Kea's PTR for that address: the apply's regenerated reverse zone drops it for the PTR set by hand "
      "(the zone as BIND serves it), and keeps laptop1's", "printer.dhcp" not in merged
      and "laptop1.dhcp.lan.test." in merged, merged[-600:])

# the hourly timer's run: what its unit starts, with the addresses the apply kept
unit = open(f"{REPO}/templates/systemd/fabric-dhcp-names.service").read()
timer = open(f"{REPO}/templates/systemd/fabric-dhcp-names.timer").read()
argv = [ln.split("=", 1)[1].split() for ln in unit.splitlines() if ln.startswith("ExecStart=")][0]
check("the timer runs hourly and its unit runs the cleanup alone (`fabricctl dhcp clean-names --scheduled`)",
      argv == ["/usr/bin/fabricctl", "dhcp", "clean-names", "--scheduled"] and "OnUnitActiveSec=1h" in timer, argv)
HV2 = {**HV, "dns": {"dynamic_zone_var": {"A": HV["dns"]["dynamic_zone_var"]["A"]
                                          + [{"name": "cam3", "ip": f"{P}.23.44"}]}}}
kept = keep_hand_set_addresses(HV2)
check("the apply keeps its addresses set by hand for the timer (root only, 0600)",
      kept and oct(os.stat(kept).st_mode & 0o777) == "0o600"
      and json.load(open(kept))["addresses"] == [f"{P}.23.42", f"{P}.23.44", f"{P}.23.9"], kept)
planted = kea_update(f"update add old-cam.dhcp.lan.test 300 A {P}.23.44",
                     f"update add old-cam.dhcp.lan.test 300 DHCID {DHCID}")
check("(set up: a name Kea registered for cam3's address before it was named by hand)",
      planted.returncode == 0 and dig("old-cam.dhcp.lan.test") == f"{P}.23.44", planted.stdout + planted.stderr)
# covers: cli:dhcp.clean-names +
rc = run_dhcp_command(HV2, argv[2:])
check("by the timer's unit: the name left behind is deleted, audited as the timer's; laptop1 left alone",
      rc == 0 and dig("old-cam.dhcp.lan.test") == "" and dig_t("DHCID", "old-cam.dhcp.lan.test") == ""
      and dig("laptop1.dhcp.lan.test") == ip1 and CLEARED[-1][2] == "timer", (rc, CLEARED[-2:]))
# covers: cli:dhcp.clean-names -
planted = kea_update(f"update add old-cam2.dhcp.lan.test 300 A {P}.23.44")
check("(set up: a second name left behind, old-cam2, served by BIND)", planted.returncode == 0
      and until(lambda: dig("old-cam2.dhcp.lan.test") == f"{P}.23.44", 15), planted.stdout + planted.stderr)
before = len(CLEARED)
cdn.load_secrets = lambda: {"kea_ddns_secret": sh("openssl rand -base64 32").stdout.strip()}
rc_bad = run_dhcp_command(HV2, ["clean-names", "--scheduled"])
_, err = call(lambda: csn.clear_stale_dhcp_names(HV2, [f"{P}.23.44"], "x" + secret[1:], "root", "cli"))
check("refused: BIND refusing the update (a key it does not know) fails the run (exit 1) and says so; the name "
      "stays, nothing audited", rc_bad == 1 and "BIND refused" in err and "nothing was deleted" in err
      and dig("old-cam2.dhcp.lan.test") == f"{P}.23.44" and len(CLEARED) == before, (rc_bad, err))
cdn.load_secrets = lambda: {"kea_ddns_secret": secret}
os.remove(kept)
check("refused: no apply has kept the addresses yet (exit 1); a stray argument is a usage error (2)",
      run_dhcp_command(HV2, ["clean-names"]) == 1 and run_dhcp_command(HV2, ["clean-names", "now"]) == 2
      and dig("old-cam2.dhcp.lan.test") == f"{P}.23.44")
off = {**HV2, "dhcp": {**HV2["dhcp"], "ddns": False}}
keep_hand_set_addresses(HV2)
check("with DHCP's DNS registration off: nothing kept, nothing to clean (exit 0), nothing deleted",
      keep_hand_set_addresses(off) is None and not os.path.exists(kept) and run_dhcp_command(off, ["clean-names"]) == 0
      and dig("old-cam2.dhcp.lan.test") == f"{P}.23.44")


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


# ------------------------------------------------------------------ the plan's options and netboot presets
# (decisions 2.1.10.23 and 2.1.10.25, manual 1.10.4.24 and 1.10.4.25): Kea itself takes the rendered classes, and real
# clients of each kind are handed their own boot file; options at each level win in Kea's order
NB_PLAN = {"site": "lan", "block": 1, "vlans": [{"id": 23, "name": "lab", "access": "full"}], "networks": [],
           "domain_options": {"options": [{"name": "time-offset", "data": "100"},
                                       {"name": "ztp-url", "data": "http://ztp.lan/cfg"}],
                           "option_defs": [{"name": "ztp-url", "code": 239, "type": "string"}], "client_classes": []},
           "site_options": {"options": [{"name": "time-offset", "data": "200"}], "option_defs": [],
                            "client_classes": []},
           "subnets": [{"name": "lab", "cidr": SUBNET, "vlan": 23, "gateway": f"{P}.23.1", "dhcp": True, "id": 7,
                        "relay": "", "notes": "", "allow_overlap": "", "options": [{"name": "time-offset",
                                                                                     "data": "300"}],
                        "netboot": {"server": f"{P}.23.30", "bios": "undionly.kpxe", "uefi": "ipxe.efi",
                                    "ipxe": f"http://{P}.23.30/boot.ipxe",
                                    "http": f"http://{P}.23.30/grubx64.efi"},
                        "ranges": [{"kind": "dhcp", "first": f"{P}.23.100", "last": f"{P}.23.150"}],
                        "addresses": [{"ip": f"{P}.23.51", "kind": "reservation", "name": "kiosk",
                                       "mac": "02:00:00:00:00:51", "dns": False,
                                       "options": [{"name": "time-offset", "data": "400"}],
                                       "netboot": {"server": f"{P}.23.31", "bios": "kiosk.0"}}]}]}
NB = plan_to_dhcp(NB_PLAN)
nv = {**V, "dns": {"dynamic_zone_var": {"A": NB["records"]}}}
nv["dhcp"] = normalize_dhcp({**nv, "dhcp": {**V["dhcp"], "subnets": NB["subnets"], "options": NB["options"],
                                           "option_defs": NB["option_defs"], "client_classes": NB["client_classes"]}})
nb_cfg = env.get_template("kea/kea-dhcp4.conf.j2").render(**nv)
try:
    nb_ok = check_kea_config(KEA_IMAGE, "kea-dhcp4.conf", nb_cfg) is True
except ValidationError as e:
    nb_ok = str(e)
check("Kea accepts the plan's option sets and netboot classes: a custom definition, only-in-additional-list classes "
      "the subnet evaluates, a reservation's marker class", nb_ok is True and '"only-in-additional-list": true'
      in nb_cfg and '"evaluate-additional-classes"' in nb_cfg and f'"fabric-nb-a-{P}.23.51"' in nb_cfg, nb_ok)
check("the global level: the site's time-offset (200) over the domain's (100)",
      {"name": "time-offset", "data": "200"} in NB["options"]
      and {"name": "time-offset", "data": "100"} not in NB["options"], NB["options"])
saved_cfg = open(f"{W}/kea/config/kea-dhcp4.conf").read()
with open(f"{W}/kea/config/kea-dhcp4.conf", "w") as f:
    f.write(nb_cfg)
testrun.remove("container", KT_DHCP4)
start_dhcp4()
until(lambda: os.path.exists(f"{W}/kea/run/kea4-ctrl-socket"))
time.sleep(2)
ip_b, out_b = client(KT_NB1, "02:00:00:00:00:61", extra=["0x5d:0000"])
check("a BIOS PXE client (architecture 0) gets the BIOS file from the boot server, and the subnet's time-offset "
      "(300) over the site's", ip_b and "boot_file=undionly.kpxe" in out_b and f"siaddr={P}.23.30" in out_b
      and f"tftp={P}.23.30" in out_b and "timezone=300" in out_b, out_b[-500:])
ip_u, out_u = client(KT_NB2, "02:00:00:00:00:62", extra=["0x5d:0007"])
check("a UEFI client (architecture 7) gets the UEFI file", ip_u and "boot_file=ipxe.efi" in out_u, out_u[-500:])
ip_i, out_i = client(KT_NB3, "02:00:00:00:00:63", extra=["0x5d:0007", "0x4d:69505845"])
check("the same client once running iPXE (user class 'iPXE') gets the script's URL, not iPXE again",
      ip_i and f"boot_file=http://{P}.23.30/boot.ipxe" in out_i, out_i[-500:])
ip_h, out_h = client(KT_NB4, "02:00:00:00:00:64", vendor="HTTPClient:Arch:00016:UNDI:003001")
check("a UEFI HTTP boot client gets the HTTP URL", ip_h and f"boot_file=http://{P}.23.30/grubx64.efi" in out_h,
      out_h[-500:])
ip_n, out_n = client(KT_NB5, "02:00:00:00:00:65")
check("a client that asks for no boot gets no boot file", ip_n and "boot_file=" not in out_n.replace("boot_file=\n", ""),
      out_n[-500:])
ip_k, out_k = client(KT_NB6, "02:00:00:00:00:51", extra=["0x5d:0000"])
check("the reservation's own preset and option win over the subnet's: its address, its boot server and file, "
      "time-offset 400", ip_k == f"{P}.23.51" and "boot_file=kiosk.0" in out_k and f"siaddr={P}.23.31" in out_k
      and "timezone=400" in out_k, out_k[-500:])
with open(f"{W}/kea/config/kea-dhcp4.conf", "w") as f:
    f.write(saved_cfg)
testrun.remove("container", KT_DHCP4)
start_dhcp4()


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
check("a name already in use, an overlapping pool, and a missing subnet are refused",
      "unique" in refused(lambda: add_subnet("root", "10.5.0.0/24", "iot"))
      and "overlaps" in refused(lambda: update_subnet("root", "iot", add_pools=["10.4.0.150 - 10.4.0.220"]))
      and "no DHCP subnet" in refused(lambda: update_subnet("root", "nope", notes="x")))
add_subnet("root", "10.5.0.0/24", "cams", vlan=40, pools=["10.5.0.100 - 10.5.0.200"])
check("a second subnet on a VLAN already in use is accepted (2.1.10.18)",
      subnets()["10.5.0.0/24"]["vlan"] == 40 and subnets()["10.4.0.0/24"]["vlan"] == 40, subnets())
remove_subnet("root", "cams", [])
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
check("every change was audited", AUDIT.count("DHCP_SUBNET_ADD") == 2 and "DHCP_CLASS_REMOVE" in AUDIT
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
      code == 0 and f"{P}.23.0/24" in out and "lab" in out and "VLAN 23" in out and "printer" in out
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
# a reservation inside a pool is allowed since 0.8.0 (manual 1.10.4.3.2): the second refusal is a MAC that is no MAC
code2, err2, same2 = refused_cli(V, "reserve", "02:00:00:00:00", "10.1.0.21", "--no-apply")
code3, err3, same3 = refused_cli(V, "reserve", "02:00:00:00:00:78", "10.1.0.20", "--no-apply")
# covers: cli:dhcp.reserve -
check("dhcp reserve refuses an address in no subnet, a MAC that is no MAC, one already reserved; nothing saved",
      (code, code2, code3) == (1, 1, 1) and "10.9.0.5 is in none of the DHCP subnets" in err
      and "MAC like aa:bb:cc:dd:ee:ff" in err2 and "must be unique" in err3 and same and same2 and same3,
      (err, err2, err3))
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
# the settings' own classes and options (a site whose subnets are not in an address plan: 1.10.4.24.4; the sandbox
# runs the plan's, `fabricctl ipam class` and `ipam option`)
code, out, err = dhcp_cli(V, "class", "add", "pxe-uefi", "--test", "option[93].hex == 0x0007", "--next-server",
                          "10.4.0.30", "--boot-file", "ipxe.efi", "--no-apply")
code2, out2, err2 = dhcp_cli(V, "option", "set", "tftp-server-name", "10.4.0.30", "--class", "pxe-uefi", "--no-apply")
pxe = next((c for c in STORE["vars"]["dhcp"].get("client_classes") or [] if c["name"] == "pxe-uefi"), {})
# covers: cli:dhcp.class cli:dhcp.option +
check("dhcp class add and option set --class: the class saved with its boot fields and the option, Kea's check passed",
      code == 0 and code2 == 0 and "client class pxe-uefi added" in out and "recorded" in out2
      and pxe.get("next_server") == "10.4.0.30" and pxe.get("boot_file_name") == "ipxe.efi"
      and [o.get("name") for o in pxe.get("options") or []] == ["tftp-server-name"], (out, err, out2, err2, pxe))
code, err, same = refused_cli(V, "option", "set", "no-such-option", "1", "--no-apply")
# covers: cli:dhcp.option -
check("dhcp option set refuses an option Kea does not know (Kea's own check); nothing saved",
      code == 1 and "Kea refused" in err and same, err[-300:])
code, out, err = dhcp_cli(V, "class", "remove", "pxe-uefi", "--no-apply")
check("dhcp class remove: the class and its option gone", code == 0 and not any(
    c["name"] == "pxe-uefi" for c in STORE["vars"]["dhcp"].get("client_classes") or []), (out, err))

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
