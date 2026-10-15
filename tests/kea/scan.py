#!/usr/bin/env python3
"""The `kea` suite, ping-check and the scan on a real network (manual 1.10.4.22, decisions 2.1.10.13 and 2.1.10.26):
Kea from fabric's image and template with ping-check on skips an address a device already answers on (the lease
declined) and offers the next; with `dhcp.ping_check: false` it offers that address; Kea's own check accepts the
hook. A scan run by fabric's code in Kea's container (fping and the neighbour table, the container's two
capabilities only): a recorded address, a lease, a device set by hand nobody recorded (with its MAC), one that drops
pings found by ARP, the address Kea declined; refused: a subnet Kea does not serve, the same subnet again within a
minute, nothing probed.

    sudo python3 tests/kea/scan.py          (needs Docker, root)
"""
import json
import os
import shlex
import shutil
import subprocess
import sys
import time

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/kea-scan"
NET, SUBNET, KEA_IP = "keascan_net", "10.254.64.0/24", "10.254.64.2"
KEA = "ks-dhcp4"
FAILED = 0
sys.path[0:0] = [os.path.join(REPO, "src"), REPO]
from tests.common.kea_image import build_kea_image  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.common.read_packages_lock import read_packages_lock  # noqa: E402
from fabriclib.dhcp.check_kea_config import check_kea_config  # noqa: E402
from fabriclib.dhcp.list_leases import list_leases  # noqa: E402
from fabriclib.dhcp.normalize_dhcp import normalize_dhcp  # noqa: E402
import fabriclib.ipam.scan_subnet as m_scan  # noqa: E402
from fabriclib.ipam.scancontrol.local_scan_state import local_scan_state  # noqa: E402
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


TARGETS = {"ks-squat": ("10.254.64.100", "02:00:00:00:64:64", []),        # set by hand inside the pool
           "ks-nas": ("10.254.64.10", "02:00:00:00:64:10", []),           # recorded in the plan
           "ks-hand": ("10.254.64.11", "02:00:00:00:64:11", []),          # nobody recorded it
           "ks-quiet": ("10.254.64.12", "02:00:00:00:64:12",              # drops pings, answers ARP
                        ["--sysctl", "net.ipv4.icmp_echo_ignore_all=1"])}


def cleanup():
    sh(["docker", "rm", "-f", KEA, "ks-c1", "ks-c1-up", "ks-c2", *TARGETS], ok=False)
    sh(["docker", "network", "rm", NET], ok=False)


cleanup()
shutil.rmtree(W, ignore_errors=True)
os.makedirs(W)
lock, pkgs = read_images_lock(os.path.join(REPO, "config")), read_packages_lock(os.path.join(REPO, "config"))
DEBIAN, BUSYBOX = lock["debian"]["ref"], \
    "busybox:1.37@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"
k = pkgs["kea"]
build = build_kea_image()
check("Kea's image builds, with fping for the scan", build.returncode == 0 and sh(
    "docker run --rm --entrypoint fping fabric/kea:test -v", ok=False).returncode == 0, build.stderr[-500:])

PLAN = {"site": "home", "block": 1, "vlans": [{"id": 64, "name": "lab", "access": "full"}],
        "subnets": [{"name": "lab", "cidr": SUBNET, "vlan": 64, "gateway": "10.254.64.1", "dhcp": True, "id": 1,
                     "relay": "", "notes": "", "allow_overlap": "", "options": [],
                     # a two-address pool: the squatter on the first leaves the client the second
                     "ranges": [{"kind": "dhcp", "first": "10.254.64.100", "last": "10.254.64.101"}],
                     "addresses": [{"ip": "10.254.64.10", "kind": "static", "name": "nas", "mac": "", "dns": False,
                                    "options": []}]}]}
env = jinja_env(os.path.join(REPO, "templates"))


def render(ping_check):
    """Kea's configuration from fabric's template, as an apply renders it (no DDNS here)."""
    v = {"deploy_base_dir": W, "domain": "lan.test", "install_kea": True, "host_ip": KEA_IP, "site_name": "home",
         "ip_kea_ddns": "10.255.0.97", "dhcp": {"interfaces": ["eth0"], "ddns": False, "lease_time": 3600,
                                                 "ping_check": ping_check, "subnets": plan_to_dhcp(PLAN)["subnets"]}}
    v["dhcp"] = normalize_dhcp(v)
    os.makedirs(f"{W}/kea/config", exist_ok=True)
    os.makedirs(f"{W}/kea/leases", exist_ok=True)
    os.makedirs(f"{W}/kea/run", exist_ok=True)
    os.chmod(f"{W}/kea/run", 0o750)      # as the deploy makes it: Kea 3 refuses a socket folder looser than 750
    text = env.get_template("kea/kea-dhcp4.conf.j2").render(**v)
    with open(f"{W}/kea/config/kea-dhcp4.conf", "w") as f:
        f.write(text)
    return v, text


V, CFG = render(True)
try:
    accepted = check_kea_config("fabric/kea:test", "kea-dhcp4.conf", CFG)
except ValidationError as e:
    accepted = str(e)
# covers: setting:dhcp +
check("Kea's own check accepts the ping_check hook from its packages (open source in Kea 3.0)",
      accepted is True and "libdhcp_ping_check.so" in CFG, accepted)

KEA_CMD = yaml.safe_load(env.get_template("kea/docker-compose.yml.j2").render(
    **V, image_debian="debian", kea_mem_limit="128m", packages_lock=pkgs,
    service_users={"kea": {"uid": 915, "gid": 915}}, published_ref=lambda name: None))["services"]["kea-dhcp4"]
check("least privilege: the Kea container fabric renders has exactly NET_RAW and NET_BIND_SERVICE (none added for "
      "the scan)", sorted(KEA_CMD["cap_add"]) == ["NET_BIND_SERVICE", "NET_RAW"] and KEA_CMD["cap_drop"] == ["ALL"],
      KEA_CMD.get("cap_add"))


# who may scan (2.1.10.30) is read from the domain, which this suite does not run: this site is the top one, where
# local scans always run (the rule itself against a real DC: tests/samba/ipam.py)
def top_site(v):
    return local_scan_state({v["site_name"]: {"top": True}}, v["site_name"])


def start_kea():
    sh(["docker", "rm", "-f", KEA], ok=False)
    sh(f"docker run -d --name {KEA} --network {NET} --ip {KEA_IP} --read-only --security-opt no-new-privileges:true "
       f"--cap-drop ALL --cap-add NET_RAW --cap-add NET_BIND_SERVICE --tmpfs /tmp "
       f"-v {W}/kea/config:/config:ro -v {W}/kea/leases:/var/lib/kea -v {W}/kea/run:/run/kea "
       f"fabric/kea:test {shlex.join(KEA_CMD['command'])}")
    return until(lambda: os.path.exists(f"{W}/kea/run/kea4-ctrl-socket"))


def client(name, mac):
    out = sh(["docker", "run", "--name", name, "--network", NET, "--mac-address", mac, "--cap-add", "NET_ADMIN",
              "--cap-add", "NET_RAW", BUSYBOX, "udhcpc", "-i", "eth0", "-n", "-q", "-f", "-t", "8"], ok=False)
    text = out.stdout + out.stderr
    got = [ln.split("lease of ")[1].split()[0] for ln in text.splitlines() if "lease of " in ln]
    return (got[-1] if got else None), text


sh(f"docker network create --subnet {SUBNET} --gateway 10.254.64.1 {NET}")
for name, (ip, mac, extra) in TARGETS.items():
    sh(["docker", "run", "-d", "--name", name, "--network", NET, "--ip", ip, "--mac-address", mac, *extra, BUSYBOX,
        "sleep", "3600"])
check("Kea runs with ping-check on", start_kea(), sh(f"docker logs {KEA}", ok=False).stderr[-600:])

# ---- ping-check (2.1.10.13)
ip1, out1 = client("ks-c1", "02:00:00:00:64:01")
check("ping-check: the pool's first address answers a ping (set by hand), so the client is offered the next",
      ip1 == "10.254.64.101", out1[-400:])
leases = list_leases(V)
check("Kea declined the address that answered (its lease is declined)",
      any(lease["ip"] == "10.254.64.100" and lease["state"] == "declined" for lease in leases), leases)
# covers: setting:dhcp -
sh(["docker", "rm", "-f", KEA, "ks-c1"], ok=False)
for f in os.listdir(f"{W}/kea/leases"):
    os.remove(os.path.join(f"{W}/kea/leases", f))
V_OFF, CFG_OFF = render(False)
check("with dhcp.ping_check: false the hook is not loaded", "ping_check" not in CFG_OFF and start_kea())
ip2, out2 = client("ks-c2", "02:00:00:00:64:02")
check("without ping-check Kea offers the address a device already answers on (what ping-check prevents)",
      ip2 == "10.254.64.100", out2[-400:])

# ---- the scan (2.1.10.26), back with ping-check on and the declined lease
sh(["docker", "rm", "-f", KEA, "ks-c2"], ok=False)
for f in os.listdir(f"{W}/kea/leases"):
    os.remove(os.path.join(f"{W}/kea/leases", f))
V, CFG = render(True)
start_kea()
ip1, out1 = client("ks-c1", "02:00:00:00:64:01")
if ip1:     # udhcpc quits once it has the lease: the client keeps its address up as a device would, so the scan sees it
    sh(["docker", "run", "-d", "--name", "ks-c1-up", "--network", NET, "--ip", ip1, "--mac-address",
        "02:00:00:00:64:01", BUSYBOX, "sleep", "3600"])
AUDIT = []
m_scan.load_plan_cache = lambda: PLAN
m_scan.write_audit = lambda actor, action, detail, source="cli", path=None: AUDIT.append((action, detail))
STATE = f"{W}/scan-state"
try:
    # covers: cli:ipam.scan agent:post.ipam.scan +
    res = m_scan.scan_subnet(V, "root", SUBNET, container=KEA, state_dir=STATE, local=top_site)
    err = ""
except ValidationError as e:
    res, err = {"answering": []}, str(e)
by = {f["ip"]: f for f in res["answering"]}
print(json.dumps(res, indent=1)[:2000])
check("the scan runs in Kea's container and finds the recorded address as recorded", not err
      and by.get("10.254.64.10", {}).get("status") == "recorded", err or res)
check("a device set by hand that nobody recorded: in use, unrecorded, with its MAC",
      by.get("10.254.64.11", {}).get("status") == "unrecorded"
      and by.get("10.254.64.11", {}).get("mac") == "02:00:00:00:64:11", by.get("10.254.64.11"))
check("a device that drops pings is found by ARP", by.get("10.254.64.12", {}).get("how") == "arp"
      and by.get("10.254.64.12", {}).get("status") == "unrecorded", by.get("10.254.64.12"))
check("the client's lease is a lease; the address Kea declined is in use, unrecorded",
      by.get(ip1 or "", {}).get("status") == "lease" and by.get("10.254.64.100", {}).get("status") == "unrecorded"
      and "declined" in by.get("10.254.64.100", {}).get("note", ""), (ip1, by.get(ip1 or ""), by.get("10.254.64.100")))
check("the scan is audited", AUDIT and AUDIT[-1][0] == "IPAM_SCAN" and f"subnet={SUBNET}" in AUDIT[-1][1], AUDIT)
# covers: cli:ipam.scan agent:post.ipam.scan -
n = len(AUDIT)
for typed, words in (("10.254.99.0/24", "not a subnet of this site's plan"), (SUBNET, "scanned")):
    try:
        m_scan.scan_subnet(V, "root", typed, container=KEA, state_dir=STATE, local=top_site)
        why = "not refused"
    except ValidationError as e:
        why = str(e)
    check(f"refused: a scan of {typed} ({words})", words in why, why)
check("nothing audited for a refused scan", len(AUDIT) == n, AUDIT)
caps = sh(["docker", "inspect", "-f", "{{json .HostConfig.CapAdd}}", KEA]).stdout
check("the scan ran with the Kea container's capabilities as they were", "NET_RAW" in caps and "NET_ADMIN" not in caps,
      caps)

cleanup()
print(f"\n{FAILED} failed" if FAILED else "\nall passed")
sys.exit(1 if FAILED else 0)
