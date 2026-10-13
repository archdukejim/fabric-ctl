#!/usr/bin/env python3
"""The `kea` suite, relayed VLANs (manual 1.10.4.11, 1.10.4.5; decision 2.1.10.8): Kea rendered from a site's address
plan answers a relayed request on each of three VLANs. Each VLAN is a Docker network of its own with a relay
container (busybox's dhcprelay) standing for the gateway: its address on the VLAN is the VLAN's gateway, and it
forwards to Kea on the core network. Proves: Kea's own check accepts the three subnets; a client on each VLAN gets an
address from its own VLAN's DHCP range, its gateway as router and fabric's DNS server; a reservation on one VLAN is
given to its MAC through the relay; refused: once a VLAN's subnet leaves the plan, a client relayed from it gets
nothing (Kea serves no subnet for that relay), while the others still do.

    sudo python3 tests/kea/relay.py          (needs Docker, nsenter and ip, root)
"""
import os
import shlex
import shutil
import subprocess
import sys
import time

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/kea-relay"
# free ranges (every tests/**/*.py checked; 0.7.1 uses 10.254.45-48): the core network and three VLANs
CORE, CORE_NET, KEA_IP = "kearelay_core", "10.254.60.0/24", "10.254.60.2"
VLANS = {61: "kearelay_v61", 62: "kearelay_v62", 63: "kearelay_v63"}
KEA = "kr-dhcp4"
FAILED = 0
sys.path[0:0] = [os.path.join(REPO, "src"), REPO]
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.common.read_packages_lock import read_packages_lock  # noqa: E402
from fabriclib.dhcp.check_kea_config import check_kea_config  # noqa: E402
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


def relay(vid):
    return f"kr-relay{vid}"


def cleanup():
    sh(["docker", "rm", "-f", KEA, *[relay(v) for v in VLANS], *[f"kr-c{v}" for v in VLANS], "kr-res", "kr-gone",
        "kr-still"], ok=False)
    for net in [CORE, *VLANS.values()]:
        sh(["docker", "network", "rm", net], ok=False)


cleanup()
shutil.rmtree(W, ignore_errors=True)
for d in ("config", "leases", "run"):
    os.makedirs(f"{W}/kea/{d}")
lock, pkgs = read_images_lock(os.path.join(REPO, "config")), read_packages_lock(os.path.join(REPO, "config"))
DEBIAN, BUSYBOX = lock["debian"]["ref"], \
    "busybox:1.37@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"
k = pkgs["kea"]
sh(["docker", "build", "-q", "-t", "fabric/kea:test", "--build-arg", f"BASE_IMAGE={DEBIAN}",
    "--build-arg", f"KEA_VERSION={k['version']}", "--build-arg", f"KEA_REPO={k['repo']}",
    "--build-arg", f"KEA_SUITE={k['suite']}", "--build-arg", f"KEA_KEY_URL={k['key_url']}",
    "--build-arg", f"KEA_KEY_FINGERPRINT={k['key_fingerprint']}", f"{REPO}/packaging/images/kea"])
check("busybox has dhcprelay (the relays)", sh(["docker", "run", "--rm", BUSYBOX, "dhcprelay"], ok=False).stderr
      .lower().count("usage") > 0 or "dhcprelay" in sh(["docker", "run", "--rm", BUSYBOX, "busybox", "--list"],
                                                         ok=False).stdout)


def subnet(vid, sid):
    """A VLAN's subnet in the plan: gateway .1 (the relay), DHCP .100-.150; the relay is inside the subnet, so Kea
    picks it by the relay's address (giaddr) with no relay field."""
    return {"name": f"v{vid}", "cidr": f"10.254.{vid}.0/24", "vlan": vid, "gateway": f"10.254.{vid}.1", "dhcp": True,
            "id": sid, "relay": "", "notes": "", "allow_overlap": "", "options": [],
            "ranges": [{"kind": "dhcp", "first": f"10.254.{vid}.100", "last": f"10.254.{vid}.150"}],
            "addresses": ([{"ip": "10.254.62.42", "kind": "reservation", "name": "printer",
                            "mac": "02:00:00:00:62:42", "dns": False, "options": []}] if vid == 62 else [])}


PLAN = {"site": "home", "block": 254, "vlans": [{"id": v, "name": f"v{v}", "access": "full"} for v in VLANS],
        "subnets": [subnet(v, i + 1) for i, v in enumerate(VLANS)]}
env = jinja_env(os.path.join(REPO, "templates"))


def render(plan):
    v = {"deploy_base_dir": W, "domain": "lan.test", "install_kea": True, "host_ip": KEA_IP, "site_name": "home",
         "ip_kea_ddns": "10.255.0.97", "dhcp": {"interfaces": ["eth0"], "ddns": False, "lease_time": 3600,
                                                 "dns": [KEA_IP], "subnets": plan_to_dhcp(plan)["subnets"]}}
    v["dhcp"] = normalize_dhcp(v)
    text = env.get_template("kea/kea-dhcp4.conf.j2").render(**v)
    with open(f"{W}/kea/config/kea-dhcp4.conf", "w") as f:
        f.write(text)
    return v, text


V, CFG = render(PLAN)
try:
    accepted = check_kea_config("fabric/kea:test", "kea-dhcp4.conf", CFG)
except ValidationError as e:
    accepted = str(e)
check("Kea accepts a configuration rendered from a plan with three relayed VLANs", accepted is True
      and all(f'"10.254.{v}.0/24"' in CFG for v in VLANS), accepted)
KEA_CMD = yaml.safe_load(env.get_template("kea/docker-compose.yml.j2").render(
    **V, image_debian="debian", kea_mem_limit="128m", packages_lock=pkgs,
    service_users={"kea": {"uid": 915, "gid": 915}}))["services"]["kea-dhcp4"]["command"]

# ---- the networks: Docker's own gateway on each VLAN is .254, so the relay can be the VLAN's gateway (.1)
sh(f"docker network create --subnet {CORE_NET} --gateway 10.254.60.254 {CORE}")
for vid, net in VLANS.items():
    sh(f"docker network create --subnet 10.254.{vid}.0/24 --gateway 10.254.{vid}.254 {net}")


def start_kea():
    sh(["docker", "rm", "-f", KEA], ok=False)
    sh(f"docker run -d --name {KEA} --network {CORE} --ip {KEA_IP} --read-only "
       f"--security-opt no-new-privileges:true --cap-drop ALL --cap-add NET_RAW --cap-add NET_BIND_SERVICE "
       f"--tmpfs /tmp -v {W}/kea/config:/config:ro -v {W}/kea/leases:/var/lib/kea -v {W}/kea/run:/run/kea "
       f"fabric/kea:test {shlex.join(KEA_CMD)}")
    up = until(lambda: os.path.exists(f"{W}/kea/run/kea4-ctrl-socket"))
    # Kea answers a relay at its giaddr: the way back to each VLAN is through that VLAN's relay (the router's job)
    pid = sh(["docker", "inspect", "-f", "{{.State.Pid}}", KEA]).stdout.strip()
    for vid in VLANS:
        sh(["nsenter", "-t", pid, "-n", "ip", "route", "replace", f"10.254.{vid}.0/24", "via", f"10.254.60.{vid}"])
    return up


for vid, net in VLANS.items():
    # the relay: on the core network (eth0) and its VLAN (eth1) as the gateway; forwards to Kea with giaddr .1
    sh(["docker", "run", "-d", "--name", relay(vid), "--network", CORE, "--ip", f"10.254.60.{vid}",
        "--cap-drop", "ALL", "--cap-add", "NET_RAW", "--cap-add", "NET_BIND_SERVICE", BUSYBOX, "sleep", "3600"])
    sh(["docker", "network", "connect", "--ip", f"10.254.{vid}.1", net, relay(vid)])
    sh(["docker", "exec", "-d", relay(vid), "dhcprelay", "eth1", "eth0", KEA_IP])
check("Kea runs on the core network, reachable from the three relays", start_kea(),
      sh(f"docker logs {KEA}", ok=False).stderr[-600:])


def client(name, vid, mac=None):
    """A DHCP client on a VLAN; its script prints what it was given (ip, router, dns)."""
    args = ["docker", "run", "--name", name, "--network", VLANS[vid], "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW"]
    if mac:
        args += ["--mac-address", mac]
    args += [BUSYBOX, "sh", "-c", "printf '#!/bin/sh\\nenv | grep -E \"^(ip|router|dns)=\"\\n' > /tmp/s; chmod +x /tmp/s; "
             "exec udhcpc -i eth0 -n -q -f -t 8 -s /tmp/s"]
    out = sh(args, ok=False)
    text = out.stdout + out.stderr
    got = [ln.split("lease of ")[1].split()[0] for ln in text.splitlines() if "lease of " in ln]
    return (got[-1] if got else None), text


for vid in VLANS:
    ip, out = client(f"kr-c{vid}", vid)
    check(f"VLAN {vid}: a relayed client gets an address from its own VLAN's DHCP range, its gateway as router and "
          f"fabric's DNS", ip is not None and ip.startswith(f"10.254.{vid}.1") and f"router=10.254.{vid}.1" in out
          and f"dns={KEA_IP}" in out, (ip, out[-500:], sh(f"docker logs {KEA}", ok=False).stdout[-600:]))
ip, out = client("kr-res", 62, "02:00:00:00:62:42")
check("VLAN 62: a reservation in the plan reaches its MAC through the relay", ip == "10.254.62.42", out[-400:])

# ---- refused: a VLAN whose subnet leaves the plan is no longer served
GONE = {**PLAN, "subnets": [s for s in PLAN["subnets"] if s["vlan"] != 63]}
V, CFG = render(GONE)
check("Kea restarted with VLAN 63's subnet removed from the plan", '"10.254.63.0/24"' not in CFG and start_kea())
ip, out = client("kr-gone", 63)
check("refused: a client relayed from VLAN 63 gets nothing (no subnet for that relay)", ip is None, out[-400:])
ip, out = client("kr-still", 61)
check("VLAN 61 is still served", ip is not None and ip.startswith("10.254.61.1"), out[-400:])

cleanup()
print(f"\n{FAILED} failed" if FAILED else "\nall passed")
sys.exit(1 if FAILED else 0)
