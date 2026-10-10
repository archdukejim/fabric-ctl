#!/usr/bin/env python3
"""Time (manual 1.13.1) with real containers: chrony (Debian's package on fabric's pinned Debian image) run from
the configuration deploy_chrony generates. A site serves its network and refuses others; a second site syncs
from it as its upstream site (federation); time_status and query_time read real chrony. Includes what must be
refused. The containers never set the clock (-x): they share the host's kernel clock.

    sudo python3 tests/ntp/run.py            (needs Docker)
"""
import json
import os
import shutil
import subprocess
import sys
import time

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/ntp"
NET_A, SUB_A, SRV_A = "ntp_test_lan", "10.254.42.0/24", "10.254.42.10"
NET_B, SUB_B, SRV_B = "ntp_test_other", "10.254.43.0/24", "10.254.43.10"
SITE_IP = "10.254.42.20"
IMAGE = "fabric/chrony:test"
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def sh(cmd, ok=True):
    res = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True)
    if ok and res.returncode != 0:
        raise SystemExit(f"command failed: {cmd}\n{res.stderr}")
    return res


def until(fn, seconds=60):
    end = time.time() + seconds
    while time.time() < end:
        if fn():
            return True
        time.sleep(2)
    return False


def py(container, code, network=None):
    """Run fabriclib code inside a container (a running one, or a fresh one on network)."""
    if network:
        cmd = ["docker", "run", "--rm", "--network", network, "-v", f"{REPO}/src:/fabric-lib:ro",
               "-e", "PYTHONPATH=/fabric-lib", IMAGE, "python3", "-c", code]
    else:
        cmd = ["docker", "exec", "-e", "PYTHONPATH=/fabric-lib", container, "python3", "-c", code]
    return sh(cmd, ok=False).stdout.strip()


sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.ntp.chrony_settings import chrony_settings  # noqa: E402
from fabriclib.ntp.deploy_chrony import deploy_chrony  # noqa: E402
from fabriclib.ntp.normalize_ntp import normalize_ntp  # noqa: E402

env = jinja_env(os.path.join(REPO, "templates"))
lock = read_images_lock(os.path.join(REPO, "config"))


def cleanup():
    for c in ("ntp-srv", "ntp-site"):
        sh(["docker", "rm", "-f", c], ok=False)
    for n in (NET_A, NET_B):
        sh(["docker", "network", "rm", n], ok=False)


# --- settings: what must be refused, and the upstream site first
for bad, why in ((["bad host!"], "a bad host"), (["time.example nts nts"], "a repeated flag"),
                 (["time.example bogus"], "an unknown flag"), (["a.example", "A.example"], "a duplicate host"),
                 ("time.example", "not a list"), ([42], "not a string")):
    try:
        normalize_ntp({"ntp_servers": bad})
        check(f"settings: {why} is refused", False, bad)
    except ValidationError:
        # covers: setting:ntp_servers -
        check(f"settings: {why} is refused", True)
try:
    normalize_ntp({"ntp_servers": [], "ntp_serve": "yes"})
    check("settings: ntp_serve must be a boolean", False)
except ValidationError:
    # covers: setting:ntp_serve -
    check("settings: ntp_serve must be a boolean", True)
got = normalize_ntp({"ntp_servers": ["time.cloudflare.com nts", "192.168.4.1 prefer", "pool.ntp.org pool"]})
# covers: setting:ntp_servers +
check("settings: hosts, addresses and flags parsed",
      got == [{"host": "time.cloudflare.com", "nts": True, "pool": False, "prefer": False},
              {"host": "192.168.4.1", "nts": False, "pool": False, "prefer": True},
              {"host": "pool.ntp.org", "nts": False, "pool": True, "prefer": False}], got)

shutil.rmtree(W, ignore_errors=True)
os.makedirs(W)
reg = os.path.join(W, "federation.yaml")
with open(reg, "w") as f:
    yaml.safe_dump({"upstream": {"site": "lan", "address": SRV_A, "domain": "lan.test"}}, f)
site_v = {"ntp_servers": ["time.cloudflare.com nts"], "lan_cidr": SUB_A, "install_kea": True,
          "dhcp": {"subnets": [{"subnet": "192.168.20.0/24"}]}, "security": {"firewall_allow": ["10.8.0.0/24"]}}
st = chrony_settings(site_v, reg)
check("a site asks its upstream site first, then its own sources",
      [s["host"] for s in st["sources"]] == [SRV_A, "time.cloudflare.com"] and st["sources"][0]["prefer"], st)
# covers: setting:security +
check("it serves the LAN, the VPN and every DHCP subnet, nothing else",
      st["allow"] == [SUB_A, "10.8.0.0/24", "192.168.20.0/24"], st["allow"])

# --- a site serving its network (no sources: its own clock), rendered by deploy_chrony
srv_root, site_root = os.path.join(W, "srv"), os.path.join(W, "site")
srv_v = {"ntp_servers": [], "lan_cidr": SUB_A, "ntp_serve": True, "ntp_set_clock": False}
changed = deploy_chrony(srv_v, os.path.join(W, "none.yaml"), env, root=srv_root, manage_units=False)
conf = open(os.path.join(srv_root, "etc/chrony/chrony.conf")).read()
# covers: setting:lan_cidr setting:ntp_serve +
check("deploy: chrony.conf written; answers the LAN only; own clock as the last resort",
      changed and f"allow {SUB_A}" in conf and SUB_B not in conf and "local stratum 10 orphan" in conf
      and "server " not in conf, conf)
check("deploy: Windows members' time is signed through the DC's socket, in the folder AppArmor allows (2.1.13.1)",
      "ntpsigndsocket /var/lib/samba/ntp_signd" in conf, conf)
# covers: setting:ntp_set_clock +
check("deploy: chrony is told never to set the clock here (-x)",
      '"-F 1 -x"' in open(os.path.join(srv_root, "etc/default/chrony")).read())
check("deploy: chrony-wait never blocks start-up forever",
      "TimeoutStartSec=90" in open(os.path.join(srv_root, "etc/systemd/system/chrony-wait.service.d/fabric.conf")).read())
check("deploy: nothing new, nothing changed",
      not deploy_chrony(srv_v, os.path.join(W, "none.yaml"), env, root=srv_root, manage_units=False))
deploy_chrony({**srv_v, "ntp_set_clock": True}, os.path.join(W, "none.yaml"), env, root=os.path.join(W, "real"),
              manage_units=False)
check("deploy: on a real host chrony sets the clock from its saved time at start (-s, no RTC on a Pi)",
      '"-F 1 -s"' in open(os.path.join(W, "real/etc/default/chrony")).read())
deploy_chrony({**srv_v, "ntp_serve": False}, os.path.join(W, "none.yaml"), env, root=os.path.join(W, "quiet"),
              manage_units=False)
check("deploy: ntp_serve false answers nobody",
      "allow" not in open(os.path.join(W, "quiet/etc/chrony/chrony.conf")).read())
site_reg = os.path.join(W, "site-federation.yaml")
with open(site_reg, "w") as f:
    yaml.safe_dump({"upstream": {"site": "lan", "address": SRV_A}}, f)
deploy_chrony({"ntp_servers": [], "lan_cidr": SUB_A, "ntp_set_clock": False}, site_reg, env, root=site_root,
              manage_units=False)

# --- real chrony
cleanup()
build = os.path.join(W, "build")
os.makedirs(build)
with open(os.path.join(build, "Dockerfile"), "w") as f:
    f.write(f"FROM {lock['debian']['ref']}\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends chrony python3-minimal "
            "&& rm -rf /var/lib/apt/lists/* && mkdir -p /run/chrony /var/log/chrony\n")
sh(["docker", "build", "-q", "-t", IMAGE, build])
sh(["docker", "network", "create", "--subnet", SUB_A, NET_A])
sh(["docker", "network", "create", "--subnet", SUB_B, NET_B])
try:
    sh(["docker", "run", "-d", "--name", "ntp-srv", "--network", NET_A, "--ip", SRV_A,
        "-v", f"{srv_root}/etc/chrony:/etc/chrony:ro", "-v", f"{REPO}/src:/fabric-lib:ro",
        IMAGE, "chronyd", "-d", "-x", "-f", "/etc/chrony/chrony.conf"])
    sh(["docker", "network", "connect", "--ip", SRV_B, NET_B, "ntp-srv"])
    status = {}

    def srv_status():
        status.update(json.loads(py("ntp-srv", "import json; from fabriclib.ntp.time_status import time_status; "
                                               "print(json.dumps(time_status()))") or "{}"))
        return "local" in status
    until(srv_status, 30)
    check("time_status: a site with no source reports its own clock, not synchronised",
          status.get("local") is True and status.get("synced") is False, status)

    offset = py(None, f"from fabriclib.ntp.query_time import query_time; print(query_time('{SRV_A}'))", NET_A)
    try:
        ok = abs(float(offset)) < 1.0
    except ValueError:
        ok = False
    check("query_time: a client on the LAN gets the time (same kernel clock: well under 1 s)", ok, offset)
    refused = py(None, f"from fabriclib.ntp.query_time import query_time; print(query_time('{SRV_B}', 6))", NET_B)
    check("query_time: a network that is not allowed gets no answer", refused == "None", refused)

    # a second site whose upstream is the first: it syncs from it
    sh(["docker", "run", "-d", "--name", "ntp-site", "--network", NET_A, "--ip", SITE_IP,
        "-v", f"{site_root}/etc/chrony:/etc/chrony:ro", "-v", f"{REPO}/src:/fabric-lib:ro",
        IMAGE, "chronyd", "-d", "-x", "-f", "/etc/chrony/chrony.conf"])
    site = {}

    def site_synced():
        site.clear()
        site.update(json.loads(py("ntp-site", "import json; from fabriclib.ntp.time_status import time_status; "
                                              "print(json.dumps(time_status()))") or "{}"))
        return site.get("synced")
    check("a site syncs from its upstream site (federation hierarchy)",
          until(site_synced, 90) and site.get("source") == SRV_A and site.get("stratum") == 11, site)
finally:
    if FAILED:
        print(sh(["docker", "logs", "--tail", "30", "ntp-srv"], ok=False).stderr)
    cleanup()

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
