#!/usr/bin/env python3
"""The `samba` suite, an edit at the top reaching the house (manual 1.10.4.8, 1.10.4.11; decision 2.1.10.11): a root
DC and a site's writable DC joined the way site_join.py joins one; a VLAN and then a reservation written into the
site's plan at the top (the root's DC, as the root's agent) replicate to the site's DC, and the site's fabric, which
polls its own DC's highest USN every 30 s, renders the change into its Kea configuration. Proves: the change reaches
the house's Kea within 30 s of reaching the house's DC (2.1.10.11's contract) and Kea accepts it; refused: a second
claim on the address at the top is refused there, nothing replicates and the house's Kea is left as it was.

The house's poll is fabric's own (`fabriclib.ipam.poll_plan`, 1.10.4.26, built on dev/0.8.0-options and merged into
dev/0.8.0-ipam): its read is the real `read_plan` of the house's DC and its render the real `render_kea` into the
test's folder; only Kea's restart (there is no Kea container here) and the host firewall step are left out, so the test
host is never touched. `poll_once` below is the one call.

    sudo python3 tests/samba/ipam_two_site.py
"""
import base64
import importlib
import os
import subprocess
import sys
import threading
import time

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.dirname(os.path.abspath(__file__))]
# the USN poll (2.1.10.11, 2.1.10.24): one poll of the site's own DC, rendering Kea when what Kea is rendered from
# changed (fabriclib/ipam/poll_plan, manual 1.10.4.26)
POLL_MODULE, POLL_FUNCTION = "fabriclib.ipam.poll_plan", "poll_plan"
CONTRACT = 30          # seconds: the poll's interval, 2.1.10.11
try:
    POLL = getattr(importlib.import_module(POLL_MODULE), POLL_FUNCTION)
except (ImportError, AttributeError) as exc:
    print(f"NOT RUN: the USN poll ({POLL_MODULE}.{POLL_FUNCTION}, built on dev/0.8.0-options) is not on this branch "
          f"({exc})")
    sys.exit(2)

from start_bind import start_bind  # noqa: E402
from start_dc import POLICY, dc_tls, run_dc, start_dc  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.dhcp.check_kea_config import check_kea_config  # noqa: E402
from fabriclib.federation.next_id_block import next_id_block  # noqa: E402
from fabriclib.ipam.add_address import add_address  # noqa: E402
from fabriclib.ipam.add_vlan import add_vlan  # noqa: E402
from fabriclib.ipam.common.site_plan import site_plan  # noqa: E402
from fabriclib.ipam.options.render_kea import render_kea  # noqa: E402
from fabriclib.ipam.read_plan import read_plan  # noqa: E402
from fabriclib.samba.converge_domain import converge_domain  # noqa: E402
from fabriclib.samba.deploy_samba import deploy_samba  # noqa: E402
from fabriclib.samba.finish_join import finish_join  # noqa: E402
from fabriclib.samba.prepare_site import prepare_site  # noqa: E402
from fabriclib.secrets.random_password import random_password  # noqa: E402

W = os.path.join(os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests"), "samba-ipam-two-site")
NET, SUBNET = "ipam2site_net", "10.254.65.0/24"           # free: every tests/**/*.py checked
ROOT, ROOT_IP, ROOT_BIND = "i2root", "10.254.65.10", "i2root-bind"
SITE, SITE_C, SITE_IP, SITE_LAN = "lab", "i2lab", "10.254.65.20", "10.77.0.0/24"
VLAN_NET, RES_IP, RES_MAC = "10.77.20.0/24", "10.77.20.150", "02:00:00:00:77:50"
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[-700:]}"))


def sh(cmd, ok=False, **kw):
    res = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if ok and res.returncode:
        raise SystemExit(f"failed: {cmd[:6]}\n{res.stdout[-1500:]}{res.stderr[-1500:]}")
    return res


def until(pred, timeout=180, step=2):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return False


def cleanup():
    sh(["docker", "rm", "-f", ROOT, ROOT_BIND, SITE_C])
    sh(["docker", "network", "rm", NET])


cleanup()
root = start_dc(os.path.join(W, "root"), ROOT, NET, SUBNET, ROOT_IP, hostname="i2host", dc_name="dc1")
RV, RS, ENV = root["v"], root["secrets"], root["env"]
start_bind(RV, ENV, ROOT, ROOT_BIND)

# ---- the site joins, as site_join.py joins a writable site
block = next_id_block(RV, {"sites": {}}, container=ROOT)
accounts = {kind: random_password() for kind in ("agent", "keycloak", "radius")}
join_pw = random_password()
prepare_site(RV, SITE, [{"name": "lan", "cidr": SITE_LAN}], block, accounts, join_pw, container=ROOT)
work = os.path.join(W, SITE)
sh(["rm", "-rf", work])
V = yaml.safe_load(ENV.get_template("vars.yaml.j2").render(
    domain=f"{SITE}.lan.j-j.family", hostname=f"host-{SITE}", dc_name=f"dc-{SITE}", host_ip=SITE_IP,
    lan_cidr=SITE_LAN, lan_gateway="10.77.0.1", site_name=SITE, ad_domain=RV["ad_domain"], ad_password_policy=POLICY,
    deploy_base_dir=work, ad_ntp_signd_dir=os.path.join(work, "ntp_signd"), ad_dc_type="writable",
    ad_join_server=ROOT_IP, ad_join_server_name=RV["hostname_dc"], posix_id_range=block,
    ad_site_ou=f"OU={SITE},OU=lan,OU=sites", ad_org_ou="OU=organisation,OU=lan,OU=sites",
    install_kea=True, dhcp={"interfaces": ["eth0"], "ddns": False}))
S = {"ad_admin_password": random_password(), **{f"ad_{k}_password": p for k, p in accounts.items()},
     "ad_join": {"user": f"fabric-join-{SITE}", "password": join_pw}}
os.makedirs(os.path.join(work, "stepca", "data", "certs"))
sh(["cp", root["root_ca"], os.path.join(work, "stepca", "data", "certs", "root_ca.crt")], ok=True)
deploy_samba(V, S, ENV)
dc_tls(V, root["root_ca"], root["root_key"])
run_dc(V, SITE_C, NET, ENV, tries=120)
fed = os.path.join(work, "federation.yaml")
with open(fed, "w") as f:
    yaml.safe_dump({"sites": {}, "upstream": {"site_name": "lan"}}, f)
converge_domain(V, fed, S, container=SITE_C)
finish_join(V, S, SITE_C)
check("the site's DC joined the root's domain", "joined" in sh(["docker", "logs", SITE_C]).stdout)


def site_plan_at(container, v, secrets):
    """The site's plan as a DC holds it (empty when not readable yet)."""
    try:
        return site_plan(read_plan(v, secrets, of=SITE, container=container), SITE)
    except ValidationError:
        return {}


def kea_conf():
    try:
        with open(os.path.join(work, "kea", "config", "kea-dhcp4.conf")) as f:
            return f.read()
    except FileNotFoundError:
        return ""


# ---- the house's fabric polls its own DC, as its timer would (2.1.10.11): its settings, kept state, lock and audit
# in the test's folder (deploy_paths reads these at each call), never the host's
os.environ["DEPLOY_BASE_DIR"] = work
os.environ["CUSTOM_VARS_PATH"] = os.path.join(work, "fabric", "config", "vars.yaml")
os.makedirs(os.path.dirname(os.environ["CUSTOM_VARS_PATH"]), exist_ok=True)
with open(os.environ["CUSTOM_VARS_PATH"], "w") as f:
    yaml.safe_dump(V, f)
m_poll = importlib.import_module(POLL_MODULE)
AUDIT = []
m_poll.write_audit = lambda actor, event, detail, source="cli": AUDIT.append((event, detail))
_lock = m_poll._try_lock
m_poll._try_lock = lambda path=None: _lock(os.path.join(work, "fabric", "vars.lock"))
S["kea_ddns_secret"] = base64.b64encode(os.urandom(32)).decode()     # made per run; DDNS is off here


def poll_once():
    """One run of fabric's poll at the house: the real read and render, Kea's restart and the firewall left out."""
    return POLL(V, container=SITE_C, secrets=S, read=read_plan,
                render=lambda secrets, container="samba": render_kea(secrets, container=container,
                                                                     restart=lambda *a, **k: None),
                firewall=lambda: (True, "the test host's firewall is never touched"))


STOP = threading.Event()
POLL_ERRORS = []


def poller():
    while not STOP.is_set():
        try:
            poll_once()
        except Exception as exc:          # a test thread: every failure is reported below
            POLL_ERRORS.append(repr(exc))
        STOP.wait(CONTRACT)


threading.Thread(target=poller, daemon=True).start()

# ---- an edit at the top: a VLAN with its subnet, written on the root's DC into the site's OU
try:
    add_vlan(RV, "root", 20, "iot", site=SITE, subnet=VLAN_NET, secrets=RS, container=ROOT)
    made = ""
except ValidationError as e:
    made = str(e)
check("at the top: a VLAN and its subnet written into the site's plan on the root's DC", not made, made)
check("it replicates to the site's DC", until(lambda: any(s.get("cidr") == VLAN_NET for s in site_plan_at(
    SITE_C, V, S).get("subnets") or []), 900, 5))
check(f"the house's Kea serves the new subnet within {CONTRACT} s of its DC holding it (plus a render)",
      until(lambda: f'"{VLAN_NET}"' in kea_conf(), CONTRACT + 30), (POLL_ERRORS[-3:], kea_conf()[:400]))

# ---- the reservation, timed from the moment the house's DC holds it
add_address(RV, "root", RES_IP, "reservation", site=SITE, name="cam9", mac=RES_MAC, secrets=RS, container=ROOT)
check("at the top: a reservation written into the site's plan", any(
    a["ip"] == RES_IP for s in site_plan_at(ROOT, RV, RS).get("subnets") or [] for a in s.get("addresses") or []))
check("it replicates to the site's DC", until(lambda: any(
    a["ip"] == RES_IP for s in site_plan_at(SITE_C, V, S).get("subnets") or [] for a in s.get("addresses") or []),
    900, 1))
held = time.time()
reached = until(lambda: RES_IP in kea_conf() and RES_MAC in kea_conf(), CONTRACT + 15, 1)
took = time.time() - held
check(f"an edit at the top reaches the house's Kea within {CONTRACT} s of reaching its DC (took {took:.0f} s, render "
      "included)", reached and took <= CONTRACT + 15, (POLL_ERRORS[-3:], kea_conf()[-600:]))
try:
    kea_ok = check_kea_config(V.get("image_kea") or "fabric/kea:local", "kea-dhcp4.conf", kea_conf())
except ValidationError as e:
    kea_ok = str(e)
check("Kea accepts the configuration the house rendered", kea_ok is True, kea_ok)

# ---- refused at the top: nothing replicates, the house's Kea is left as it was
before = kea_conf()
try:
    add_address(RV, "root", RES_IP, "static", site=SITE, name="other", secrets=RS, container=ROOT)
    why = "not refused"
except ValidationError as e:
    why = str(e)
check("refused at the top: a second claim on the reservation's address, naming the first", "cam9" in why
      or RES_IP in why, why)
time.sleep(CONTRACT + 15)
check("nothing reached the house: its Kea configuration is unchanged", kea_conf() == before)
check("the poll ran without errors, and audited each render", not POLL_ERRORS
      and any(e == "IPAM_WATCH_RENDER" for e, _ in AUDIT), (POLL_ERRORS[-3:], AUDIT[-3:]))

STOP.set()
cleanup()
print(f"\n{FAILED} failed" if FAILED else "\nall passed")
sys.exit(1 if FAILED else 0)
