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
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/kea"
NET, SUBNET = "keatest_net", "10.254.23.0/24"
BIND_IP, DDNS_IP = "10.254.23.30", "10.254.23.97"
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
    sh("docker rm -f kt-dhcp4 kt-ddns kt-bind kt-c1 kt-c2 kt-c3 kt-boot >/dev/null 2>&1", ok=False)
    sh(f"docker network rm {NET} >/dev/null 2>&1", ok=False)


cleanup()
shutil.rmtree(W, ignore_errors=True)
os.makedirs(f"{W}/bind9/data")
lock, pkgs = read_images_lock(os.path.join(REPO, "config")), read_packages_lock(os.path.join(REPO, "config"))
DEBIAN, BUSYBOX = lock["debian"]["ref"], \
    "busybox:1.37@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"
k = pkgs["kea"]

# ------------------------------------------------------------------ images
build = sh(["docker", "build", "-q", "-t", "fabric/kea:test", "--build-arg", f"BASE_IMAGE={DEBIAN}",
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
version = sh("docker run --rm --entrypoint /usr/sbin/kea-dhcp4 fabric/kea:test -V", ok=False).stdout
check("Kea 3.0 LTS inside (the pinned version)", version.startswith("3.0."), version[:80])
sh(["docker", "build", "-q", "-t", "fabric/bind9:keatest", "--build-arg", f"BASE_IMAGE={DEBIAN}",
    f"{REPO}/packaging/images/bind9"])

# ------------------------------------------------------------------ fabric's files
V = {"deploy_base_dir": W, "domain": "lan.test", "install_kea": True, "ip_kea_ddns": DDNS_IP, "ip_bind9": BIND_IP,
     "host_ip": BIND_IP, "service_users": {"kea": {"uid": 915, "gid": 915}}, "image_kea": "fabric/kea:test",
     "dhcp": {"interfaces": ["eth0"], "lease_time": 3600,
              "options": [{"name": "time-offset", "data": "3600"}],
              # network boot for clients that say they are "fabricboot" (option 60): next-server, file, TFTP name
              "client_classes": [{"name": "boot-test", "test": "substring(option[60].hex,0,10) == 'fabricboot'",
                                  "next_server": "10.254.23.30", "boot_file_name": "ipxe.efi",
                                  "options": [{"name": "tftp-server-name", "data": "10.254.23.30"}]}],
              "subnets": [{"subnet": SUBNET, "name": "lab", "vlan": 23, "notes": "the test bridge", "id": 7,
                           "pools": ["10.254.23.100 - 10.254.23.150"], "routers": "10.254.23.1",
                           "reservations": [{"mac": "02:00:00:00:00:42", "ip": "10.254.23.42",
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
      check_kea_config("fabric/kea:test", "kea-dhcp4.conf", cfg4) is True and '"id": 7' in cfg4
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
sh(f"chown -R 53:53 {W}/bind9/data")

# ------------------------------------------------------------------ containers
sh(f"docker network create --subnet {SUBNET} --gateway 10.254.23.1 {NET}")
sh(f"docker run -d --name kt-bind --network {NET} --ip {BIND_IP} --user 53:53 --cap-drop ALL "
   f"-v {W}/bind9/config:/etc/bind:ro -v {W}/bind9/data:/var/lib/bind --tmpfs /var/cache/bind:uid=53,gid=53 "
   f"--tmpfs /run/named:uid=53,gid=53 fabric/bind9:keatest")
# production runs kea-dhcp4 in the host network; here it serves the test bridge's eth0,
# with the command from fabric's compose template
import shlex  # noqa: E402
import yaml  # noqa: E402
KEA_CMD = yaml.safe_load(env.get_template("kea/docker-compose.yml.j2").render(
    **V, image_debian="debian", kea_mem_limit="128m",
    packages_lock=pkgs))["services"]["kea-dhcp4"]["command"]


def start_dhcp4():
    sh(f"docker run -d --name kt-dhcp4 --network {NET} --ip 10.254.23.2 --read-only "
       f"--security-opt no-new-privileges:true --cap-drop ALL --cap-add NET_RAW --cap-add NET_BIND_SERVICE --tmpfs /tmp "
       f"-v {W}/kea/config:/config:ro -v {W}/kea/leases:/var/lib/kea -v {W}/kea/run:/run/kea "
       f"fabric/kea:test {shlex.join(KEA_CMD)}")


start_dhcp4()
sh(f"docker run -d --name kt-ddns --network {NET} --ip {DDNS_IP} --user 915:915 --read-only "
   f"--security-opt no-new-privileges:true --cap-drop ALL --tmpfs /tmp --tmpfs /run/kea:uid=915,gid=915 "
   f"-v {W}/kea/config:/config:ro fabric/kea:test /usr/sbin/kea-dhcp-ddns -c /config/kea-dhcp-ddns.conf")
check("kea-dhcp4 runs and creates its control socket", until(lambda: os.path.exists(f"{W}/kea/run/kea4-ctrl-socket")),
      sh("docker logs kt-dhcp4", ok=False).stdout[-800:] + sh("docker logs kt-dhcp4", ok=False).stderr[-800:])


def client(name, mac=None, hostname=None, vendor=None):
    """One DHCP client run; its script prints what it was given (udhcpc's environment: tftp, bootfile, siaddr…)."""
    args = ["docker", "run", "--name", name, "--network", NET, "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW"]
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


ip1, out1 = client("kt-c1", "02:00:00:00:00:11", "laptop1")
check("a client gets an address from the pool", ip1 is not None and ip1.startswith("10.254.23.1"), out1[-400:])


def dig(name):
    return sh(["dig", "+short", f"@{BIND_IP}", name], ok=False).stdout.strip()


check("its hostname is registered in the DHCP subzone (Kea DDNS -> BIND, kea-ddns key)",
      until(lambda: dig("laptop1.dhcp.lan.test") == ip1, 30),
      (dig("laptop1.dhcp.lan.test"), sh("docker logs kt-ddns", ok=False).stdout[-600:]))
check("every client gets the global option (time-offset 3600 s), no boot settings",
      "timezone=3600" in out1 and "tftp=" not in out1, out1[-400:])
ipb, outb = client("kt-boot", "02:00:00:00:00:31", vendor="fabricboot-x86")
check("a client in the boot class gets next-server, the boot file and the TFTP server option",
      ipb is not None and "siaddr=10.254.23.30" in outb and "boot_file=ipxe.efi" in outb
      and "tftp=10.254.23.30" in outb, outb[-500:])
ip2, out2 = client("kt-c2", "02:00:00:00:00:42")
check("a reserved MAC gets its fixed address", ip2 == "10.254.23.42", out2[-400:])
check(f"the lease's PTR is registered too, in fabric's reverse zone {REV} (2.1.10.7)",
      until(lambda: sh(["dig", "+short", f"@{BIND_IP}", "-x", ip1], ok=False).stdout.strip()
            == "laptop1.dhcp.lan.test.", 30), (sh(["dig", "+short", f"@{BIND_IP}", "-x", ip1], ok=False).stdout,
                                               sh("docker logs kt-ddns", ok=False).stdout[-600:]))
ip3, out3 = client("kt-c3", "02:00:00:00:00:13", "laptop1")
time.sleep(3)
check("another client asking for the same name cannot take it over (DHCID)", ip3 and ip3 != ip1
      and dig("laptop1.dhcp.lan.test") == ip1, (ip3, dig("laptop1.dhcp.lan.test")))
leases = list_leases(V)
check("lease list over the control socket shows the clients", any(lease["ip"] == ip1 and lease["hostname"].startswith("laptop1")
      for lease in leases) and any(lease["ip"] == "10.254.23.42" for lease in leases), leases)
evil = sh(f"printf 'server {BIND_IP}\\nzone lan.test\\nupdate add evil.lan.test 60 A 1.2.3.4\\nsend\\n' "
          f"| nsupdate -y hmac-sha256:kea-ddns:{secret} 2>&1", ok=False).stdout
check("the key may not touch anything but the DHCP subzone", "REFUSED" in evil or "NOTAUTH" in evil, evil[-300:])
evil_rev = sh(f"printf 'server {BIND_IP}\\nzone {REV}\\nupdate add 9.{REV} 60 TXT evil\\nsend\\n' "
              f"| nsupdate -y hmac-sha256:kea-ddns:{secret} 2>&1", ok=False).stdout
check("in the reverse zone the key may write PTR and DHCID only (a TXT refused)", "REFUSED" in evil_rev, evil_rev[-300:])


def leases_or_none():
    try:
        return list_leases(V)
    except Exception:
        return []


# a new container over the same run folder (restart, upgrade): the old PID file must not stop it
sh("docker rm -f kt-dhcp4")
start_dhcp4()
check("kea-dhcp4 starts again over the previous container's run folder; leases kept",
      until(lambda: sh("docker inspect -f {{.State.Running}} kt-dhcp4", ok=False).stdout.strip() == "true"
            and os.path.exists(f"{W}/kea/run/kea4-ctrl-socket") and time.sleep(3) is None
            and sh("docker inspect -f {{.State.Running}} kt-dhcp4", ok=False).stdout.strip() == "true"
            and any(lease["ip"] == ip1 for lease in leases_or_none())),
      sh("docker logs kt-dhcp4", ok=False).stderr[-600:])

insp = {c: json.loads(sh(f"docker inspect {c}").stdout)[0] for c in ("kt-dhcp4", "kt-ddns")}
h4, hd = insp["kt-dhcp4"]["HostConfig"], insp["kt-ddns"]["HostConfig"]
check("kea-dhcp4: only NET_RAW + NET_BIND_SERVICE, read-only, no-new-privileges",
      sorted(c.replace("CAP_", "") for c in h4.get("CapAdd") or []) == ["NET_BIND_SERVICE", "NET_RAW"]
      and h4["CapDrop"] == ["ALL"]
      and h4["ReadonlyRootfs"] and "no-new-privileges:true" in h4["SecurityOpt"], h4.get("CapAdd"))
check("kea-ddns: uid 915, no capabilities, read-only",
      insp["kt-ddns"]["Config"]["User"] == "915:915" and not hd.get("CapAdd") and hd["ReadonlyRootfs"])


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
                  "image_kea": "fabric/kea:test", "dhcp": {"interfaces": ["eth0"], "subnets": [
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
check("Kea accepts what the commands made", check_kea_config("fabric/kea:test", "kea-dhcp4.conf", cfg) is True)
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

cleanup()
print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
