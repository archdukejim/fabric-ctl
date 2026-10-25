#!/usr/bin/env python3
"""DNS between federation sites (manual 1.9 M4) with two real BIND servers (fabric's image):

the root site `lan` (lan.test) and its site `lab` (lab.lan.test), each configured from fabric's own
templates with the links dns_links derives from a federation registry and fabric's secrets: lan delegates
lab.lan.test (NS + glue), each keeps a secondary copy of the other's zone, transfers are TSIG-signed with
the link's key, and a change on lan reaches lab by NOTIFY. lab's DNS also listens on 5053, the port lan
records for it (a site whose BIND sits behind another resolver on 53). Includes what must be refused (transfers
without the key or with the wrong one).

    sudo python3 tests/federation/dns.py         (needs Docker and dig; run by tests/federation/run.py)
"""
import base64
import os
import shutil
import subprocess
import sys
import time

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
sys.path.insert(0, os.path.join(REPO, "tests", "common"))
import test_run as testrun  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.federation.dns_links import dns_links  # noqa: E402

W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/federation-dns"
NET, SUBNET = testrun.name("fed_dns_net"), f"{testrun.PREFIX}.31.0/24"
IP = {"lan": f"{testrun.PREFIX}.31.10", "lab": f"{testrun.PREFIX}.31.11"}
DOMAIN = {"lan": "lan.test", "lab": "lab.lan.test"}
IMAGE = "fabric/bind9:" + testrun.name("fedtest")
FD = {site: testrun.name(f"fd-{site}") for site in ("lan", "lab")}      # per run (manual 3.1.2.6)
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


def dig(server, *args):
    return sh(["dig", "+time=2", "+tries=1", f"@{IP[server]}", *args], ok=False).stdout


def until(fn, seconds=40):
    end = time.time() + seconds
    while time.time() < end:
        if fn():
            return True
        time.sleep(1)
    return False


env = jinja_env(os.path.join(REPO, "templates"))
KEY = base64.b64encode(os.urandom(32)).decode()


def render(site, records, registry, secrets, extra_port=None):
    """fabric's named.conf.keys/zones and zone file for one site, from its registry and secrets."""
    base = f"{W}/{site}"
    os.makedirs(f"{base}/config", exist_ok=True)
    os.makedirs(f"{base}/data", exist_ok=True)
    with open(f"{base}/federation.yaml", "w") as f:
        yaml.safe_dump(registry, f)
    v = {"domain": DOMAIN[site], "host_ip": IP[site], "dns": {"dynamic_zone_var": records}, "bind_acls": {"lan": ["any"]},
         "tsig_keys": [], "tsig_secrets": {}, "install_kea": False, "reverse_zone_names": []}
    links = dns_links(v, secrets, f"{base}/federation.yaml")
    ctx = {**v, "federation_links": links}
    with open(f"{base}/config/named.conf", "w") as f:
        listen = "listen-on { any; };" + (f" listen-on port {extra_port} {{ any; }};" if extra_port else "")
        f.write('options { directory "/var/cache/bind"; ' + listen + ' listen-on-v6 { none; }; recursion no; };\n'
                'acl "lan" { any; };\n'
                + env.get_template("bind9/config/named.conf.keys.j2").render(**ctx)
                + env.get_template("bind9/config/named.conf.zones.j2").render(**ctx))
    with open(f"{base}/data/db.{DOMAIN[site]}", "w") as f:
        f.write(env.get_template("bind9/data/zone.j2").render(**ctx, zone_name=DOMAIN[site], zone_records=records))
    sh(f"chown -R 53:53 {base}/data")
    return links


def start(site):
    testrun.remove("container", FD[site])      # this run's only
    sh(f"docker run -d --name {FD[site]} --label {testrun.LABEL} --network {NET} --ip {IP[site]} --user 53:53 --cap-drop ALL "
       f"-v {W}/{site}/config:/etc/bind:ro -v {W}/{site}/data:/var/lib/bind --tmpfs /var/cache/bind:uid=53,gid=53 "
       f"--tmpfs /run/named:uid=53,gid=53 {IMAGE}")


try:
    shutil.rmtree(W, ignore_errors=True)
    debian = sh([sys.executable, os.path.join(REPO, "tests", "image_ref.py"), "debian"]).stdout.strip()
    sh(["docker", "build", "-q", "-t", IMAGE, "--build-arg", f"BASE_IMAGE={debian}", f"{REPO}/packaging/images/bind9"])
    testrun.create_network(NET, SUBNET)

    lan_records = {"zone_authority": True, "A": [{"name": "www", "ip": "10.9.9.1"}]}
    lab_records = {"zone_authority": True, "A": [{"name": "printer", "ip": "10.9.9.2"}]}
    lan_links = render("lan", lan_records,
                       {"sites": {"lab": {"domain": "lab.lan.test", "address": IP["lab"], "dns_port": 5053}}, "upstream": None},
                       {"federation_tsig": {"lab": KEY}})
    lab_links = render("lab", lab_records,
                       {"sites": {}, "upstream": {"site_name": "lan", "site": "lab", "domain": "lan.test",
                                                  "address": IP["lan"], "dns_key": "fed-lab"}},
                       {"federation_tsig": {"upstream": KEY}}, extra_port=5053)
    check("links: lan delegates lab.lan.test to lab; lab's upstream is lan, one shared key",
          lan_links["children"][0]["delegate"] and lan_links["children"][0]["label"] == "lab"
          and lab_links["upstream"]["key"] == lan_links["children"][0]["key"] == "fed-lab", (lan_links, lab_links))
    zone = open(f"{W}/lan/data/db.lan.test").read()
    conf = open(f"{W}/lan/config/named.conf").read()
    check("lan transfers lab's zone from lab's DNS port (5053, like a BIND behind the DNS filter)",
          f'primaries {{ {testrun.PREFIX}.31.11 port 5053 key "fed-lab"; }};' in conf
          and f'also-notify {{ {testrun.PREFIX}.31.11 port 5053 key "fed-lab"; }};' in conf, conf[-900:])
    check("lan's zone: NS and glue for lab", "lab                     NS      ns.lab.lan.test." in zone
          and f"ns.lab                  A       {testrun.PREFIX}.31.11" in zone, zone[-600:])
    for site in ("lab", "lan"):
        start(site)
    check("both servers answer for their own zone",
          until(lambda: "10.9.9.1" in dig("lan", "+short", "www.lan.test") and
                "10.9.9.2" in dig("lab", "+short", "printer.lab.lan.test")),
          sh(f"docker logs {FD['lan']}", ok=False).stderr[-600:] + sh(f"docker logs {FD['lab']}", ok=False).stderr[-600:])
    check("lab keeps a secondary copy of lan's zone (answers authoritatively)",
          until(lambda: "10.9.9.1" in dig("lab", "+short", "www.lan.test")), sh(f"docker logs {FD['lab']}", ok=False).stderr[-800:])
    check("lan keeps a secondary copy of lab's zone (transferred over 5053)",
          until(lambda: "10.9.9.2" in dig("lan", "+short", "printer.lab.lan.test")), sh(f"docker logs {FD['lan']}", ok=False).stderr[-800:])
    referral = dig("lan", "+norec", "NS", "lab.lan.test")
    check("lan answers lab.lan.test's NS with ns.lab.lan.test", "ns.lab.lan.test." in referral, referral[-400:])
    check("a zone transfer without the key is refused", "Transfer failed" in dig("lan", "AXFR", "lan.test"))
    wrong = base64.b64encode(os.urandom(32)).decode()
    check("a zone transfer with a wrong key is refused",
          "www.lan.test" not in dig("lan", "-y", f"hmac-sha256:fed-lab:{wrong}", "AXFR", "lan.test"))
    check("a zone transfer with the link's key works",
          "www.lan.test" in dig("lan", "-y", f"hmac-sha256:fed-lab:{KEY}", "AXFR", "lan.test"))
    time.sleep(1.2)                                      # the zone serial is the time: let it move on
    render("lan", {**lan_records, "A": lan_records["A"] + [{"name": "new", "ip": "10.9.9.3"}]},
           {"sites": {"lab": {"domain": "lab.lan.test", "address": IP["lab"], "dns_port": 5053}}, "upstream": None},
           {"federation_tsig": {"lab": KEY}})
    sh(f"docker restart {FD['lan']}")
    check("a change on lan reaches lab's copy (NOTIFY, then a signed transfer)",
          until(lambda: "10.9.9.3" in dig("lab", "+short", "new.lan.test")), sh(f"docker logs {FD['lab']}", ok=False).stderr[-800:])
finally:
    testrun.remove("container", *FD.values())      # this run's only
    testrun.remove("network", NET)
print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
