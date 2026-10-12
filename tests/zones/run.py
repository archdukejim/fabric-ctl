#!/usr/bin/env python3
"""Zones added and removed in seconds (manual 1.4.1.3, decision 2.1.4.5) with real containers: fabric's BIND image run
from the configuration fabric renders (its named.conf, keys, ACLs and zone list) and the DNS filter's resolver from
the configuration deploy_resolver writes, both reloaded by the code under test. The code runs from an installed-looking
tree (<out>/zones/fabric/lib), as on a host: fabric-agent's routes (POST /v1/zones, /v1/zones/<key>/delete) as the
console calls them, and the menu (`fabricctl`, DNS Configuration) driven on its standard input.

    sudo python3 tests/zones/run.py          (needs Docker and dig)
"""
import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/zones"
LIB = f"{W}/fabric/lib"
NET, SUBNET, GATEWAY = "zones_test_net", "10.254.44.0/24", "10.254.44.1"
BIND_IP, RES_IP = "10.254.44.30", "10.254.44.33"
IMAGE = "fabric/bind9:zonetest"
SOCK = f"{W}/agent.sock"
FAILED = 0
sys.path[0:0] = [os.path.join(REPO, "src")]


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:600]}"))


def sh(cmd, ok=True, **kw):
    res = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)
    if ok and res.returncode != 0:
        raise SystemExit(f"command failed: {cmd}\n{res.stdout}\n{res.stderr}")
    return res


def dig(server, *args):
    return sh(["dig", "+time=3", "+tries=1", f"@{server}", *args], ok=False).stdout


def short(server, name, rtype="A"):
    return sh(["dig", "+time=3", "+tries=1", "+short", f"@{server}", name, rtype], ok=False).stdout.strip()


def status(server, name, rtype="SOA"):
    out = dig(server, name, rtype)
    return out.split("status: ", 1)[1].split(",", 1)[0] if "status: " in out else "no answer"


def until(fn, seconds=30):
    end = time.time() + seconds
    while time.time() < end:
        if fn():
            return True
        time.sleep(0.5)
    return False


def lib(code, stdin=None):
    """Run Python in the installed tree (its paths: <W>/fabric/config/vars.yaml, ...)."""
    return sh([sys.executable, "-c", f"import sys; sys.path.insert(0, {LIB!r})\n{code}"], ok=False, input=stdin,
              env={**os.environ, "TERM": "dumb"})


class UConn(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(300)
        self.sock.connect(SOCK)


def agent(path, body):
    """POST to fabric-agent as a root peer (the host: no token, the actor from the body)."""
    c = UConn("x")
    c.request("POST", path, body=json.dumps({"actor": "tester", **body}), headers={"Content-Type": "application/json"})
    r = c.getresponse()
    return r.status, json.loads(r.read().decode() or "null")


def vars_dns():
    return json.loads(lib("import json; from fabriclib.common.load_vars import load_vars; "
                          "print(json.dumps(load_vars().get('dns')))").stdout)


# ---- what needs no host: the routes' permissions, the resolver's forward list
from fabriclib.dns_filter.common.filter_zones import filter_zones  # noqa: E402
from fabriclib.rbac.permissions import BUNDLES  # noqa: E402
from fabriclib.rbac.required_permission import required_permission  # noqa: E402

check("permissions: adding and removing a zone need dns:write",
      required_permission("POST", ["zones"]) == "dns:write"
      and required_permission("POST", ["zones", "home.lan", "delete"]) == "dns:write")
check("permissions: the auditor may read zones but not change them",
      "dns:read" in BUNDLES["fabric-auditor"] and "dns:write" not in BUNDLES["fabric-auditor"])
fz = filter_zones({"domain": "lan.test", "dns": {"dynamic_zone_var": {}, "home.lan": {"zone_authority": True}}},
                  {"children": [], "upstream": None})
check("the resolver forwards every zone in dns: to BIND, the site's domain first", fz[0] == "lan.test"
      and "home.lan" in fz and "dynamic_zone_var" not in fz, fz)

# ---- the installed tree, its settings and secrets
SECRETS = {"ca_password": "x", "rndc_secret": "dGVzdC1vbmx5LXJuZGMtc2VjcmV0LTMyLWJ5dGVzISE=",
           "resolver_rndc_secret": "c2VjcmV0LXRlc3Qta2V5LWZvci1mYWJyaWMtcmVzb2x2ZXI=",
           "keycloak_admin_user": "admin", "keycloak_admin_password": "x", "keycloak_db_password": "x",
           "webui_oidc_secret": "x", "tsig_secrets": {}}
VARS = {"deploy_base_dir": W, "domain": "lan.test", "org_domain": "lan.test", "hostname": "pi-core",
        "host_ip": "192.168.77.53", "lan_cidr": "192.168.77.0/24", "fabric_subnet": SUBNET,
        "ip_bind9": BIND_IP, "ip_resolver": RES_IP, "host_ram_capacity": 8, "ad_domain": "corp.test",
        "dns_filter": "bind", "dns_filter_lists": [], "dns_filter_upstreams": [{"address": "1.1.1.1", "name": "cloudflare-dns.com"}],
        "service_users": {"bind": {"uid": 600, "gid": 600}, "resolver": {"uid": 913, "gid": 913}},
        "dns": {"dynamic_zone_var": {"zone_authority": True, "A": [{"name": "www", "ip": "10.9.8.7"}]}}}
agent_proc = None
try:
    sh(f"docker rm -f bind9 bind9-resolver; docker network rm {NET}", ok=False)
    shutil.rmtree(W, ignore_errors=True)
    ignore = shutil.ignore_patterns("__pycache__")
    shutil.copytree(f"{REPO}/src/fabriclib", f"{LIB}/fabriclib", ignore=ignore)
    shutil.copytree(f"{REPO}/src/agent", f"{LIB}/agent", ignore=ignore)
    shutil.copytree(f"{REPO}/templates", f"{W}/fabric/jinja", ignore=ignore)
    for f in ("VERSION", "images.lock.yaml"):
        shutil.copy(f"{REPO}/config/{f}", f"{W}/fabric/{f}")
    os.makedirs(f"{W}/fabric/config")
    import yaml  # noqa: E402
    with open(f"{W}/fabric/config/vars.yaml", "w") as f:
        yaml.safe_dump(VARS, f, sort_keys=False)
    fd = os.open(f"{W}/fabric/config/fabric-secrets.yml", os.O_WRONLY | os.O_CREAT, 0o600)
    with os.fdopen(fd, "w") as f:
        yaml.safe_dump(SECRETS, f)
    for d in ("config", "data", "log", "cache", "ssl"):
        os.makedirs(f"{W}/bind9/{d}")
    os.makedirs(f"{W}/samba/bind")
    for f in ("dlz.conf", "options.conf"):           # no Windows domain: empty includes, as deploy_samba leaves them
        open(f"{W}/samba/bind/{f}", "w").close()
    sh(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
        "-subj", "/CN=dns.lan.test", "-keyout", f"{W}/bind9/ssl/privkey.pem", "-out", f"{W}/bind9/ssl/fullchain.pem"])
    sh(f"chown -R 600:600 {W}/bind9")

    # BIND not running: the quick path refuses, saying why (its files are rendered for the start below)
    r = lib("from fabriclib.dns.publish_zone_list import publish_zone_list\n"
            "try:\n    publish_zone_list(added=('lan.test',))\nexcept Exception as e:\n    print('REFUSED', e)")
    check("BIND not running: the reload is refused, saying why", "REFUSED" in r.stdout and "bind9" in r.stdout,
          r.stdout + r.stderr)
    check("BIND's configuration rendered as apply renders it (zone list, keys, ACLs, the site's zone file)",
          all(os.path.exists(f"{W}/bind9/config/{n}") for n in ("named.conf", "named.conf.zones", "named.conf.keys",
                                                                "named.conf.acl", "rndc.key"))
          and os.path.exists(f"{W}/bind9/data/db.lan.test")
          and oct(os.stat(f"{W}/bind9/config/named.conf.keys").st_mode & 0o777) == "0o600")

    # the containers: BIND from fabric's configuration, the resolver from deploy_resolver's
    debian = sh([sys.executable, os.path.join(REPO, "tests", "image_ref.py"), "debian"]).stdout.strip()
    sh(["docker", "build", "-q", "-t", IMAGE, "--build-arg", f"BASE_IMAGE={debian}", f"{REPO}/packaging/images/bind9"])
    sh(["docker", "network", "create", "--subnet", SUBNET, "--gateway", GATEWAY, NET])
    sh(["docker", "run", "-d", "--name", "bind9", "--network", NET, "--ip", BIND_IP, "--user", "600:600",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--tmpfs", "/run/named:uid=600,gid=600,mode=0755,size=4m", "--tmpfs", "/tmp:noexec,nosuid,size=8m",
        "-v", f"{W}/bind9/config:/etc/bind:ro", "-v", f"{W}/bind9/data:/var/lib/bind",
        "-v", f"{W}/bind9/log:/var/log", "-v", f"{W}/bind9/cache:/var/cache/bind",
        "-v", f"{W}/bind9/ssl:/etc/bind9/ssl:ro", "-v", f"{W}/samba/bind:/etc/bind-samba:ro", IMAGE])
    up = until(lambda: "10.9.8.7" in short(BIND_IP, "www.lan.test"))
    check("BIND starts from fabric's rendered configuration and serves the site's zone", up,
          sh("docker logs --tail 30 bind9", ok=False).stderr)
    r = lib("import json\nfrom fabriclib.common.jinja_env import jinja_env\nfrom fabriclib.common.load_vars import "
            "load_vars\nfrom fabriclib.secrets.load_secrets import load_secrets\nfrom fabriclib.deploy.render_vars "
            "import render_vars\nfrom fabriclib.dns_filter.deploy_resolver import deploy_resolver\n"
            f"env = jinja_env({W + '/fabric/jinja'!r})\ns = load_secrets()\nv, _ = render_vars(env, s, load_vars())\n"
            "deploy_resolver(v, s, {'children': [], 'upstream': None}, env)\nprint('rendered')")
    check("the resolver's configuration rendered", "rendered" in r.stdout, r.stderr[-600:])
    sh(["docker", "run", "-d", "--name", "bind9-resolver", "--network", NET, "--ip", RES_IP, "--user", "913:913",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--tmpfs", "/run/named:uid=913,gid=913,mode=0755,size=4m", "--tmpfs", "/tmp:noexec,nosuid,size=8m",
        "-v", f"{W}/resolver/config:/etc/bind:ro", "-v", f"{W}/resolver/lists:/etc/bind-lists:ro",
        "-v", f"{W}/resolver/tls:/etc/bind-tls:ro", "-v", f"{W}/resolver/log:/var/log/named",
        "-v", f"{W}/resolver/cache:/var/cache/bind", "--entrypoint", "/usr/sbin/named", IMAGE,
        "-f", "-c", "/etc/bind/named.conf"])
    up = until(lambda: "10.9.8.7" in short(RES_IP, "www.lan.test"))
    check("the resolver starts and forwards the site's zone to BIND", up,
          sh("docker logs --tail 30 bind9-resolver", ok=False).stderr)

    # fabric-agent from the tree, as on the host
    agent_proc = subprocess.Popen([sys.executable, f"{LIB}/agent/server.py", "--socket", SOCK, "--socket-gid", "0"],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    until(lambda: os.path.exists(SOCK), 10)

    # ---- add a zone through the agent (the console's route)
    t0 = time.time()
    st, res = agent("/v1/zones", {"name": "Home.LAN.", "hide_public": False})
    took = time.time() - t0
    # covers: agent:post.zones +
    check("add: POST /v1/zones accepts a zone, normalised (lowercase, no trailing dot)",
          st == 200 and res["name"] == "home.lan" and res["resolver"] and not res["public"], (st, res))
    check(f"add: in seconds, not an apply ({took:.1f} s)", took < 30, took)
    check("add: saved in dns: with its ns record (zone_authority)",
          vars_dns().get("home.lan") == {"zone_authority": True}, vars_dns())
    check("add: BIND answers for the zone at once (SOA, and ns.<zone> at host_ip)",
          status(BIND_IP, "home.lan") == "NOERROR" and short(BIND_IP, "ns.home.lan") == "192.168.77.53",
          dig(BIND_IP, "ns.home.lan"))
    check("add: a record in the new zone resolves through the resolver (forwarded to BIND, never filtered)",
          until(lambda: short(RES_IP, "ns.home.lan") == "192.168.77.53", 10), dig(RES_IP, "ns.home.lan"))
    conf = open(f"{W}/resolver/config/named.conf").read()
    check("add: the resolver forwards the zone to BIND in every view, never validating it (unsigned, 2.1.12.7)",
          conf.count('zone "home.lan" { type forward;') == conf.count('view "') and '"home.lan";' in
          conf.split("validate-except {", 1)[-1].split("}", 1)[0])
    audit = open(f"{W}/fabric/archive/audit.log").read()
    check("add: audited", "DNS_ZONE_ADD" in audit and "zone=home.lan" in audit, audit[-300:])

    # ---- refused names: the reason, and nothing changed
    before = vars_dns()
    for name, why, word in (("lan.test", "the site's own domain", "site's own"),
                            ("dhcp.lan.test", "the DHCP zone", "DHCP"),
                            ("corp.test", "the Windows domain's zone", "Windows"),
                            ("7.168.192.in-addr.arpa", "a reverse zone", "reverse"),
                            ("home.lan", "an existing zone", "already"),
                            ("nodots", "a single label", "two labels"),
                            ("bad_name.lan", "not a DNS name", "two labels"),
                            ("shop.example.com", "a public name without the tick", "Hide the public name")):
        st, res = agent("/v1/zones", {"name": name})
        # covers: agent:post.zones -
        check(f"add refused: {why}, saying why, nothing changed",
              st == 400 and word in res["error"] and vars_dns() == before, (st, res))
    st, res = agent("/v1/zones", {"name": 7})
    check("add refused: a name that is not text", st == 400 and "must be text" in res["error"], (st, res))
    st, res = agent("/v1/zones", {"name": "shop.example.com", "hide_public": True})
    check("add: a public name with 'Hide the public name' ticked is served",
          st == 200 and res["public"] and status(BIND_IP, "shop.example.com") == "NOERROR", (st, res))

    # ---- the reload fails: the vars change is rolled back and the reason given
    sh("docker stop bind9-resolver")
    st, res = agent("/v1/zones", {"name": "lab.test"})
    check("add while the resolver cannot reload: refused, saying why",
          st == 400 and "not added" in res["error"] and "resolver" in res["error"], (st, res))
    check("rollback: the zone is not in the vars, BIND does not serve it, its file is gone",
          "lab.test" not in vars_dns() and status(BIND_IP, "lab.test") != "NOERROR"
          and not os.path.exists(f"{W}/bind9/data/db.lab.test"), (vars_dns(), dig(BIND_IP, "lab.test", "SOA")))
    sh("docker start bind9-resolver")
    until(lambda: "10.9.8.7" in short(RES_IP, "www.lan.test"))

    # ---- removal: refused while a TSIG key names the zone, or without the name typed again
    st, res = agent("/v1/tsig", {"name": "home-acme", "zone": "home.lan", "scope": "acme-zone"})
    check("a TSIG key for the new zone is created (the Keys page)", st == 200, (st, res))
    st, res = agent("/v1/zones/home.lan/delete", {"confirm": "home.lan"})
    check("remove refused while a TSIG key names the zone, saying which",
          st == 400 and "TSIG key home-acme" in res["error"] and "home.lan" in vars_dns(), (st, res))
    st, res = agent("/v1/zones", {"name": "keys.test"})
    check("a zone change renders the new key too (BIND's zone list names it): accepted",
          st == 200 and status(BIND_IP, "keys.test") == "NOERROR", (st, res))
    st, _ = agent("/v1/tsig/home-acme/delete", {})
    check("the key removed", st == 200)
    for key, confirm, why, word in (("home.lan", "home.la", "the name typed wrong", "type the zone's name"),
                                    ("dynamic_zone_var", "lan.test", "the site's own zone", "cannot be removed"),
                                    ("nowhere.lan", "nowhere.lan", "an unknown zone", "unknown zone")):
        st, res = agent(f"/v1/zones/{key}/delete", {"confirm": confirm})
        # covers: agent:post.zones.*.delete -
        check(f"remove refused: {why}, saying why", st == 400 and word in res["error"], (st, res))
    st, res = agent("/v1/zones/home.lan/records", {"type": "A", "name": "nas", "ip": "10.9.8.20"})
    check("a record added to the zone (published by the next apply)", st == 200, (st, res))
    st, res = agent("/v1/zones/home.lan/delete", {"confirm": "HOME.LAN"})
    # covers: agent:post.zones.*.delete +
    check("remove: accepted with the name typed again, the record count returned",
          st == 200 and res == {"key": "home.lan", "name": "home.lan", "records": 1}, (st, res))
    check("remove: BIND and the resolver stop answering for it, its zone file is gone",
          status(BIND_IP, "home.lan") != "NOERROR" and short(RES_IP, "ns.home.lan") != "192.168.77.53"
          and not os.path.exists(f"{W}/bind9/data/db.home.lan") and "home.lan" not in vars_dns()
          and 'zone "home.lan"' not in open(f"{W}/resolver/config/named.conf").read(),
          (dig(BIND_IP, "home.lan", "SOA"), dig(RES_IP, "ns.home.lan")))
    audit = open(f"{W}/fabric/archive/audit.log").read()
    check("remove: audited with the records removed", "DNS_ZONE_DELETE" in audit and "10.9.8.20" in audit,
          audit[-300:])

    # ---- the menu (sudo fabricctl, DNS Configuration) reaches the same units
    menu = "from fabriclib.common.load_vars import load_vars\nfrom fabriclib.menu.edit_dns import edit_dns\n" \
           "edit_dns(load_vars())"
    r = lib(menu, stdin="a\nmenu.lan\n\nb\n")
    check("menu: 'a' adds a zone and BIND answers for it", "Zone menu.lan added" in r.stdout
          and status(BIND_IP, "menu.lan") == "NOERROR", r.stdout[-400:] + r.stderr[-400:])
    r = lib(menu, stdin="a\nlan.test\n\nb\n")
    check("menu: 'a' refuses a name BIND already answers for, saying why", "site's own domain" in r.stdout,
          r.stdout[-400:])
    r = lib(menu, stdin="a\nshop.example.net\nn\n\nb\n")
    # covers: ask:menu.dns.hide_public -
    check("menu: a public name asks whether it hides the real one; no is refused",
          "Hide the public name?" in r.stdout and "Tick 'Hide the public name'" in r.stdout, r.stdout[-400:])
    r = lib(menu, stdin="a\nshop.example.org\ny\n\nb\n")
    # covers: ask:menu.dns.hide_public +
    check("menu: a public name with yes to hiding the real one is added and BIND answers for it",
          "Zone shop.example.org added" in r.stdout and status(BIND_IP, "shop.example.org") == "NOERROR",
          r.stdout[-400:] + r.stderr[-400:])
    idx = 1 + [k for k in vars_dns() if k != "dynamic_zone_var"].index("menu.lan") + 1
    r = lib(menu, stdin=f"r\n{idx}\nwrong.lan\n\nb\n")
    # covers: ask:menu.dns.remove_pick ask:menu.dns.remove_confirm -
    check("menu: 'r' shows the record count and refuses a name typed wrong",
          "removes its 0 record(s)" in r.stdout and "type the zone's name" in r.stdout
          and "menu.lan" in vars_dns(), r.stdout[-400:])
    r = lib(menu, stdin=f"r\n{idx}\nmenu.lan\n\nb\n")
    # covers: ask:menu.dns.remove_pick ask:menu.dns.remove_confirm +
    check("menu: 'r' removes the zone once its name is typed again", "Zone menu.lan removed" in r.stdout
          and status(BIND_IP, "menu.lan") != "NOERROR" and "menu.lan" not in vars_dns(), r.stdout[-400:])
    r = lib(menu, stdin="r\n1\n\nb\n")
    check("menu: 'r' refuses the site's own zone", "cannot be removed" in r.stdout, r.stdout[-400:])
    # fabric's own names (2.1.2.22 item 6): the host's A record comes back on every render, so its delete is refused
    # in the menu as in the console, naming the setting it follows
    st, res = agent("/v1/zones/dynamic_zone_var/records", {"type": "A", "name": "pi-core", "ip": "192.168.77.53"})
    pos = 1 + [r["name"] for r in vars_dns()["dynamic_zone_var"]["A"]].index("pi-core")
    r = lib(menu, stdin=f"1\nd\n{pos}\n\nb\nb\n")
    check("menu: deleting one of fabric's own names (the host's A) is refused, naming the setting; it stays",
          st == 200 and "provided by fabric" in r.stdout and "hostname" in r.stdout
          and "pi-core" in [x["name"] for x in vars_dns()["dynamic_zone_var"]["A"]], r.stdout[-600:])
    st, res = agent("/v1/zones/dynamic_zone_var/records/delete", {"type": "A", "index": pos - 1, "name": "pi-core"})
    check("the agent refuses it too (400), saying why", st == 400 and "provided by fabric" in str(res), (st, res))
    r = lib(menu, stdin="1\nd\n1\n\nb\nb\n")
    check("menu: an admin's own record still deletes", "www" not in [x["name"] for x in
                                                                     vars_dns()["dynamic_zone_var"].get("A", [])],
          r.stdout[-400:])
finally:
    if agent_proc:
        agent_proc.terminate()
    sh(f"docker rm -f bind9 bind9-resolver; docker network rm {NET}", ok=False)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
