#!/usr/bin/env python3
"""The DNS filter (manual 1.12.2, 1.12.3) with real containers: fabric's BIND image as the authoritative server for a
test zone, AdGuard Home (its pinned image) run as its rendered compose file says from the AdGuardHome.yaml fabric
renders, and the resolver in front of it, from the configuration deploy_resolver writes. The lists are fabric's local
copies, fetched from a local server. Also the settings that must be refused.

    sudo python3 tests/resolver/run.py           (needs Docker and dig; the internet checks need Cloudflare)
"""
import http.server
import io
import json
import os
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from contextlib import redirect_stderr, redirect_stdout

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "tests", "common"))
import test_run as testrun  # noqa: E402
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/resolver"
NET, SUBNET, GATEWAY = testrun.name("res_test_net"), f"{testrun.PREFIX}.42.0/24", f"{testrun.PREFIX}.42.1"
BIND_IP, RES_IP, AG_IP = f"{testrun.PREFIX}.42.30", f"{testrun.PREFIX}.42.33", f"{testrun.PREFIX}.42.34"
IMAGE = "fabric/bind9:" + testrun.name("restest")
RES_AUTH = testrun.name("res-auth")
# bind9-resolver and adguard-filter are the product's names (its deploy and sync use them): one such run at a time
# (manual 3.1.2.6), and only this run's are removed
LOCK = testrun.product_names_lock("resolver").__enter__()
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


def dig(*args):
    return sh(["dig", "+time=5", "+tries=1", f"@{RES_IP}", *args], ok=False).stdout


def status(name):
    out = dig(name)
    return out.split("status: ", 1)[1].split(",", 1)[0] if "status: " in out else "no answer"


def product_negative_ttl():
    """The negative-caching TTL fabric's forward zones carry (templates/bind9/data/zone.j2's SOA minimum, 2.1.4.9)."""
    with open(os.path.join(REPO, "templates", "bind9", "data", "zone.j2")) as f:
        line = [ln for ln in f if "; Negative caching TTL" in ln][0]
    return int(line.split(";", 1)[0].split()[-1])


NEG = product_negative_ttl()


def test_zone(serial, extra=""):
    """The authoritative BIND's test zone, with the SOA minimum fabric's zones have."""
    return (f"$TTL 300\n@ IN SOA ns.lan.test. hostmaster.lan.test. {serial} 3600 600 86400 {NEG}\n"
            f"@ IN NS ns.lan.test.\nns IN A {BIND_IP}\nwww IN A 10.9.8.7\nads IN A 10.9.8.8\n"
            f"long 86400 IN A 10.9.8.30\n{extra}")     # a day: the resolver's cache keeps it 300 s (2.1.12.11)


def answer_ttls(name, rtype="A", section="+answer"):
    """The TTLs of one section of the resolver's answer for name (a miss's SOA: section "+authority")."""
    out = dig("+noall", section, name, rtype)
    return [int(f[1]) for f in (ln.split() for ln in out.splitlines()) if len(f) > 1 and f[1].isdigit()]


def publish(serial, extra):
    """A new version of the test zone served by the authoritative BIND (SIGHUP: named reads its zones again)."""
    with open(f"{W}/bind9/data/db.lan.test", "w") as f:
        f.write(test_zone(serial, extra))
    sh(["docker", "kill", "-s", "HUP", RES_AUTH])
    return until(lambda: str(serial) in sh(["dig", "+short", f"@{BIND_IP}", "lan.test", "SOA"], ok=False).stdout, 20)


def until(fn, seconds=90):
    end = time.time() + seconds
    while time.time() < end:
        if fn():
            return True
        time.sleep(1)
    return False


def refused(fn, *args):
    try:
        fn(*args)
    except ValidationError as e:
        return str(e)
    return ""


def run_compose(svc, name, ip, image):
    """A compose service as `docker run` (the hardening as rendered): account, capabilities, sysctls, mounts."""
    cmd = ["docker", "run", "-d", "--name", name, *testrun.labels(), "--network", NET, "--ip", ip, "--user", svc["user"],
           "--cap-drop", "ALL", "--memory", str(svc["mem_limit"])]
    cmd += ["--read-only"] if svc.get("read_only") else []
    cmd += [x for o in svc.get("security_opt") or [] for x in ("--security-opt", o)]
    cmd += [x for c in svc.get("cap_add") or [] for x in ("--cap-add", c)]
    cmd += [x for k, val in (svc.get("sysctls") or {}).items() for x in ("--sysctl", f"{k}={val}")]
    cmd += [x for t in svc.get("tmpfs") or [] for x in ("--tmpfs", t)]
    cmd += [x for vol in svc.get("volumes") or [] for x in ("-v", vol)]
    if svc.get("entrypoint"):
        cmd += ["--entrypoint", svc["entrypoint"][0]]
    return sh(cmd + [image, *(svc.get("entrypoint") or [])[1:], *(svc.get("command") or [])])


sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.dns_filter.check_filter_settings import check_filter_settings  # noqa: E402
from fabriclib.dns_filter.common.adguard_api import adguard_api  # noqa: E402
from fabriclib.dns_filter.common.adguard_desired import adguard_desired  # noqa: E402
from fabriclib.dns_filter.common.adguard_paths import adguard_paths  # noqa: E402
from fabriclib.dns_filter.common.list_id import list_id  # noqa: E402
from fabriclib.dns_filter.common.list_memory import list_memory  # noqa: E402
from fabriclib.dns_filter.common.resolver_rndc import resolver_rndc  # noqa: E402
from fabriclib.dns.changed_names import changed_names  # noqa: E402
from fabriclib.dns_filter.flush_published_names import flush_published_names  # noqa: E402
from fabriclib.dns_filter.deploy_adguard import deploy_adguard  # noqa: E402
from fabriclib.dns_filter.deploy_resolver import deploy_resolver  # noqa: E402
from fabriclib.dns_filter.show_filter_status import show_filter_status  # noqa: E402
from fabriclib.dns_filter.resolver_tls_pending import resolver_tls_pending  # noqa: E402
from fabriclib.dns_filter.sync_adguard import sync_adguard  # noqa: E402
from fabriclib.common.dot_query import dot_query  # noqa: E402
from fabriclib.dns_filter.update_lists import update_lists  # noqa: E402
from fabriclib.dns_filter.run_dns_filter_command import run_dns_filter_command  # noqa: E402
from fabriclib.deploy.check_settings import check_settings  # noqa: E402


def dnsf(v, *argv):
    """fabricctl dns-filter …, as the CLI routes it (fabriclib/cli.py): its exit status and output (stdout and
    stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = run_dns_filter_command(v, list(argv))
    return code, out.getvalue() + err.getvalue()

# ---- settings that must be refused
UP = [{"address": "1.1.1.1", "name": "cloudflare-dns.com"}]
BASE = {"domain": "lan.test", "org_domain": "lan.test", "dns_filter_lists": [], "dns_filter_allow": [],
        "dns_filter_block": [], "dns_filter_upstreams": UP}
_kept = {k: x for k, x in BASE.items() if k != "dns_filter_upstreams"}
check("settings: vars.yaml as saved by an install that kept the default upstreams (none written) is accepted, as "
      "the console's changes check it", refused(check_filter_settings, _kept) == ""
      and refused(check_filter_settings, {**_kept, "dns_filter_upstreams": None}) == "")
for name, bad in (("a list without an http(s) url", {"dns_filter_lists": [{"name": "x", "url": "ftp://x/y"}]}),
                  ("the same list twice", {"dns_filter_lists": [{"url": "https://x/y"}, {"url": "https://x/y"}]}),
                  ("a list ticked neither true nor false", {"dns_filter_lists": [{"url": "https://x/y",
                                                                                  "enabled": "yes"}]}),
                  ("an allow that is not a name", {"dns_filter_allow": ["not a name!"]}),
                  ("a block inside fabric's own domain", {"dns_filter_block": ["www.lan.test"]}),
                  ("a name allowed and blocked", {"dns_filter_allow": ["a.example"], "dns_filter_block": ["A.example."]}),
                  ("no upstream (AdGuard Home needs one)", {"dns_filter_upstreams": []}),
                  ("an upstream without an address", {"dns_filter_upstreams": [{"address": "dns.example", "name": "x.y"}]}),
                  ("an upstream without a certificate name", {"dns_filter_upstreams": [{"address": "1.1.1.1"}]}),
                  ("a group with lists of its own (the lists are the site's)",
                   {"lan_cidr": "192.168.77.0/24", "dns_filter_groups": [
                       {"name": "kids", "clients": ["192.168.77.5"], "lists": [{"url": "https://x/y"}]}]})):
    e = refused(check_filter_settings, {**BASE, **bad})
    # covers: setting:dns_filter_lists setting:dns_filter_allow -
    # covers: setting:dns_filter_block setting:dns_filter_upstreams -
    check(f"settings: {name} is refused, saying why", bool(e), "accepted")
for value, says in (("unbound", "dns_filter must be bind or none (got 'unbound')"),
                    ("adguard", "dns_filter must be bind or none (got 'adguard')")):
    try:
        check_settings({"dns_filter": value, "domain": "lan.test", "org_domain": "lan.test"})
        check(f"settings: dns_filter {value} is refused", False, "accepted")
    except ValidationError as e:
        # covers: setting:dns_filter -
        check(f"settings: dns_filter {value} is refused by the settings check, saying why", says in str(e), e)
ok = {**BASE, "dns_filter_allow": ["Fine.Example."], "dns_filter_block": ["bad.example", "bad.example"]}
check_filter_settings(ok)
# covers: setting:dns_filter_allow setting:dns_filter_block +
check("settings: rules are normalised (lowercase, no trailing dot, no duplicates)",
      ok["dns_filter_allow"] == ["fine.example"] and ok["dns_filter_block"] == ["bad.example"], ok)

# ---- a local server for the lists
LIST_DIR = os.path.join(W, "served")
LIST1 = ("! test list\n||ads.example^\n||lan.test^\n||blocked-then-allowed.example^\n0.0.0.0 hosts-blocked.example\n"
         "||example.org^\n||example.net^\n")


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


def serve():
    handler = lambda *a, **k: Quiet(*a, directory=LIST_DIR, **k)  # noqa: E731
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


internet = sh(["dig", "+time=3", "+tries=1", "@1.1.1.1", "example.com"], ok=False).returncode == 0
env = jinja_env(os.path.join(REPO, "templates"))
USERS = {"resolver": {"uid": 913, "gid": 913}, "adguard": {"uid": 914, "gid": 914}}
SECRETS = {"resolver_rndc_secret": "c2VjcmV0LXRlc3Qta2V5LWZvci1mYWJyaWMtcmVzb2x2ZXI=",
           "adguard_api_password": "TestAdGuardPassw0rdForFabric"}
PW = SECRETS["adguard_api_password"]
NAMES = ("bind9-resolver", RES_AUTH, "adguard-filter")
try:
    shutil.rmtree(W, ignore_errors=True)
    os.makedirs(LIST_DIR)
    with open(os.path.join(LIST_DIR, "one.txt"), "w") as f:
        f.write(LIST1)
    with open(os.path.join(LIST_DIR, "two.txt"), "w") as f:
        f.write("! second list\n||second-list.example^\n")
    srv = serve()
    # fabric's secrets as an install keeps them (the query log asks AdGuard with them)
    os.makedirs(f"{W}/fabric/config")
    with open(f"{W}/fabric/config/fabric-secrets.yml", "w") as f:
        yaml.safe_dump(SECRETS, f)
    os.chmod(f"{W}/fabric/config/fabric-secrets.yml", 0o600)
    # the DNS name's certificate, as mint_service_certs leaves it (a throwaway self-signed one: its own CA)
    os.makedirs(f"{W}/resolver/tls")
    sh(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
        "-subj", "/CN=dns.lan.test", "-addext", "subjectAltName=DNS:dns.lan.test",
        "-keyout", f"{W}/resolver/tls/privkey.pem", "-out", f"{W}/resolver/tls/fullchain.pem"])
    sh(f"chown -R 913:913 {W}/resolver/tls; chmod 600 {W}/resolver/tls/privkey.pem")
    URL1 = f"http://127.0.0.1:{srv.server_port}/one.txt"
    URL2 = f"http://127.0.0.1:{srv.server_port}/two.txt"
    URL404 = f"http://127.0.0.1:{srv.server_port}/missing.txt"
    V = {"deploy_base_dir": W, "service_users": USERS, "domain": "lan.test", "org_domain": "lan.test",
         "host_ip": GATEWAY, "ip_bind9": BIND_IP, "ip_resolver": RES_IP, "ip_adguard": AG_IP,
         "lan_cidr": "192.168.77.0/24", "fabric_subnet": f"{testrun.PREFIX}.99.0/24", "dns": {"dynamic_zone_var": {}},
         "install_resolver": True, "dns_filter": "bind", "resolver_mem_limit": "128m", "adguard_mem_limit": "1024m",
         "dns_filter_lists": [{"name": "Test list", "url": URL1, "enabled": True}],
         "dns_filter_allow": ["blocked-then-allowed.example", "example.net"],
         "dns_filter_block": ["owner-blocked.example"],
         "dns_filter_upstreams": ([{"address": "1.1.1.1", "name": "cloudflare-dns.com"},
                                   {"address": "1.0.0.1", "name": "cloudflare-dns.com"}] if internet else
                                  [{"address": "192.0.2.1", "name": "nowhere.invalid"}]),
         "dns_filter_groups": [], "image_adguard": sh([sys.executable, os.path.join(REPO, "tests", "image_ref.py"),
                                                       "adguard"]).stdout.strip(),
         "published_ref": lambda name: None}
    links = {"children": [], "upstream": None}

    # the lists job: a copy of the site's list (the catalogue's too, given one)
    res = update_lists(V, catalogue=[{"name": "Second", "url": URL2}])
    lid1, lid2 = list_id(URL1), list_id(URL2)
    stf = json.load(open(f"{W}/dnsfilter/state.json"))
    check("lists: a copy of the site's list and of the catalogue's, each with its rules and memory estimate",
          os.path.exists(f"{W}/dnsfilter/lists/{lid1}.txt") and os.path.exists(f"{W}/dnsfilter/lists/{lid2}.txt")
          and stf[lid1]["rules"] == 6 and stf[lid1]["memory_mb"] is not None and not res["failed"], (res, stf))
    check("lists: copies root-owned, readable by AdGuard's group only",
          oct(os.stat(f"{W}/dnsfilter/lists/{lid1}.txt").st_mode & 0o777) == "0o640"
          and os.stat(f"{W}/dnsfilter/lists/{lid1}.txt").st_gid == 914)

    # phase 1: the gateway (this host, as the clients) is not among the allowed networks
    r = deploy_resolver(V, SECRETS, links, env)
    conf = open(f"{W}/resolver/config/named.conf").read()
    check("deploy: the resolver's configuration, rules zones and key written; no list in it",
          r["config"] and "list.rpz" not in conf and not os.path.exists(f"{W}/resolver/lists"), r)
    check("deploy: files root-owned, readable by the resolver's group only; log and cache its own",
          oct(os.stat(f"{W}/resolver/config/rndc.key").st_mode & 0o777) == "0o640"
          and os.stat(f"{W}/resolver/config/rndc.key").st_gid == 913 and os.stat(f"{W}/resolver/log").st_uid == 913)
    check("config: fabric's zone forwarded to the authoritative BIND (never validated: unsigned), the rest to AdGuard "
          "Home, validated (2.1.12.7), passthru zone first",
          f'zone "lan.test" {{ type forward; forward only; forwarders {{ {BIND_IP} port 53; }}; }};' in conf
          and f"forwarders {{ {AG_IP} port 53; }};" in conf and "dnssec-validation auto;" in conf
          and 'validate-except { "lan.test";' in conf
          and conf.index('zone "fabric.rpz";') < conf.index('zone "owner.rpz";'))
    check("config: DoT (853) and DoH (8053, plain: nginx terminates TLS) for clients with the DNS name's certificate",
          'listen-on port 853 tls "clients"' in conf and 'listen-on port 8053 tls none http "doh"' in conf
          and 'cert-file "/etc/bind-tls/fullchain.pem"' in conf and not resolver_tls_pending(V), conf[:900])
    check("deploy again: nothing changes", not deploy_resolver(V, SECRETS, links, env)["config"])
    a = deploy_adguard(V, SECRETS, env, sync=False)
    agconf = yaml.safe_load(open(f"{W}/dnsfilter/conf/AdGuardHome.yaml"))
    check("AdGuard: its file rendered (a first start), owned by its account, unreadable to others",
          a["restart"] and os.stat(f"{W}/dnsfilter/conf/AdGuardHome.yaml").st_uid == 914
          and oct(os.stat(f"{W}/dnsfilter/conf/AdGuardHome.yaml").st_mode & 0o777) == "0o600"
          and oct(os.stat(f"{W}/dnsfilter/render.json").st_mode & 0o777) == "0o600", a)
    check("AdGuard: the site's list as a file, the owner's allows past it, fabric-agent's account (a bcrypt hash, "
          "never the password), only the resolver may ask it",
          [f["url"] for f in agconf["filters"]] == [f"/lists/{lid1}.txt"]
          and agconf["user_rules"] == ["@@||*^$dnstype=DS,important", "@@||blocked-then-allowed.example^$important",
                                      "@@||example.net^$important"]
          and agconf["users"][0]["name"] == "fabric-agent" and agconf["users"][0]["password"].startswith("$2")
          and PW not in open(f"{W}/dnsfilter/conf/AdGuardHome.yaml").read()
          and agconf["dns"]["allowed_clients"] == [RES_IP], agconf.get("filters"))
    again = deploy_adguard(V, SECRETS, env, sync=False)
    check("AdGuard: deployed again, nothing to restart (the password's hash kept)", not again["restart"], again)

    # the containers: the authoritative BIND, AdGuard Home and the resolver as their compose files say
    testrun.remove("container", *NAMES)
    testrun.remove("network", NET)
    os.makedirs(f"{W}/bind9/config")
    os.makedirs(f"{W}/bind9/data")
    debian = sh([sys.executable, os.path.join(REPO, "tests", "image_ref.py"), "debian"]).stdout.strip()
    sh(["docker", "build", "-q", "-t", IMAGE, "--build-arg", f"BASE_IMAGE={debian}", f"{REPO}/packaging/images/bind9"])
    with open(f"{W}/bind9/config/named.conf", "w") as f:
        f.write('options { directory "/var/cache/bind"; listen-on { any; }; listen-on-v6 { none; }; recursion no; };\n'
                'zone "lan.test" { type primary; file "/var/lib/bind/db.lan.test"; };\n')
    with open(f"{W}/bind9/data/db.lan.test", "w") as f:
        f.write(test_zone(1))
    uid = sh(["docker", "run", "--rm", "--entrypoint", "id", IMAGE, "-u"]).stdout.strip()
    sh(f"chown -R {uid}:{uid} {W}/bind9/data")
    testrun.create_network(NET, SUBNET, GATEWAY)
    sh(["docker", "run", "-d", "--name", RES_AUTH, *testrun.labels(), "--network", NET, "--ip", BIND_IP,
        "-v", f"{W}/bind9/config:/etc/bind:ro", "-v", f"{W}/bind9/data:/var/lib/bind", IMAGE])
    ag = yaml.safe_load(env.get_template("dnsfilter/docker-compose.yml.j2").render(**V))["services"]["adguard-filter"]
    t0 = time.time()
    run_compose(ag, "adguard-filter", AG_IP, V["image_adguard"])
    ag_up = until(lambda: sh(["docker", "exec", "adguard-filter", "wget", "-q", "--spider",
                              "http://127.0.0.1:3000/login.html"], ok=False).returncode == 0, 120)
    check("AdGuard Home starts from fabric's file as its own account (no first launch), every capability dropped, "
          "port 53 through the sysctl", ag_up, sh("docker logs --tail 30 adguard-filter", ok=False).stderr)
    print(f"INFO AdGuard answered after {time.time() - t0:.1f} s")
    # a first start reads a list given as a file only at AdGuard's first update; the sync of an apply reads it at once
    first = adguard_api(V, PW, "GET", "/control/filtering/status")["filters"][0]
    synced = sync_adguard(V, PW)
    loaded = adguard_api(V, PW, "GET", "/control/filtering/status")["filters"][0]
    check("a first start: the ticked list not yet read; the sync reads it at once",
          (synced == ["lists read"] or first.get("last_updated")) and loaded.get("rules_count", 0) >= 6
          and loaded.get("last_updated"),
          (first, synced, loaded))
    procs = sh(["docker", "exec", "adguard-filter", "sh", "-c", "grep -E '^(Uid|CapEff)' /proc/1/status"],
               ok=False).stdout
    # Docker gives the added capability to a non-root user too: binding below 1024 is its only one (1.12.3.3)
    check("AdGuard Home's process: its uid, NET_BIND_SERVICE its only capability, nothing published",
          "914" in procs and "CapEff:\t0000000000000400" in procs
          and sh(["docker", "port", "adguard-filter"], ok=False).stdout.strip() == "", procs)
    check("AdGuard Home's API answers fabric-agent's account; the wrong password is refused",
          adguard_api(V, PW, "GET", "/control/status").get("running") is True
          and "401" in refused(adguard_api, V, "wrong-password", "GET", "/control/status"))
    ql = adguard_api(V, PW, "GET", "/control/querylog/config")
    stats = adguard_api(V, PW, "GET", "/control/stats/config")
    check("AdGuard Home's own query log and statistics are off (fabric's are the only ones)",
          ql.get("enabled") is False and stats.get("enabled") is False, (ql, stats))
    rc = yaml.safe_load(env.get_template("resolver/docker-compose.yml.j2").render(**V))["services"]["bind9-resolver"]
    # covers: setting:resolver_mem_limit +
    check("compose: the resolver's own account, no capabilities, read-only, no-new-privileges, 128m, named -f",
          rc["user"] == "913:913" and rc["cap_drop"] == ["ALL"] and rc["read_only"] is True
          and rc["security_opt"] == ["no-new-privileges:true"] and rc["mem_limit"] == "128m"
          and rc["entrypoint"][:2] == ["/usr/sbin/named", "-f"], rc)
    run_compose(rc, "bind9-resolver", RES_IP, IMAGE)
    up = until(lambda: (resolver_rndc(["status"]) or subprocess.CompletedProcess([], 1)).returncode == 0)
    check("the resolver starts and answers rndc with its own key (the health check)", up,
          sh("docker logs --tail 30 bind9-resolver", ok=False).stderr)
    check("a client outside the allowed networks is REFUSED", status("www.lan.test") == "REFUSED", dig("www.lan.test"))

    # phase 2: this host allowed (the firewall's networks); the running resolver reloads it
    V["security"] = {"firewall_allow": [f"{GATEWAY}/32"]}
    r = deploy_resolver(V, SECRETS, links, env)
    check("a settings change is written and reloaded by the running resolver", r["config"] and r["reconfigured"], r)
    # covers: setting:security +
    check("after the reload the host is allowed: fabric's zone answers through the authoritative BIND",
          until(lambda: "10.9.8.7" in dig("+short", "www.lan.test"), 20), dig("www.lan.test"))

    # no cached answer kept more than 5 minutes, a miss neither (2.1.12.11)
    conf = open(f"{W}/resolver/config/named.conf").read()
    opts = conf[conf.index("options {"):conf.index("logging {")]
    check("config: the resolver keeps no answer and no miss more than 300 s (max-cache-ttl, max-ncache-ttl, in "
          "the options: every view)", "max-cache-ttl 300;" in opts and "max-ncache-ttl 300;" in opts, opts)
    check("AdGuard keeps no answer more than 300 s (cache_ttl_max)", agconf["dns"]["cache_ttl_max"] == 300,
          agconf["dns"].get("cache_ttl_max"))
    long_ttls = answer_ttls("long.lan.test") + answer_ttls("long.lan.test")    # asked, then from the cache
    check("a record its zone gives a day (86400 s): through the resolver, asked and then from its cache, its TTL is "
          "never over 300 s", len(long_ttls) == 2 and max(long_ttls) <= 300
          and "86400" in sh(["dig", "+noall", "+answer", f"@{BIND_IP}", "long.lan.test"], ok=False).stdout,
          (long_ttls, dig("long.lan.test")))

    # a name asked before it exists (2.1.4.9): the resolver keeps the NXDOMAIN for the zone's SOA minimum only
    check(f"fabric's zones keep 'no such name' {NEG} s (zone.j2's SOA minimum), not hours", NEG == 30, NEG)
    first = status("late.lan.test")
    asked = time.time()
    published = publish(2, "late IN A 10.9.8.20\n")
    cached = status("late.lan.test")
    came = until(lambda: "10.9.8.20" in dig("+short", "late.lan.test"), NEG + 15)
    waited = time.time() - asked
    check(f"a name published after a client asked: the resolver's cached NXDOMAIN ends within {NEG} s, without a "
          f"flush ({waited:.0f} s)", first == "NXDOMAIN" and published and cached == "NXDOMAIN" and came
          and waited <= NEG + 5, (first, published, cached, came, waited))
    # the apply's flush (dns/changed_names + flush_published_names): the name answers at once
    check("before the flush: another new name is NXDOMAIN through the resolver",
          status("later.lan.test") == "NXDOMAIN", dig("later.lan.test"))
    old = f"{W}/db.lan.test.old"
    shutil.copy(f"{W}/bind9/data/db.lan.test", old)
    published = publish(3, "late IN A 10.9.8.20\nlater IN A 10.9.8.21\n")
    still = status("later.lan.test")
    names = changed_names([("lan.test", f"{W}/bind9/data/db.lan.test", old)])
    flushed = flush_published_names(V, names)
    check("BIND serves it, the resolver still answers its cached NXDOMAIN; after the apply's flush it answers at once "
          "(only the changed name flushed, in every view)",
          published and still == "NXDOMAIN" and names == {"names": ["later.lan.test."], "trees": []}
          and flushed == {"flushed": 1, "error": None} and "10.9.8.21" in dig("+short", "later.lan.test"),
          (published, still, names, flushed, dig("later.lan.test")))
    addr = sh(["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
               "bind9-resolver"], ok=False).stdout.strip()
    # covers: setting:ip_resolver +
    check("the resolver runs on ip_resolver (its compose file's address) and answers clients there",
          rc["networks"]["fabric_net"]["ipv4_address"] == V["ip_resolver"] == addr
          and "10.9.8.7" in sh(["dig", "+time=5", "+tries=1", f"@{addr}", "+short", "www.lan.test"], ok=False).stdout,
          (rc["networks"], addr))
    check("fabric's zone is never filtered, even when a list names it (||lan.test^): AdGuard is never asked",
          "10.9.8.8" in dig("+short", "ads.lan.test"), dig("ads.lan.test"))
    # covers: setting:dns_filter_lists +
    check("a listed name answers NXDOMAIN (from AdGuard), and every name below it",
          until(lambda: status("ads.example") == "NXDOMAIN", 20) and status("deep.sub.ads.example") == "NXDOMAIN")
    check("a hosts line blocks", status("hosts-blocked.example") == "NXDOMAIN")
    check("the owner's block applies (in the resolver)", status("owner-blocked.example") == "NXDOMAIN"
          and status("x.owner-blocked.example") == "NXDOMAIN")
    CA = f"{W}/resolver/tls/fullchain.pem"
    dot = sh(["dig", "+time=5", "+tries=1", "+tls", f"+tls-ca={CA}", "+tls-hostname=dns.lan.test", f"@{RES_IP}",
              "ads.example"], ok=False).stdout
    check("DoT (853) for clients: the certificate verified, and filtered like plain DNS", "status: NXDOMAIN" in dot, dot)
    doh = sh(["dig", "+time=5", "+tries=1", "+http-plain", "-p", "8053", f"@{RES_IP}", "ads.example"], ok=False).stdout
    check("DoH (/dns-query on 8053, as nginx passes it) answers and filters", "status: NXDOMAIN" in doh, doh)
    check("doctor's DoT client (common/dot_query): the answer, the certificate verified for the DNS name",
          dot_query("www.lan.test", "dns.lan.test", RES_IP, CA) == ["10.9.8.7"])
    try:
        dot_query("www.lan.test", "other.lan.test", RES_IP, CA)
        check("doctor's DoT client refuses a certificate for another name", False, "accepted")
    except ssl.SSLError as e:
        check("doctor's DoT client refuses a certificate for another name", "match" in str(e) or "mismatch" in str(e)
              or "CERTIFICATE_VERIFY_FAILED" in str(e), e)
    if internet:
        check("an internet name resolves through AdGuard Home", status("example.com") == "NOERROR", dig("example.com"))
        # the resolver validates (2.1.12.7): broken signatures are refused, a signed answer carries AD
        check("DNSSEC validated: a name with broken signatures (dnssec-failed.org) is refused",
              status("dnssec-failed.org") == "SERVFAIL", dig("dnssec-failed.org"))
        check("DNSSEC validated: a signed name's answer carries AD (example.com)",
              " ad;" in dig("+dnssec", "example.com").split("flags:", 1)[-1].split("QUERY", 1)[0], dig("example.com"))
        # AdGuard's unsigned NXDOMAIN in a signed zone cannot validate: SERVFAIL, still blocked (2.1.12.7)
        check("a listed internet name in a signed zone is blocked though it exists (example.org: SERVFAIL)",
              status("example.org") == "SERVFAIL", dig("example.org"))
        check("the owner's allow beats a list (example.net is listed and allowed: it resolves)",
              status("example.net") == "NOERROR", dig("example.net"))
        # the root zone gives its servers' addresses 3600000 s, .com a miss 900 s: neither kept over 300 s (2.1.12.11)
        root = answer_ttls("a.root-servers.net") + answer_ttls("a.root-servers.net")
        check("an internet answer with a long TTL (a.root-servers.net): through the resolver never over 300 s",
              len(root) == 2 and max(root) <= 300, (root, dig("a.root-servers.net")))
        miss = f"no-such-name-{testrun.RUN}.com"
        neg = answer_ttls(miss, "A", "+authority") + answer_ttls(miss, "A", "+authority")
        check("an internet miss (a name .com does not have): its SOA's TTL through the resolver never over 300 s",
              status(miss) == "NXDOMAIN" and len(neg) == 2 and max(neg) <= 300, (neg, dig(miss)))
    else:
        print("INFO no internet: AdGuard's upstream and the allow over a real name not checked")
    host = adguard_api(V, PW, "GET", "/control/filtering/check_host?" + urllib.parse.urlencode(
        {"name": "blocked-then-allowed.example"}))
    check("AdGuard says the owner's allow passes its list (check_host)", host.get("reason") == "NotFilteredWhiteList",
          host)

    # the query log: the resolver logs each answer; an NXDOMAIN AdGuard gave is marked with its list
    from fabriclib.dns_filter.ingest_dns_log import QUERY, RPZ, _adguard_blocks, _responses, _rows  # noqa: E402
    qlog = open(f"{W}/resolver/log/query.log").read().splitlines()
    rlog = open(f"{W}/resolver/log/rpz.log").read().splitlines()
    q_rows, q_skip = _rows(qlog, QUERY, False)
    r_rows, r_skip = _rows(rlog, RPZ, True)
    resp = _responses(qlog)
    check("the query-log job parses every line BIND wrote: queries, their answers (responselog) and rewrites",
          q_rows and r_rows and resp and q_skip == 0 and r_skip == 0
          and any(x[4] == "ads.example" and x[6] == "NXDOMAIN" for x in resp), (q_skip, r_skip, resp[:2]))
    rewritten = {(x[1], x[2], x[4]) for x in resp if x[4].endswith("owner-blocked.example")}
    rows, err = _adguard_blocks(V, resp, rewritten)
    marked = {row.split("\t")[3]: row.split("\t")[4] for row in rows}
    check("the query log marks AdGuard's block with its list; the owner's block (a rewrite of the resolver's) and a "
          "name that does not exist are not AdGuard's",
          not err and marked.get("ads.example") == f"{lid1}.list.rpz" and "owner-blocked.example" not in marked
          and status("no-such-name.invalid") in ("NXDOMAIN", "SERVFAIL"), (err, marked))

    # ticking and unticking a list: the API, in seconds, nothing restarts
    V["dns_filter_lists"] = [{"name": "Test list", "url": URL1, "enabled": True},
                             {"name": "Second", "url": URL2, "enabled": True}]
    t0 = time.time()
    ch = sync_adguard(V, PW)
    took = time.time() - t0
    check("a list ticked (its copy already fetched) is added through the API in under 2 seconds and blocks",
          took < 2 and ch == ["list added: Second"] and until(lambda: status("second-list.example") == "NXDOMAIN", 10),
          (took, ch))
    V["dns_filter_lists"][1]["enabled"] = False
    ch = sync_adguard(V, PW)
    check("a list unticked stays in AdGuard, off, and no longer blocks", ch == ["list off: Second"]
          and adguard_api(V, PW, "GET", "/control/filtering/check_host?name=second-list.example")["reason"]
          != "FilteredBlackList", ch)
    check("synced again: nothing to change", sync_adguard(V, PW) == [])
    started = sh(["docker", "inspect", "-f", "{{.State.StartedAt}}", "adguard-filter"]).stdout
    a = deploy_adguard(V, SECRETS, env)
    check("an apply after console changes: AdGuard matched through its API, not restarted",
          not a["restart"] and a["synced"] == [] and not a["error"]
          and sh(["docker", "inspect", "-f", "{{.State.StartedAt}}", "adguard-filter"]).stdout == started, a)
    V["dns_filter_upstreams"] = V["dns_filter_upstreams"][:1]
    a = deploy_adguard(V, SECRETS, env)
    # covers: setting:dns_filter_upstreams +
    check("an upstream changed: made through the API, no restart", not a["restart"] and a["synced"] == ["upstreams"], a)
    moved = deploy_adguard({**V, "ip_resolver": f"{testrun.PREFIX}.42.99"}, SECRETS, env, sync=False)
    check("a change outside the API (who may ask it) rewrites the file and asks for a restart", moved["restart"], moved)
    deploy_adguard(V, SECRETS, env, sync=False)          # back to this test's file

    # memory: the rule of 1.12.3.9 (estimate × 2.5 within adguard_mem_limit)
    m = list_memory(V)
    state_file = adguard_paths(V)["state"]
    with open(state_file) as f:
        kept = f.read()
    big = json.loads(kept)
    big.setdefault(lid2, {})["memory_mb"] = 500.0        # as a large list's copy would say
    with open(state_file, "w") as f:
        json.dump(big, f)
    small = list_memory(V, [{"url": URL1}, {"url": URL2}])
    with open(state_file, "w") as f:
        f.write(kept)
    check("memory: the ticked lists fit 1 GiB; a 500 MiB list's peak (x 2.5) with them does not, so it is refused",
          m["fits"] and not small["fits"] and small["peak_mb"] >= 1250 and small["limit_mb"] == 1024.0, (m, small))

    # the lists job: a changed list rereads; a failing or truncated one keeps its last good copy
    with open(os.path.join(LIST_DIR, "one.txt"), "a") as f:
        f.write("||new-entry.example^\n")
    res = update_lists(V)
    adguard_api(V, PW, "POST", "/control/filtering/refresh", {"whitelist": False}, timeout=120)
    check("lists: a changed list gets a new copy, and AdGuard blocks its new entry after the refresh",
          res["changed"] == [lid1] and until(lambda: status("new-entry.example") == "NXDOMAIN", 20), res)
    res = update_lists(V)
    check("lists: an unchanged list is not rewritten", res["changed"] == [] and not res["failed"], res)
    with open(os.path.join(LIST_DIR, "one.txt"), "w") as f:
        f.write("! truncated\n||ads.example^\n")
    res = update_lists(V)
    check("lists: a download with less than half the last copy's rules is refused; the last copy stays",
          res["failed"] == ["Test list"] and "less than half" in res["lists"][lid1]["error"]
          and "new-entry.example" in open(f"{W}/dnsfilter/lists/{lid1}.txt").read(), res["lists"][lid1])
    V["dns_filter_lists"] = [{"name": "Test list", "url": URL1}, {"name": "Missing", "url": URL404}]
    res = update_lists(V)
    check("lists: a list that cannot be fetched fails alone, its error kept",
          "Missing" in res["failed"] and "404" in res["lists"][list_id(URL404)]["error"], res)
    check("AdGuard is given only lists with a copy (the missing one waits)",
          [f["source"] for f in adguard_desired(V)["filters"]] == [URL1])
    check("status: exit 1 while a ticked list has no good copy", show_filter_status(V, PW) == 1)
    code, out = dnsf(V, "status")
    code2, out2 = dnsf(V, "status", "--all")
    # covers: cli:dns-filter.status -
    check("fabricctl dns-filter status: exit 1 naming the list with no good copy and its error; an unknown word "
          "refused with the usage", code == 1 and "Missing: no good copy yet" in out and "404" in out
          and code2 == 2 and "usage: fabricctl dns-filter" in out2, (code, out, code2, out2))
    good = open(f"{W}/dnsfilter/lists/{lid1}.txt").read()
    code, out = dnsf(V, "lists")
    # covers: cli:dns-filter.lists -
    check("fabricctl dns-filter lists: a list that cannot be fetched is reported FAILED with its error, exit 1; the "
          "good list's copy unchanged, still blocking", code == 1 and "Missing: FAILED" in out and "404" in out
          and open(f"{W}/dnsfilter/lists/{lid1}.txt").read() == good
          and not os.path.exists(f"{W}/dnsfilter/lists/{list_id(URL404)}.txt") and status("ads.example") == "NXDOMAIN",
          (code, out))
    V["dns_filter_lists"] = [{"name": "Test list", "url": URL1}]
    check("status: exit 0 when the resolver and AdGuard answer and every ticked list has a copy",
          show_filter_status(V, PW) == 0)
    # fabricctl dns-filter, as the CLI routes it (manual 1.12.2.10)
    with open(os.path.join(LIST_DIR, "one.txt"), "w") as f:     # the last good copy, and one entry more
        f.write(good + "||cli-entry.example^\n")
    code, out = dnsf(V, "lists")
    # covers: cli:dns-filter.lists +
    check("fabricctl dns-filter lists: the changed list's new copy counted, AdGuard's catalogue reported, AdGuard "
          "given the copy, exit 0; the new entry is blocked", code == 0 and "Test list: new copy" in out
          and "AdGuard's catalogue:" in out and until(lambda: status("cli-entry.example") == "NXDOMAIN", 30),
          (code, out))
    code, out = dnsf(V)
    code2, out2 = dnsf(V, "status")
    # covers: cli:dns-filter cli:dns-filter.status setting:install_resolver +
    check("fabricctl dns-filter (status by default): the running resolver and AdGuard Home, their memory limits, "
          "exit 0", code == 0 and code2 == 0 and f"resolver: running   memory limit {V['resolver_mem_limit']}" in out
          and f"AdGuard Home: running   memory limit {V['adguard_mem_limit']}" in out and "Test list" in out
          and out == out2, (code, out, code2, out2))
    state_before = sorted(os.listdir(f"{W}/dnsfilter/lists"))
    off = {**V, "install_resolver": False, "dns_filter": "none"}
    code, out = dnsf(off, "lists")
    code2, out2 = dnsf(V, "restart")
    code3, out3 = dnsf(V, "lists", "--now")
    # covers: cli:dns-filter -
    check("fabricctl dns-filter: lists refused while the filter is off (exit 2, saying so, nothing fetched); an "
          "unknown command or option refused with the usage", code == 2
          and "the DNS filter is off (dns_filter: none)" in out
          and sorted(os.listdir(f"{W}/dnsfilter/lists")) == state_before
          and code2 == 2 and "usage: fabricctl dns-filter" in out2 and code3 == 2 and "usage:" in out3,
          (code, out, code2, out2, code3, out3))
    code, out = dnsf(off, "apply")
    code2, out2 = dnsf(V, "apply", "--now")
    # covers: cli:dns-filter.apply -
    check("fabricctl dns-filter apply: refused while the filter is off (exit 2, saying so); an option it does not "
          "take refused with the usage", code == 2 and "the DNS filter is off (dns_filter: none)" in out
          and code2 == 2 and "usage: fabricctl dns-filter" in out2, (code, out, code2, out2))
    code, out = dnsf(off, "status")
    check("fabricctl dns-filter status with the filter off: says so (install_resolver false)",
          code == 0 and "the DNS filter is off (dns_filter: none)" in out and "resolver: running" not in out, out)
    V["dns_filter_lists"] = []
    deploy_resolver(V, SECRETS, {"children": [], "upstream": None}, env)

    # fail closed: AdGuard stopped, the resolver answers fabric's names and refuses internet ones (SERVFAIL)
    sh("docker stop adguard-filter")
    # BIND gives up on its forwarder after its 10 s query timeout: SERVFAIL (a client may stop waiting first)
    down = dig("+time=20", f"never-asked-{int(time.time())}.example.com")
    check("AdGuard stopped: internet names fail closed (SERVFAIL), never unfiltered; fabric's names still answer",
          "status: SERVFAIL" in down and "10.9.8.7" in dig("+short", "www.lan.test"), down)
    a = deploy_adguard(V, SECRETS, env)
    check("an apply while AdGuard is down: the file written for its next start, the reason kept",
          a["synced"] is None and "not answering" in (a["error"] or ""), a)
    check("status: exit 1 while AdGuard is not answering", show_filter_status(V, PW) == 1)
    t0 = time.time()
    sh("docker start adguard-filter")
    check("AdGuard back: the resolver blocks through it again", until(lambda: status("ads.example") == "NXDOMAIN", 120))
    print(f"INFO AdGuard blocking again {time.time() - t0:.1f} s after its start")
finally:
    if not os.environ.get("KEEP"):           # KEEP=1 leaves the containers to look at
        testrun.remove("container", *NAMES)
        testrun.remove("network", NET)

print("\nall passed (0 failures)" if not FAILED else f"\n{FAILED} failed")
sys.exit(1 if FAILED else 0)
