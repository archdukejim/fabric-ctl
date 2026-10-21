#!/usr/bin/env python3
"""The DNS filter (manual 1.12.2, 1.12.3) with real containers: fabric's BIND image as the authoritative server for a
test zone, AdGuard Home (its pinned image) run as its rendered compose file says from the AdGuardHome.yaml fabric
renders, and the resolver in front of it, from the configuration deploy_resolver writes. The lists are fabric's local
copies, fetched from a local server. Also the settings that must be refused, the move from 0.6's AdGuard Home and the
0.7.0 upgrade of the vars.

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
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/resolver"
NET, SUBNET, GATEWAY = "res_test_net", "10.254.42.0/24", "10.254.42.1"
BIND_IP, RES_IP, AG_IP = "10.254.42.30", "10.254.42.33", "10.254.42.34"
IMAGE = "fabric/bind9:restest"
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
    cmd = ["docker", "run", "-d", "--name", name, "--network", NET, "--ip", ip, "--user", svc["user"],
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

# ---- the move from 0.6's AdGuard Home (manual 2.3.12.1.9, 1.12.3.11)
GEN = "! fabric: the rules above are generated (fabric's own names stay resolvable)"
SET = "! fabric: the rules above are adguard_rules (vars); rules you add in this UI go below"
ADG = {"dns": {"upstream_dns": ["[/lan.test/]10.255.0.30", "https://1.1.1.1/dns-query", "tls://dns.quad9.net",
                                "https://doh.example.net/dns-query", "192.168.1.1"]},
       "filters": [{"enabled": True, "name": "AdGuard DNS filter", "url": "https://x.example/filter_1.txt"},
                   {"enabled": False, "name": "Off list", "url": "https://x.example/off.txt"}],
       "whitelist_filters": [{"name": "Allow list", "url": "https://x.example/allow.txt"}],
       "user_rules": ["@@||lan.test^$important", "@@||192.168.77.53^$important", GEN, "||from-vars.example^", SET,
                      "||ui-block.example^", "@@||ui-allow.example^$important", "/regex/", "plain.example",
                      "||www.lan.test^"],
       "filtering": {"safe_search": {"enabled": True}, "parental_enabled": True,
                     "blocked_services": {"ids": ["tiktok"]}, "rewrites": [{"domain": "nas.home", "answer": "10.0.0.5"}]},
       "clients": {"persistent": [{"name": "kid-tablet", "ids": ["192.168.77.40"]}]},
       "users": [{"name": "fabric", "password": "$2a$10$hash"}]}
VV = {"domain": "lan.test", "org_domain": "lan.test", "ip_bind9": "10.255.0.30"}
from fabriclib.dns_filter.import_adguard_settings import import_adguard_settings  # noqa: E402
imp = import_adguard_settings(ADG, VV)
st = imp["settings"]
check("import: DoH/DoT upstreams of known providers become DoT by address with the certificate name",
      st["dns_filter_upstreams"] == [{"address": "1.1.1.1", "name": "cloudflare-dns.com"},
                                     {"address": "9.9.9.9", "name": "dns.quad9.net"},
                                     {"address": "149.112.112.112", "name": "dns.quad9.net"}], st["dns_filter_upstreams"])
check("import: lists by URL, ticked as they were (a switched-off one comes unticked); the owner's ||name^ and "
      "@@||name^ rules (vars and UI); fabric's own left out",
      st["dns_filter_lists"] == [{"name": "AdGuard DNS filter", "url": "https://x.example/filter_1.txt",
                                  "enabled": True},
                                 {"name": "Off list", "url": "https://x.example/off.txt", "enabled": False}]
      and st["dns_filter_block"] == ["from-vars.example", "ui-block.example"]
      and st["dns_filter_allow"] == ["ui-allow.example"] and st["dns_filter"] == "bind", st)
nc = "\n".join(imp["not_carried"])
check("import: what cannot move is listed — an unknown upstream, plain DNS, an allowlist, regex and exact rules, "
      "parental control, blocked services, a rewrite, a client outside the networks answered",
      all(x in nc for x in ("doh.example.net", "192.168.1.1", "Allow list", "/regex/", "plain.example",
                            "parental", "blocked services", "nas.home", "kid-tablet"))
      and "Off list" not in nc and st["dns_filter_safe_search"] is True and "www.lan.test" not in nc, imp["not_carried"])
none = import_adguard_settings({"dns": {"upstream_dns": ["192.168.1.1"]}}, VV)
check("import: when no upstream can be carried over DoT, Cloudflare's are used, and that is said",
      none["settings"]["dns_filter_upstreams"][0] == {"address": "1.1.1.1", "name": "cloudflare-dns.com"}
      and any("Cloudflare" in x for x in none["not_carried"]), none)
plain = import_adguard_settings(None, {**VV, "adguard_rules": ["||a.example^"]})["settings"]
check("import without AdGuard's config: what the adguard_* settings (or their defaults) would have started",
      plain["dns_filter_upstreams"][0] == {"address": "1.1.1.1", "name": "cloudflare-dns.com"}
      and plain["dns_filter_lists"][0]["name"] == "AdGuard DNS filter" and plain["dns_filter_block"] == ["a.example"])
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
NAMES = ("bind9-resolver", "res-auth", "adguard-filter")
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
         "lan_cidr": "192.168.77.0/24", "fabric_subnet": "10.254.99.0/24", "dns": {"dynamic_zone_var": {}},
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
    sh(f"docker rm -f {' '.join(NAMES)}; docker network rm {NET}", ok=False)
    os.makedirs(f"{W}/bind9/config")
    os.makedirs(f"{W}/bind9/data")
    debian = sh([sys.executable, os.path.join(REPO, "tests", "image_ref.py"), "debian"]).stdout.strip()
    sh(["docker", "build", "-q", "-t", IMAGE, "--build-arg", f"BASE_IMAGE={debian}", f"{REPO}/packaging/images/bind9"])
    with open(f"{W}/bind9/config/named.conf", "w") as f:
        f.write('options { directory "/var/cache/bind"; listen-on { any; }; listen-on-v6 { none; }; recursion no; };\n'
                'zone "lan.test" { type primary; file "/var/lib/bind/db.lan.test"; };\n')
    with open(f"{W}/bind9/data/db.lan.test", "w") as f:
        f.write("$TTL 300\n@ IN SOA ns.lan.test. hostmaster.lan.test. 1 3600 600 86400 300\n@ IN NS ns.lan.test.\n"
                f"ns IN A {BIND_IP}\nwww IN A 10.9.8.7\nads IN A 10.9.8.8\n")
    uid = sh(["docker", "run", "--rm", "--entrypoint", "id", IMAGE, "-u"]).stdout.strip()
    sh(f"chown -R {uid}:{uid} {W}/bind9/data")
    sh(["docker", "network", "create", "--subnet", SUBNET, "--gateway", GATEWAY, NET])
    sh(["docker", "run", "-d", "--name", "res-auth", "--network", NET, "--ip", BIND_IP,
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
    moved = deploy_adguard({**V, "ip_resolver": "10.254.42.99"}, SECRETS, env, sync=False)
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
        sh(f"docker rm -f {' '.join(NAMES)}; docker network rm {NET}", ok=False)

print("\nall passed (0 failures)" if not FAILED else f"\n{FAILED} failed")
sys.exit(1 if FAILED else 0)
