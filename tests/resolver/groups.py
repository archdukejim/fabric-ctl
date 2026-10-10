#!/usr/bin/env python3
"""The DNS filter's client groups and safe search (manual 1.12.2.15) with real containers: fabric's BIND image as the
authoritative server for a test zone, the resolver run as its compose file says from what deploy_resolver writes, and
three clients on their own addresses — a kid (in the kids' subnet group), a teen (an address group inside that subnet:
the most specific wins) and an adult (in no group). Also the group settings that must be refused, the memory guard
and the AdGuard import of clients.

    sudo python3 tests/resolver/groups.py        (needs Docker; the safe-search checks need the internet)
"""
import http.server
import os
import shutil
import subprocess
import sys
import threading
import time

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/resolver-groups"
NET, SUBNET, GATEWAY = "resg_test_net", "10.254.43.0/24", "10.254.43.1"
BIND_IP, RES_IP = "10.254.43.230", "10.254.43.233"
CLIENTS = {"kid": "10.254.43.5", "teen": "10.254.43.10", "adult": "10.254.43.100"}
IMAGE = "fabric/bind9:restest"
CLIENT_IMAGE = "fabric/dnsclient:restest"
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


def dig(who, *args):
    return sh(["docker", "exec", f"resg-{who}", "dig", "+time=5", "+tries=1", f"@{RES_IP}", *args], ok=False).stdout


def status(who, name):
    out = dig(who, name)
    return out.split("status: ", 1)[1].split(",", 1)[0] if "status: " in out else "no answer"


def rpz_log():
    with open(f"{W}/resolver/log/rpz.log") as f:
        return f.read()


def until(fn, seconds=90):
    end = time.time() + seconds
    while time.time() < end:
        if fn():
            return True
        time.sleep(1)
    return False


sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.dns_filter.check_filter_settings import check_filter_settings  # noqa: E402
from fabriclib.dns_filter.common.list_zone import list_zone  # noqa: E402
from fabriclib.dns_filter.common.resolver_rndc import resolver_rndc  # noqa: E402
from fabriclib.dns_filter.common.safe_search import ENGINES, safe_search_records, safe_search_summary  # noqa: E402
from fabriclib.dns_filter.deploy_resolver import deploy_resolver  # noqa: E402
from fabriclib.dns_filter.import_adguard_settings import import_adguard_settings  # noqa: E402
from fabriclib.dns_filter.ingest_dns_log import QUERY, RPZ, _rows  # noqa: E402
from fabriclib.dns_filter.resolver_views import resolver_views  # noqa: E402

# ---- the safe-search table (pure): the console's list is the zone's table
strict, moderate = safe_search_records("strict"), safe_search_records("moderate")
summary = safe_search_summary()
check("safe search: the console's engines and name counts are the zone's own",
      [(e["engine"], e["names"]) for e in summary["engines"]] == [(e, len(n)) for e, n, _, _ in ENGINES]
      and sum(e["names"] for e in summary["engines"]) == len(strict) == 251, summary)
check("safe search: strict answers restrict.youtube.com, moderate restrictmoderate; the rest the same",
      ("www.youtube.com", "CNAME", "restrict.youtube.com.") in strict
      and ("www.youtube.com", "CNAME", "restrictmoderate.youtube.com.") in moderate
      and ("www.google.co.uk", "CNAME", "forcesafesearch.google.com.") in moderate
      and ("yandex.ru", "A", "213.180.193.56") in strict and len(strict) == len(moderate))

# ---- group settings that must be refused
BASE = {"domain": "lan.test", "org_domain": "lan.test", "lan_cidr": "192.168.77.0/24",
        "fabric_subnet": "10.255.0.0/24", "dns_filter_lists": [{"name": "Shared", "url": "https://x.example/a.txt"}],
        "dns_filter_upstreams": []}


def group(**kw):
    return {"name": "kids", "clients": ["192.168.77.0/26"], **kw}


for name, bad in (
        ("a group without clients", [group(clients=[])]),
        ("a group named everyone", [group(name="everyone")]),
        ("a group name with capitals or spaces", [group(name="Kid Room")]),
        ("the same group twice", [group(), group(clients=["192.168.77.100"])]),
        ("a client that is not an address", [group(clients=["kid-tablet"])]),
        ("an IPv6 client", [group(clients=["fd00::5"])]),
        ("a subnet with host bits set", [group(clients=["192.168.77.5/24"])]),
        ("a client outside the networks the resolver answers", [group(clients=["10.9.9.9"])]),
        ("a client in fabric's own network", [group(clients=["10.255.0.40"])]),
        ("the chain's own address", [group(clients=["127.0.0.1"])]),
        ("one subnet in two groups", [group(), group(name="other", clients=["192.168.77.0/26"])]),
        ("safe search that is not true or false", [group(safe_search="yes")]),
        ("a YouTube level other than strict or moderate", [group(youtube="off")]),
        ("a group list already on everyone", [group(lists=[{"url": "https://x.example/a.txt"}])]),
        ("a group list without an http(s) url", [group(lists=[{"url": "file:///etc/passwd"}])]),
        ("a group allow inside fabric's domain", [group(allow=["www.lan.test"])]),
        ("a group allow above fabric's domain (it would hide fabric's zone)", [group(allow=["test"])]),
        ("a group allow of a reverse-zone parent", [group(allow=["in-addr.arpa"])]),
        ("a name allowed and blocked in one group", [group(allow=["a.example"], block=["a.example"])])):
    try:
        check_filter_settings({**BASE, "dns_filter_groups": bad})
        check(f"groups: {name} is refused", False, "accepted")
    except ValidationError as e:
        # covers: setting:dns_filter_groups -
        check(f"groups: {name} is refused, saying why", bool(str(e)), e)
for name, bad in (("everyone's safe search that is not true or false", {"dns_filter_safe_search": "on"}),
                  ("everyone's YouTube level other than strict or moderate", {"dns_filter_youtube": "loose"})):
    try:
        check_filter_settings({**BASE, **bad})
        check(f"settings: {name} is refused", False, "accepted")
    except ValidationError as e:
        # covers: setting:dns_filter_safe_search setting:dns_filter_youtube -
        check(f"settings: {name} is refused, saying why", bool(str(e)), e)
ok = {**BASE, "dns_filter_groups": [{"name": " Kids ", "clients": ["192.168.77.0/26", "192.168.77.70/32"],
                                     "allow": ["Ok.Example."]}]}
check_filter_settings(ok)
# covers: setting:dns_filter_groups +
check("groups: normalised (name lowercased, a /32 as an address, defaults: safe search off, YouTube strict)",
      ok["dns_filter_groups"] == [{"name": "kids", "clients": ["192.168.77.0/26", "192.168.77.70"],
                                   "safe_search": False, "youtube": "strict", "lists": [], "allow": ["ok.example"],
                                   "block": []}], ok["dns_filter_groups"])

# ---- the views (pure): the most specific address wins, the memory guard
mv = {**BASE, "resolver_mem_limit": "100m", "dns_filter_groups": [
    {"name": "house", "clients": ["192.168.77.0/24"], "safe_search": False, "youtube": "strict",
     "lists": [{"name": "Big", "url": "https://x.example/big.txt"}], "allow": [], "block": []},
    {"name": "kids", "clients": ["192.168.77.0/26"], "safe_search": True, "youtube": "moderate", "lists": [],
     "allow": [], "block": []},
    {"name": "tablet", "clients": ["192.168.77.5"], "safe_search": True, "youtube": "strict", "lists": [],
     "allow": [], "block": []}]}
shared, big = list_zone("https://x.example/a.txt"), list_zone("https://x.example/big.txt")
views = resolver_views(mv, {shared, big}, {shared: {"memory_mb": 50}, big: {"memory_mb": 20}})
match = {g["name"]: g["match"] for g in views["groups"]}
check("views: each group excludes the more specific entries of the others, so one client matches one group",
      match == {"house": ["!192.168.77.5", "!192.168.77.0/26", "192.168.77.0/24"],
                "kids": ["!192.168.77.5", "192.168.77.0/26"], "tablet": ["192.168.77.5"]}, match)
check("views: a list whose copy would pass 80% of the memory limit is left out and named (16 + 50 + 20 = 86 > 80)",
      [x["zone"] for x in views["lists"]] == [shared] and views["groups"][0]["lists"] == []
      and views["memory"]["left_out"] == [{"view": "house", "zone": big, "name": "Big"}]
      and views["memory"]["estimate_mb"] == 66.0, views["memory"])
check("views: each group's safe-search zone follows its YouTube level; everyone's off",
      [g["safe_zone"] for g in views["groups"]] == [None, "safesearch-ytmoderate.rpz", "safesearch-strict.rpz"]
      and views["safe_zone"] is None)

# ---- the AdGuard import: persistent clients become groups
ADG = {"filtering": {"safe_search": {"enabled": True, "youtube": True}},
       "clients": {"persistent": [
           {"name": "Kid Tablet", "ids": ["192.168.77.40", "aa:bb:cc:dd:ee:ff"], "use_global_settings": False,
            "safe_search": {"enabled": True, "youtube": True}},
           {"name": "Office", "ids": ["192.168.77.128/25"], "use_global_settings": True},
           {"name": "Phone", "ids": ["fd00::7", "phone-1"], "use_global_settings": False}]}}
imp = import_adguard_settings(ADG, {**BASE})
gs = imp["settings"]["dns_filter_groups"]
nc = "\n".join(imp["not_carried"])
check("import: a client with IPv4 ids becomes a group named after it, with its safe search (YouTube moderate)",
      gs[0] == {"name": "kid-tablet", "clients": ["192.168.77.40"], "safe_search": True, "youtube": "moderate",
                "lists": [], "allow": [], "block": []}, gs)
check("import: a client on the global settings takes everyone's safe search; AdGuard's global safe search is "
      "everyone's", gs[1]["name"] == "office" and gs[1]["safe_search"] is True
      and imp["settings"]["dns_filter_safe_search"] is True and imp["settings"]["dns_filter_youtube"] == "moderate", gs)
check("import: MAC addresses, client IDs, IPv6 and a client with nothing usable are listed as not carried",
      all(x in nc for x in ("aa:bb:cc:dd:ee:ff", "fd00::7", "phone-1", "Phone")) and len(gs) == 2, imp["not_carried"])
check("import: the groups pass the settings check", check_filter_settings({**BASE, **imp["settings"]}) is None)

# ---- with real containers
LIST_DIR = os.path.join(W, "served")


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


internet = sh(["dig", "+time=3", "+tries=1", "@1.1.1.1", "example.com"], ok=False).returncode == 0
env = jinja_env(os.path.join(REPO, "templates"))
USERS = {"resolver": {"uid": 913, "gid": 913}}
SECRETS = {"resolver_rndc_secret": "c2VjcmV0LXRlc3Qta2V5LWZvci1mYWJyaWMtcmVzb2x2ZXI="}
LINKS = {"children": [], "upstream": None}
try:
    shutil.rmtree(W, ignore_errors=True)
    os.makedirs(LIST_DIR)
    with open(os.path.join(LIST_DIR, "shared.txt"), "w") as f:
        f.write("||shared-blocked.example^\n||lan.test^\n||kid-allowed.example^\n")
    with open(os.path.join(LIST_DIR, "kids.txt"), "w") as f:
        f.write("||kids-list-blocked.example^\n")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), lambda *a, **k: Quiet(*a, directory=LIST_DIR, **k))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    URL_SHARED = f"http://127.0.0.1:{srv.server_port}/shared.txt"
    URL_KIDS = f"http://127.0.0.1:{srv.server_port}/kids.txt"
    V = {"deploy_base_dir": W, "service_users": USERS, "domain": "lan.test", "org_domain": "lan.test",
         "host_ip": GATEWAY, "ip_bind9": BIND_IP, "ip_resolver": RES_IP, "lan_cidr": SUBNET,
         "fabric_subnet": "10.254.99.0/24", "dns": {"dynamic_zone_var": {}}, "install_resolver": True,
         "dns_filter": "bind", "resolver_mem_limit": "384m",
         "dns_filter_lists": [{"name": "Shared", "url": URL_SHARED}], "dns_filter_allow": [], "dns_filter_block": [],
         "dns_filter_upstreams": ([{"address": "1.1.1.1", "name": "cloudflare-dns.com"},
                                   {"address": "1.0.0.1", "name": "cloudflare-dns.com"}] if internet else []),
         "dns_filter_groups": [
             {"name": "kids", "clients": ["10.254.43.0/26"], "safe_search": True, "youtube": "strict",
              "lists": [{"name": "Kids", "url": URL_KIDS}], "allow": ["kid-allowed.example"],
              "block": ["kid-blocked.example"]},
             {"name": "teen", "clients": [CLIENTS["teen"]], "safe_search": True, "youtube": "moderate"}],
         "published_ref": lambda name: None}
    os.makedirs(f"{W}/bind9/config")
    os.makedirs(f"{W}/bind9/data")
    debian = sh([sys.executable, os.path.join(REPO, "tests", "image_ref.py"), "debian"]).stdout.strip()
    sh(["docker", "build", "-q", "-t", IMAGE, "--build-arg", f"BASE_IMAGE={debian}", f"{REPO}/packaging/images/bind9"])
    # the clients need dig, which fabric's BIND image does not carry
    subprocess.run(["docker", "build", "-q", "-t", CLIENT_IMAGE, "-"], check=True, capture_output=True, text=True,
                   input=f"FROM {debian}\nRUN apt-get update && apt-get install -y --no-install-recommends "
                         "bind9-dnsutils && rm -rf /var/lib/apt/lists/*\n")
    with open(f"{W}/bind9/config/named.conf", "w") as f:
        f.write('options { directory "/var/cache/bind"; listen-on { any; }; listen-on-v6 { none; }; recursion no; };\n'
                'zone "lan.test" { type primary; file "/var/lib/bind/db.lan.test"; };\n')
    with open(f"{W}/bind9/data/db.lan.test", "w") as f:
        f.write("$TTL 300\n@ IN SOA ns.lan.test. hostmaster.lan.test. 1 3600 600 86400 300\n@ IN NS ns.lan.test.\n"
                f"ns IN A {BIND_IP}\nwww IN A 10.9.8.7\nads IN A 10.9.8.8\n")
    uid = sh(["docker", "run", "--rm", "--entrypoint", "id", IMAGE, "-u"]).stdout.strip()
    sh(f"chown -R {uid}:{uid} {W}/bind9/data")

    r = deploy_resolver(V, SECRETS, LINKS, env)
    conf = open(f"{W}/resolver/config/named.conf").read()
    kz = list_zone(URL_KIDS)
    check("deploy: the group's own list fetched; its rules zone and both safe-search zones written",
          os.path.exists(f"{W}/resolver/lists/{kz}") and os.path.exists(f"{W}/resolver/config/group-kids.rpz")
          and os.path.exists(f"{W}/resolver/config/safesearch-strict.rpz")
          and os.path.exists(f"{W}/resolver/config/safesearch-ytmoderate.rpz"), r)
    check("config: the groups' views come before everyone's, the kids' view excludes the teen's address",
          conf.index('view "kids"') < conf.index('view "teen"') < conf.index('view "everyone"')
          and f"match-clients {{ !{CLIENTS['teen']}; 10.254.43.0/26; }};" in conf, conf[:1500])
    check("config: a group's view chains to the main view, does not validate, never caches a blocked answer, and its "
          "own list is loaded only there", "forwarders { 127.0.0.1 port 53; };" in conf
          and conf.count("dnssec-validation no;") == 2 and conf.count("max-ncache-ttl 0;") == 2
          and conf.count(f'zone "{kz}" {{') == 1 and conf.index(f'zone "{kz}" {{') < conf.index('view "teen"'))

    sh(f"docker rm -f bind9-resolver resg-auth resg-kid resg-teen resg-adult; docker network rm {NET}", ok=False)
    sh(["docker", "network", "create", "--subnet", SUBNET, "--gateway", GATEWAY, NET])
    sh(["docker", "run", "-d", "--name", "resg-auth", "--network", NET, "--ip", BIND_IP,
        "-v", f"{W}/bind9/config:/etc/bind:ro", "-v", f"{W}/bind9/data:/var/lib/bind", IMAGE])
    svc = yaml.safe_load(env.get_template("resolver/docker-compose.yml.j2").render(**V))["services"]["bind9-resolver"]
    run = ["docker", "run", "-d", "--name", "bind9-resolver", "--network", NET, "--ip", RES_IP,
           "--user", svc["user"], "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
           "--memory", svc["mem_limit"], "--entrypoint", svc["entrypoint"][0]]
    for t in svc["tmpfs"]:
        run += ["--tmpfs", t]
    for vol in svc["volumes"]:
        run += ["-v", vol]
    sh(run + [IMAGE, *svc["entrypoint"][1:]])
    for who, ip in CLIENTS.items():
        sh(["docker", "run", "-d", "--name", f"resg-{who}", "--network", NET, "--ip", ip, CLIENT_IMAGE, "sleep", "900"])
    up = until(lambda: (resolver_rndc(["status"]) or subprocess.CompletedProcess([], 1)).returncode == 0)
    check("the resolver starts with the groups' views (BIND takes the configuration)", up,
          sh("docker logs --tail 30 bind9-resolver", ok=False).stderr)

    # fabric's zone through the chain, never filtered
    check("kid: fabric's zone answers through the chain, even a name a shared list names (||lan.test^)",
          "10.9.8.7" in dig("kid", "+short", "www.lan.test") and "10.9.8.8" in dig("kid", "+short", "ads.lan.test"))
    # everyone's list applies to every group, and is logged for the main view's hop
    check("kid and teen: a list on everyone blocks for the groups too (groups only add)",
          status("kid", "shared-blocked.example") == "NXDOMAIN" and status("teen", "shared-blocked.example")
          == "NXDOMAIN" and status("adult", "shared-blocked.example") == "NXDOMAIN")
    log = rpz_log()
    check("the main view's rewrite for a group's query is logged from 127.0.0.1 (the collector puts it on the group "
          "query)", "127.0.0.1#" in log and "view everyone: rpz QNAME NXDOMAIN rewrite shared-blocked.example" in log,
          log[-800:])
    n = log.count("127.0.0.1#")
    status("kid", "shared-blocked.example")
    check("a blocked answer is not cached in the group's view: asked again, it passes the main view again",
          until(lambda: rpz_log().count("127.0.0.1#") > n, 5), rpz_log()[-400:])
    # the group's own policy
    check("kid: the group's block and its own list apply to the kids only",
          status("kid", "kid-blocked.example") == "NXDOMAIN" and status("kid", "kids-list-blocked.example")
          == "NXDOMAIN" and "via kid-blocked.example.group-kids.rpz" in rpz_log()
          and f"via kids-list-blocked.example.{kz}" in rpz_log())
    before = rpz_log()
    status("adult", "kid-blocked.example")
    status("adult", "kids-list-blocked.example")
    time.sleep(1)
    after = rpz_log()[len(before):]
    check("adult: the kids' block and list do not apply (no rewrite logged)",
          "kid-blocked.example" not in after and "kids-list-blocked.example" not in after, after)
    before = rpz_log()
    status("kid", "kid-allowed.example")
    status("adult", "kid-allowed.example")
    time.sleep(1)
    after = rpz_log()[len(before):]
    check("kid: the group's allow passes everyone's list (straight to the upstream); the adult is still blocked",
          after.count("rewrite kid-allowed.example") == 1 and f"{CLIENTS['adult']}#" in after
          and "127.0.0.1#" not in after,
          after)
    q_rows, q_skip = _rows(open(f"{W}/resolver/log/query.log").read().splitlines(), QUERY, False)
    r_rows, r_skip = _rows(rpz_log().splitlines(), RPZ, True)
    check("the query-log job parses the groups' lines (the view is the group; the zones its rules and lists)",
          q_skip == 0 and r_skip == 0 and any("\tkids\t" in row for row in q_rows)
          and any(row.endswith("\tgroup-kids.rpz") for row in r_rows), (q_skip, r_skip))
    # the most specific address wins
    status("teen", "www.lan.test")
    time.sleep(1)
    teen = [ln for ln in open(f"{W}/resolver/log/query.log") if f" {CLIENTS['teen']}#" in ln]
    check("teen: the address group wins over the kids' subnet it sits in (every teen query in view teen)",
          teen and all("view teen:" in ln for ln in teen), teen[-3:])
    before = rpz_log()
    status("teen", "kid-blocked.example")
    time.sleep(1)
    check("teen: not in the kids' view", "group-kids.rpz" not in rpz_log()[len(before):], rpz_log()[len(before):])
    if internet:
        check("kid: strict safe search — Google, Bing, DuckDuckGo, YouTube strict, Yandex's family address",
              "forcesafesearch.google.com." in dig("kid", "www.google.com")
              and "strict.bing.com." in dig("kid", "www.bing.com")
              and "safe.duckduckgo.com." in dig("kid", "duckduckgo.com")
              and "restrict.youtube.com." in dig("kid", "www.youtube.com")
              and "213.180.193.56" in dig("kid", "+short", "yandex.ru"), dig("kid", "www.google.com"))
        check("kid: the safe-search target resolves to an address through the main view",
              len(dig("kid", "+short", "www.google.com").split()) >= 2, dig("kid", "www.google.com"))
        check("teen: YouTube moderate, Google still strict",
              "restrictmoderate.youtube.com." in dig("teen", "www.youtube.com")
              and "forcesafesearch.google.com." in dig("teen", "www.google.com"))
        check("adult: nothing rewritten (safe search is off for everyone)",
              "forcesafesearch" not in dig("adult", "www.google.com")
              and "restrict" not in dig("adult", "www.youtube.com"))
        V["dns_filter_safe_search"] = True
        r = deploy_resolver(V, SECRETS, LINKS, env)
        # covers: setting:dns_filter_safe_search +
        check("everyone's safe search: the adult gets strict too, the teen keeps YouTube moderate",
              r["reconfigured"] and until(lambda: "forcesafesearch" in dig("adult", "www.google.com"), 20)
              and "restrictmoderate.youtube.com." in dig("teen", "www.youtube.com"), r)
        V["dns_filter_safe_search"] = False
    else:
        print("INFO no internet: the safe-search answers and the group's allow over a real name not checked")

    # removing a group removes its view and its rules zone
    V["dns_filter_groups"] = [V["dns_filter_groups"][1]]
    r = deploy_resolver(V, SECRETS, LINKS, env)
    conf = open(f"{W}/resolver/config/named.conf").read()
    check("deploy: a removed group's view, rules zone and own list go; the resolver reloads",
          'view "kids"' not in conf and not os.path.exists(f"{W}/resolver/config/group-kids.rpz")
          and not os.path.exists(f"{W}/resolver/lists/{kz}") and r["reconfigured"], r)
    before = rpz_log()
    status("kid", "kid-blocked.example")
    time.sleep(1)
    check("kid: now in no group, answered as everyone (the kids' block gone)",
          "group-kids.rpz" not in rpz_log()[len(before):])
finally:
    sh(f"docker rm -f bind9-resolver resg-auth resg-kid resg-teen resg-adult; docker network rm {NET}", ok=False)

print("\nall passed (0 failures)" if not FAILED else f"\n{FAILED} failed")
sys.exit(1 if FAILED else 0)
