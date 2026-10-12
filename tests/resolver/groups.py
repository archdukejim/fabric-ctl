#!/usr/bin/env python3
"""The DNS filter's client groups and safe search (manual 1.12.2.15, 1.12.3.6) with real containers: fabric's BIND
image as the authoritative server for a test zone, AdGuard Home and the resolver run as their compose files say from
what deploy_adguard and deploy_resolver write, each group's view reaching AdGuard over DoT with its ClientID (a test CA
and a *.filter certificate), and three clients on their own addresses — a kid (in the kids' subnet group), a teen (an
address group inside that subnet: the most specific wins) and an adult (in no group). Also the group settings that
must be refused and the AdGuard import of clients.

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
BIND_IP, RES_IP, AG_IP = "10.254.43.230", "10.254.43.233", "10.254.43.234"
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
from fabriclib.dns_filter.common.adguard_api import adguard_api  # noqa: E402
from fabriclib.dns_filter.common.resolver_rndc import resolver_rndc  # noqa: E402
from fabriclib.dns_filter.common.safe_search import ENGINES, safe_search_records, safe_search_summary  # noqa: E402
from fabriclib.dns_filter.deploy_adguard import deploy_adguard  # noqa: E402
from fabriclib.dns_filter.deploy_resolver import deploy_resolver  # noqa: E402
from fabriclib.dns_filter.import_adguard_settings import import_adguard_settings  # noqa: E402
from fabriclib.dns_filter.ingest_dns_log import QUERY, RPZ, _rows  # noqa: E402
from fabriclib.dns_filter.resolver_views import resolver_views  # noqa: E402
from fabriclib.dns_filter.sync_adguard import sync_adguard  # noqa: E402
from fabriclib.dns_filter.update_lists import update_lists  # noqa: E402

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
        "dns_filter_upstreams": [{"address": "1.1.1.1", "name": "cloudflare-dns.com"}]}


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
        ("a list of a group's own (lists are the site's: 1.12.3.5)", [group(lists=[{"url": "https://x.example/b.txt"}])]),
        ("a group allow inside fabric's domain", [group(allow=["www.lan.test"])]),
        ("a name allowed and blocked in one group", [group(allow=["a.example"], block=["a.example"])])):
    try:
        check_filter_settings({**BASE, "dns_filter_groups": bad})
        check(f"groups: {name} is refused", False, "accepted")
    except ValidationError as e:
        # covers: setting:dns_filter_groups -
        check(f"groups: {name} is refused, saying why", bool(str(e)), e)
# a group's allow is a passthru in its view and an AdGuard rule; fabric's zones are answered before either, so an allow
# above them hides nothing now (the forward zone per allow went with 1.12.3.6)
above = {**BASE, "dns_filter_groups": [group(allow=["test", "in-addr.arpa"])]}
check_filter_settings(above)
check("groups: an allow above fabric's domain or a reverse zone is accepted (it cannot hide fabric's zones now)",
      above["dns_filter_groups"][0]["allow"] == ["test", "in-addr.arpa"], above["dns_filter_groups"])
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
                                   "safe_search": False, "youtube": "strict", "allow": ["ok.example"],
                                   "block": []}], ok["dns_filter_groups"])

# ---- the views (pure): the most specific address wins
mv = {**BASE, "dns_filter_groups": [
    {"name": "house", "clients": ["192.168.77.0/24"], "safe_search": False, "youtube": "strict", "allow": [],
     "block": []},
    {"name": "kids", "clients": ["192.168.77.0/26"], "safe_search": True, "youtube": "moderate", "allow": [],
     "block": []},
    {"name": "tablet", "clients": ["192.168.77.5"], "safe_search": True, "youtube": "strict", "allow": [],
     "block": []}]}
views = resolver_views(mv)
match = {g["name"]: g["match"] for g in views["groups"]}
check("views: each group excludes the more specific entries of the others, so one client matches one group",
      match == {"house": ["!192.168.77.5", "!192.168.77.0/26", "192.168.77.0/24"],
                "kids": ["!192.168.77.5", "192.168.77.0/26"], "tablet": ["192.168.77.5"]}, match)
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
                "allow": [], "block": []}, gs)
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
# names the shared list blocks: real ones with the internet (so a pass is NOERROR), made-up ones without (a pass then
# fails upstream: anything but NXDOMAIN)
LISTED = "example.org" if internet else "shared-blocked.example"
KID_ALLOWED = "example.net" if internet else "kid-allowed.example"
# example.org's zone is signed: AdGuard's unsigned NXDOMAIN cannot validate there, so the resolver answers SERVFAIL,
# still blocked (2.1.12.7)
BLOCKED = "SERVFAIL" if internet else "NXDOMAIN"
env = jinja_env(os.path.join(REPO, "templates"))
USERS = {"resolver": {"uid": 913, "gid": 913}, "adguard": {"uid": 914, "gid": 914}}
SECRETS = {"resolver_rndc_secret": "c2VjcmV0LXRlc3Qta2V5LWZvci1mYWJyaWMtcmVzb2x2ZXI=",
           "adguard_api_password": "TestAdGuardPassw0rdForFabric"}
PW = SECRETS["adguard_api_password"]
LINKS = {"children": [], "upstream": None}
NAMES = "bind9-resolver resg-auth adguard-filter resg-kid resg-teen resg-adult"
try:
    shutil.rmtree(W, ignore_errors=True)
    os.makedirs(LIST_DIR)
    with open(os.path.join(LIST_DIR, "shared.txt"), "w") as f:
        f.write(f"||{LISTED}^\n||lan.test^\n||{KID_ALLOWED}^\n")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), lambda *a, **k: Quiet(*a, directory=LIST_DIR, **k))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    URL_SHARED = f"http://127.0.0.1:{srv.server_port}/shared.txt"
    V = {"deploy_base_dir": W, "service_users": USERS, "domain": "lan.test", "org_domain": "lan.test",
         "host_ip": GATEWAY, "ip_bind9": BIND_IP, "ip_resolver": RES_IP, "ip_adguard": AG_IP, "lan_cidr": SUBNET,
         "fabric_subnet": "10.254.99.0/24", "dns": {"dynamic_zone_var": {}}, "install_resolver": True,
         "dns_filter": "bind", "resolver_mem_limit": "128m", "adguard_mem_limit": "1024m",
         "dns_filter_lists": [{"name": "Shared", "url": URL_SHARED, "enabled": True}],
         "dns_filter_allow": [], "dns_filter_block": [],
         "dns_filter_upstreams": ([{"address": "1.1.1.1", "name": "cloudflare-dns.com"}] if internet else
                                  [{"address": "192.0.2.1", "name": "nowhere.invalid"}]),
         "dns_filter_groups": [
             {"name": "kids", "clients": ["10.254.43.0/26"], "safe_search": True, "youtube": "strict",
              "allow": [KID_ALLOWED], "block": ["kid-blocked.example"]},
             {"name": "teen", "clients": [CLIENTS["teen"]], "safe_search": True, "youtube": "moderate"}],
         "image_adguard": sh([sys.executable, os.path.join(REPO, "tests", "image_ref.py"), "adguard"]).stdout.strip(),
         "published_ref": lambda name: None}
    check_filter_settings(V)
    # fabric's CA and AdGuard's certificate for filter.<domain> and *.filter.<domain>, as mint_service_certs leaves them
    ca, tls = f"{W}/stepca/data/certs", f"{W}/dnsfilter/tls"
    os.makedirs(ca)
    os.makedirs(tls)
    sh(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
        "-subj", "/CN=Test Root CA", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", f"{W}/ca.key", "-out", f"{ca}/root_ca.crt"])
    sh(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-subj", "/CN=filter.lan.test", "-keyout", f"{tls}/privkey.pem", "-out", f"{W}/filter.csr"])
    with open(f"{W}/ext.cnf", "w") as f:
        f.write("subjectAltName=DNS:filter.lan.test,DNS:*.filter.lan.test\nextendedKeyUsage=serverAuth\n")
    sh(["openssl", "x509", "-req", "-in", f"{W}/filter.csr", "-CA", f"{ca}/root_ca.crt", "-CAkey", f"{W}/ca.key",
        "-CAcreateserial", "-days", "2", "-extfile", f"{W}/ext.cnf", "-out", f"{tls}/fullchain.pem"])
    sh(f"chown -R 914:914 {tls}; chmod 600 {tls}/privkey.pem")
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

    lists = update_lists(V)
    r = deploy_resolver(V, SECRETS, LINKS, env)
    a = deploy_adguard(V, SECRETS, env, sync=False)
    conf = open(f"{W}/resolver/config/named.conf").read()
    kids = conf[conf.index('view "kids"'):conf.index('view "teen"')]
    check("deploy: the list's copy, the group's rules zone, both safe-search zones and AdGuard's file written",
          not lists["failed"] and os.path.exists(f"{W}/resolver/config/group-kids.rpz")
          and os.path.exists(f"{W}/resolver/config/safesearch-strict.rpz")
          and os.path.exists(f"{W}/resolver/config/safesearch-ytmoderate.rpz") and a["restart"], (lists, r, a))
    check("config: the groups' views come before everyone's, the kids' view excludes the teen's address",
          conf.index('view "kids"') < conf.index('view "teen"') < conf.index('view "everyone"')
          and f"match-clients {{ !{CLIENTS['teen']}; 10.254.43.0/26; }};" in conf, conf[:1500])
    check("config: a group's view forwards to AdGuard over DoT naming the group (its ClientID), fabric's CA checked",
          f'forwarders port 853 tls "group-kids" {{ {AG_IP}; }};' in kids and 'remote-hostname "kids.filter.lan.test"'
          in conf and os.path.exists(f"{W}/resolver/config/fabric-root-ca.crt") and "127.0.0.1" not in kids, kids)
    agconf = yaml.safe_load(open(f"{W}/dnsfilter/conf/AdGuardHome.yaml"))
    check("AdGuard: DoT on with the *.filter certificate; each group a client of its own ID with its allow",
          agconf["tls"]["enabled"] is True and agconf["tls"]["server_name"] == "filter.lan.test"
          and [(c["name"], c["ids"]) for c in agconf["clients"]["persistent"]] == [("kids", ["kids"]),
                                                                                    ("teen", ["teen"])]
          and f"@@||{KID_ALLOWED}^$client='kids',important" in agconf["user_rules"], agconf["tls"])

    sh(f"docker rm -f {NAMES}; docker network rm {NET}", ok=False)
    sh(["docker", "network", "create", "--subnet", SUBNET, "--gateway", GATEWAY, NET])
    sh(["docker", "run", "-d", "--name", "resg-auth", "--network", NET, "--ip", BIND_IP,
        "-v", f"{W}/bind9/config:/etc/bind:ro", "-v", f"{W}/bind9/data:/var/lib/bind", IMAGE])
    ag = yaml.safe_load(env.get_template("dnsfilter/docker-compose.yml.j2").render(**V))["services"]["adguard-filter"]
    run_compose(ag, "adguard-filter", AG_IP, V["image_adguard"])
    ag_up = until(lambda: sh(["docker", "exec", "adguard-filter", "wget", "-q", "--spider",
                              "http://127.0.0.1:3000/login.html"], ok=False).returncode == 0, 120)
    check("AdGuard Home starts with DoT for the groups", ag_up, sh("docker logs --tail 30 adguard-filter", ok=False).stderr)
    sync_adguard(V, PW)                                     # reads the list at once (a first start: 1.12.3.3)
    rc = yaml.safe_load(env.get_template("resolver/docker-compose.yml.j2").render(**V))["services"]["bind9-resolver"]
    run_compose(rc, "bind9-resolver", RES_IP, IMAGE)
    for who, ip in CLIENTS.items():
        sh(["docker", "run", "-d", "--name", f"resg-{who}", "--network", NET, "--ip", ip, CLIENT_IMAGE, "sleep", "900"])
    up = until(lambda: (resolver_rndc(["status"]) or subprocess.CompletedProcess([], 1)).returncode == 0)
    check("the resolver starts with the groups' views (BIND takes the configuration)", up,
          sh("docker logs --tail 30 bind9-resolver", ok=False).stderr)

    # fabric's zone, in every view, never filtered
    check("kid: fabric's zone answers in the group's view, even a name the list names (||lan.test^)",
          "10.9.8.7" in dig("kid", "+short", "www.lan.test") and "10.9.8.8" in dig("kid", "+short", "ads.lan.test"))
    # the site's list applies to every group: AdGuard matches it for each
    check("kid, teen and adult: the site's list blocks for everyone (AdGuard over DoT for the groups)",
          until(lambda: status("kid", LISTED) == BLOCKED, 20) and status("teen", LISTED) == BLOCKED
          and status("adult", LISTED) == BLOCKED, dig("kid", LISTED))
    # the group's own policy
    check("kid: the group's block applies (in its view's rules zone)",
          status("kid", "kid-blocked.example") == "NXDOMAIN" and "via kid-blocked.example.group-kids.rpz" in rpz_log())
    before = rpz_log()
    status("adult", "kid-blocked.example")
    time.sleep(1)
    check("adult: the kids' block does not apply (no rewrite logged)", "kid-blocked.example" not in rpz_log()[len(before):])
    kid_status, adult_status = status("kid", KID_ALLOWED), status("adult", KID_ALLOWED)
    check("kid: the group's allow passes the site's list in AdGuard (its ClientID over DoT); the adult is still blocked",
          kid_status != BLOCKED and (kid_status == "NOERROR" or not internet) and adult_status == BLOCKED,
          (kid_status, adult_status))
    host = adguard_api(V, PW, "GET", f"/control/filtering/check_host?name={KID_ALLOWED}&client=kids")
    check("AdGuard: the kids' allow is theirs (check_host as client kids: allowed)",
          host.get("reason") == "NotFilteredWhiteList", host)
    q_rows, q_skip = _rows(open(f"{W}/resolver/log/query.log").read().splitlines(), QUERY, False)
    r_rows, r_skip = _rows(rpz_log().splitlines(), RPZ, True)
    check("the query-log job parses the groups' lines (the view is the group; the zone its rules)",
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
        check("kid: the safe-search target resolves to an address through AdGuard",
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
        print("INFO no internet: the safe-search answers and a pass over a real name not checked")

    # everyone's YouTube level (dns_filter_youtube) with safe search on: the main view loads the moderate zone
    V["dns_filter_safe_search"], V["dns_filter_youtube"] = True, "moderate"
    r = deploy_resolver(V, SECRETS, LINKS, env)
    conf = open(f"{W}/resolver/config/named.conf").read()
    main = conf[conf.index('view "everyone"'):]
    before = rpz_log()

    def adult_moderate():
        yt = dig("adult", "www.youtube.com")
        if internet:
            return "restrictmoderate.youtube.com." in yt
        return "via www.youtube.com.safesearch-ytmoderate.rpz" in rpz_log()[len(before):]
    # covers: setting:dns_filter_youtube +
    check("everyone's YouTube level moderate: the main view loads the moderate safe-search zone, and the adult's "
          "YouTube is rewritten by it in the running resolver", r["reconfigured"]
          and 'zone "safesearch-ytmoderate.rpz"' in main and 'zone "safesearch-strict.rpz"' not in main
          and until(adult_moderate, 20), (r, rpz_log()[len(before):][-600:]))
    V["dns_filter_safe_search"], V["dns_filter_youtube"] = False, "strict"
    deploy_resolver(V, SECRETS, LINKS, env)

    # removing a group removes its view, its rules zone and its AdGuard client
    V["dns_filter_groups"] = [V["dns_filter_groups"][1]]
    r = deploy_resolver(V, SECRETS, LINKS, env)
    synced = sync_adguard(V, PW)
    conf = open(f"{W}/resolver/config/named.conf").read()
    check("deploy: a removed group's view and rules zone go, the resolver reloads; AdGuard's client and allow go",
          'view "kids"' not in conf and not os.path.exists(f"{W}/resolver/config/group-kids.rpz")
          and r["reconfigured"] and "group removed: kids" in synced and "rules" in synced, (r, synced))
    before = rpz_log()
    status("kid", "kid-blocked.example")
    time.sleep(1)
    check("kid: now in no group, answered as everyone (the kids' block gone)",
          "group-kids.rpz" not in rpz_log()[len(before):])
finally:
    if not os.environ.get("KEEP"):
        sh(f"docker rm -f {NAMES}; docker network rm {NET}", ok=False)

print("\nall passed (0 failures)" if not FAILED else f"\n{FAILED} failed")
sys.exit(1 if FAILED else 0)
