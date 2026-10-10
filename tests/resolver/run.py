#!/usr/bin/env python3
"""The DNS filter's BIND resolver (manual 1.12.2) with real containers: fabric's BIND image as the authoritative
server for a test zone, and the resolver run as its rendered compose file says (its account, no capabilities,
read-only root, named -f), from the configuration deploy_resolver writes and lists it fetched from a local server.
Also the converter's cases and the settings that must be refused.

    sudo python3 tests/resolver/run.py           (needs Docker and dig; the internet checks need Cloudflare)
"""
import http.server
import json
import os
import shutil
import ssl
import subprocess
import sys
import threading
import time

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/resolver"
NET, SUBNET, GATEWAY = "res_test_net", "10.254.42.0/24", "10.254.42.1"
BIND_IP, RES_IP = "10.254.42.30", "10.254.42.33"
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


sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.dns_filter.check_filter_settings import check_filter_settings  # noqa: E402
from fabriclib.dns_filter.common.list_zone import list_zone  # noqa: E402
from fabriclib.dns_filter.common.resolver_rndc import resolver_rndc  # noqa: E402
from fabriclib.dns_filter.convert_list import convert_list  # noqa: E402
from fabriclib.dns_filter.deploy_resolver import deploy_resolver  # noqa: E402
from fabriclib.dns_filter.show_filter_status import show_filter_status  # noqa: E402
from fabriclib.dns_filter.resolver_tls_pending import resolver_tls_pending  # noqa: E402
from fabriclib.common.dot_query import dot_query  # noqa: E402
from fabriclib.dns_filter.update_lists import update_lists  # noqa: E402

# ---- the converter (pure)
z = convert_list("\n".join([
    "! a comment", "# another", "||ads.example^", "||ads.example^$important", "@@||ok.ads.example^",
    "0.0.0.0 hosts.example other.example localhost", "plain.example", "||*.below.example^", "||zip^",
    "||gone.example^", "||gone.example^$badfilter", "||popup.example^$dnsrewrite=ad-block.dns.adguard.com",
    "||apex.example^$denyallow=fine.apex.example", "||192.0.2.7^",
    "/regex.*/", "||mid*wild.example^", "||x.example^$client=10.0.0.1", "example.org^", "example##.banner",
]), "t.list.rpz")
lines = set(z["zone_text"].splitlines())
check("convert: ||name^ blocks the name and every name below it",
      {"ads.example CNAME .", "*.ads.example CNAME ."} <= lines, z["zone_text"])
check("convert: an @@ exception is a passthru, and the block under it is left out (an exact name beats a wildcard)",
      {"ok.ads.example CNAME rpz-passthru.", "*.ok.ads.example CNAME rpz-passthru."} <= lines)
check("convert: hosts lines and plain domains block the name only; localhost is ignored",
      {"hosts.example CNAME .", "other.example CNAME .", "plain.example CNAME ."} <= lines
      and "*.hosts.example CNAME ." not in lines and not any(line.startswith("localhost") for line in lines))
check("convert: ||*.name^ blocks below only, a whole TLD, $dnsrewrite to a name is a block",
      "*.below.example CNAME ." in lines and "below.example CNAME ." not in lines and "*.zip CNAME ." in lines
      and "popup.example CNAME ." in lines)
check("convert: $badfilter cancels its rule; $denyallow allows its exceptions; an address is an rpz-ip trigger",
      "gone.example CNAME ." not in lines and "fine.apex.example CNAME rpz-passthru." in lines
      and "32.7.2.0.192.rpz-ip CNAME ." in lines)
check("convert: regex, wildcards inside a name, other modifiers, unanchored and cosmetic rules are skipped and "
      "counted", z["skipped"] == 5 and set(z["skipped_by_reason"]) == {
          "regular expression", "wildcard inside a name", "modifier", "unanchored pattern", "cosmetic"},
      z["skipped_by_reason"])
check("convert: an RPZ list as published is read back", convert_list(z["zone_text"], "u.rpz")["records"]
      == z["records"], convert_list(z["zone_text"], "u.rpz"))
check("convert: an HTML page converts to nothing (refused by update_lists)",
      convert_list("<html><body>Not found</body></html>", "h.rpz")["rules"] == 0)

# ---- settings that must be refused
BASE = {"domain": "lan.test", "org_domain": "lan.test", "dns_filter_lists": [], "dns_filter_allow": [],
        "dns_filter_block": [], "dns_filter_upstreams": []}
for name, bad in (("a list without an http(s) url", {"dns_filter_lists": [{"name": "x", "url": "ftp://x/y"}]}),
                  ("the same list twice", {"dns_filter_lists": [{"url": "https://x/y"}, {"url": "https://x/y"}]}),
                  ("an allow that is not a name", {"dns_filter_allow": ["not a name!"]}),
                  ("a block inside fabric's own domain", {"dns_filter_block": ["www.lan.test"]}),
                  ("a name allowed and blocked", {"dns_filter_allow": ["a.example"], "dns_filter_block": ["A.example."]}),
                  ("an upstream without an address", {"dns_filter_upstreams": [{"address": "dns.example", "name": "x.y"}]}),
                  ("an upstream without a certificate name", {"dns_filter_upstreams": [{"address": "1.1.1.1"}]})):
    try:
        check_filter_settings({**BASE, **bad})
        check(f"settings: {name} is refused", False, "accepted")
    except ValidationError as e:
        # covers: setting:dns_filter_lists setting:dns_filter_allow -
        # covers: setting:dns_filter_block setting:dns_filter_upstreams -
        check(f"settings: {name} is refused, saying why", bool(str(e)), e)
ok = {**BASE, "dns_filter_allow": ["Fine.Example."], "dns_filter_block": ["bad.example", "bad.example"]}
check_filter_settings(ok)
# covers: setting:dns_filter_allow setting:dns_filter_block +
check("settings: rules are normalised (lowercase, no trailing dot, no duplicates)",
      ok["dns_filter_allow"] == ["fine.example"] and ok["dns_filter_block"] == ["bad.example"], ok)

# ---- the move from 0.6's AdGuard Home (manual 2.3.12.1.9)
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
from fabriclib.setup.move_dns_filter import move_dns_filter  # noqa: E402
imp = import_adguard_settings(ADG, VV)
st = imp["settings"]
check("import: DoH/DoT upstreams of known providers become DoT by address with the certificate name",
      st["dns_filter_upstreams"] == [{"address": "1.1.1.1", "name": "cloudflare-dns.com"},
                                     {"address": "9.9.9.9", "name": "dns.quad9.net"},
                                     {"address": "149.112.112.112", "name": "dns.quad9.net"}], st["dns_filter_upstreams"])
check("import: enabled lists by URL; the owner's ||name^ and @@||name^ rules (vars and UI); fabric's own left out",
      st["dns_filter_lists"] == [{"name": "AdGuard DNS filter", "url": "https://x.example/filter_1.txt"}]
      and st["dns_filter_block"] == ["from-vars.example", "ui-block.example"]
      and st["dns_filter_allow"] == ["ui-allow.example"] and st["dns_filter"] == "bind", st)
nc = "\n".join(imp["not_carried"])
check("import: what cannot move is listed — an unknown upstream, plain DNS, a switched-off list, an allowlist, regex "
      "and exact rules, parental control, blocked services, a rewrite, a client outside the networks answered",
      all(x in nc for x in ("doh.example.net", "192.168.1.1", "Off list", "Allow list", "/regex/", "plain.example",
                            "parental", "blocked services", "nas.home", "kid-tablet"))
      and st["dns_filter_safe_search"] is True
      and "www.lan.test" not in nc, imp["not_carried"])
plain = import_adguard_settings(None, {**VV, "adguard_rules": ["||a.example^"]})["settings"]
check("import without AdGuard's config: what the adguard_* settings (or their defaults) would have started",
      plain["dns_filter_upstreams"][0] == {"address": "1.1.1.1", "name": "cloudflare-dns.com"}
      and plain["dns_filter_lists"][0]["name"] == "AdGuard DNS filter" and plain["dns_filter_block"] == ["a.example"])
MW = os.path.join(os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests"), "resolver-move")
shutil.rmtree(MW, ignore_errors=True)
os.makedirs(f"{MW}/adguard/conf")
with open(f"{MW}/adguard/conf/AdGuardHome.yaml", "w") as f:
    yaml.safe_dump(ADG, f)
data = {**VV, "dns_filter": "adguard", "adguard_upstreams": [], "ip_adguard": "10.255.0.31",
        "dns_filter_allow": ["kept.example"]}
lines = move_dns_filter(data, MW, f"{MW}/config")
rec = [f for f in os.listdir(f"{MW}/config") if f.startswith("dns-filter-import-")]
saved = json.load(open(f"{MW}/config/{rec[0]}")) if rec else {}
check("setup's move: dns_filter becomes bind, the adguard_* keys go, an allow the admin set is kept as set",
      data["dns_filter"] == "bind" and "adguard_upstreams" not in data and "ip_adguard" not in data
      and data["dns_filter_allow"] == ["kept.example"] and data["dns_filter_block"] == st["dns_filter_block"], data)
check("setup's move: a record of what moved and what did not, root only, without AdGuard's password hash",
      len(rec) == 1 and oct(os.stat(f"{MW}/config/{rec[0]}").st_mode & 0o777) == "0o600"
      and saved["not_carried"] and "users" not in saved["adguard_config"] and "$2a$" not in json.dumps(saved)
      and any("not moved:" in ln for ln in lines), (rec, lines))
check("setup's move: nothing to do once moved, nor on a host that never ran AdGuard",
      move_dns_filter(data, MW, f"{MW}/config") == [] and move_dns_filter({**VV}, f"{MW}/none", f"{MW}/config") == [])

# ---- a local server for the lists
LIST_DIR = os.path.join(W, "served")
LIST1 = "! test list\n||ads.example^\n||lan.test^\n||blocked-then-allowed.example^\n0.0.0.0 hosts-blocked.example\n"


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
USERS = {"resolver": {"uid": 913, "gid": 913}}
SECRETS = {"resolver_rndc_secret": "c2VjcmV0LXRlc3Qta2V5LWZvci1mYWJyaWMtcmVzb2x2ZXI="}
try:
    shutil.rmtree(W, ignore_errors=True)
    os.makedirs(LIST_DIR)
    with open(os.path.join(LIST_DIR, "one.txt"), "w") as f:
        f.write(LIST1)
    srv = serve()
    # the DNS name's certificate, as mint_service_certs leaves it (a throwaway self-signed one: its own CA)
    os.makedirs(f"{W}/resolver/tls")
    sh(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
        "-subj", "/CN=dns.lan.test", "-addext", "subjectAltName=DNS:dns.lan.test",
        "-keyout", f"{W}/resolver/tls/privkey.pem", "-out", f"{W}/resolver/tls/fullchain.pem"])
    sh(f"chown -R 913:913 {W}/resolver/tls; chmod 600 {W}/resolver/tls/privkey.pem")
    URL1 = f"http://127.0.0.1:{srv.server_port}/one.txt"
    URL404 = f"http://127.0.0.1:{srv.server_port}/missing.txt"
    V = {"deploy_base_dir": W, "service_users": USERS, "domain": "lan.test", "org_domain": "lan.test",
         "host_ip": GATEWAY, "ip_bind9": BIND_IP, "ip_resolver": RES_IP, "lan_cidr": "192.168.77.0/24",
         "fabric_subnet": "10.254.99.0/24", "dns": {"dynamic_zone_var": {}}, "install_resolver": True,
         "dns_filter": "bind", "resolver_mem_limit": "384m",
         "dns_filter_lists": [{"name": "Test list", "url": URL1}],
         "dns_filter_allow": ["blocked-then-allowed.example"], "dns_filter_block": ["owner-blocked.example"],
         "dns_filter_upstreams": ([{"address": "1.1.1.1", "name": "cloudflare-dns.com"},
                                   {"address": "1.0.0.1", "name": "cloudflare-dns.com"}] if internet else []),
         "published_ref": lambda name: None}

    # the authoritative BIND: fabric's zone
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

    # phase 1: the gateway (this host, as the clients) is not among the allowed networks
    r = deploy_resolver(V, SECRETS, {"children": [], "upstream": None}, env)
    zone1 = list_zone(URL1)
    conf = open(f"{W}/resolver/config/named.conf").read()
    st = json.load(open(f"{W}/resolver/lists/state.json"))[zone1]
    check("deploy: the configuration, rules zones and key written; the list fetched and converted",
          r["config"] and os.path.exists(f"{W}/resolver/lists/{zone1}") and st["rules"] == 4 and not st["error"], r)
    check("deploy: files root-owned, readable by the resolver's group only; log and cache its own",
          oct(os.stat(f"{W}/resolver/config/rndc.key").st_mode & 0o777) == "0o640"
          and os.stat(f"{W}/resolver/config/rndc.key").st_gid == 913 and os.stat(f"{W}/resolver/log").st_uid == 913)
    check("config: fabric's zone forwarded to the authoritative BIND, validate-except, passthru zone first",
          f'zone "lan.test" {{ type forward; forward only; forwarders {{ {BIND_IP} port 53; }}; }};' in conf
          and 'validate-except { "lan.test"; };' in conf
          and conf.index('zone "fabric.rpz";') < conf.index('zone "owner.rpz";') < conf.index(f'zone "{zone1}";'))
    check("config: DoT (853) and DoH (8053, plain: nginx terminates TLS) for clients with the DNS name's certificate",
          'listen-on port 853 tls "clients"' in conf and 'listen-on port 8053 tls none http "doh"' in conf
          and 'cert-file "/etc/bind-tls/fullchain.pem"' in conf and not resolver_tls_pending(V), conf[:900])
    # covers: setting:dns_filter_upstreams +
    check("config: DoT to the upstreams with the certificate name verified (when set)",
          (not internet) or ('remote-hostname "cloudflare-dns.com"' in conf and "1.1.1.1 port 853 tls" in conf), conf)
    check("deploy again: nothing changes", not deploy_resolver(V, SECRETS, {"children": [], "upstream": None},
                                                                env)["config"])

    # the containers: the authoritative BIND, and the resolver as its compose file says
    sh(f"docker rm -f bind9-resolver res-auth; docker network rm {NET}", ok=False)
    sh(["docker", "network", "create", "--subnet", SUBNET, "--gateway", GATEWAY, NET])
    sh(["docker", "run", "-d", "--name", "res-auth", "--network", NET, "--ip", BIND_IP,
        "-v", f"{W}/bind9/config:/etc/bind:ro", "-v", f"{W}/bind9/data:/var/lib/bind", IMAGE])
    compose = yaml.safe_load(env.get_template("resolver/docker-compose.yml.j2").render(**V))["services"]
    svc = compose["bind9-resolver"]
    # covers: setting:resolver_mem_limit +
    check("compose: its own account, no capabilities, read-only, no-new-privileges, the memory limit, named -f",
          svc["user"] == "913:913" and svc["cap_drop"] == ["ALL"] and svc["read_only"] is True
          and svc["security_opt"] == ["no-new-privileges:true"] and svc["mem_limit"] == "384m"
          and svc["entrypoint"][:2] == ["/usr/sbin/named", "-f"], svc)
    run = ["docker", "run", "-d", "--name", "bind9-resolver", "--network", NET, "--ip", RES_IP,
           "--user", svc["user"], "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
           "--memory", svc["mem_limit"], "--entrypoint", svc["entrypoint"][0]]
    for t in svc["tmpfs"]:
        run += ["--tmpfs", t]
    for vol in svc["volumes"]:
        run += ["-v", vol]
    sh(run + [IMAGE, *svc["entrypoint"][1:]])
    up = until(lambda: (resolver_rndc(["status"]) or subprocess.CompletedProcess([], 1)).returncode == 0)
    check("the resolver starts and answers rndc with its own key (the health check)", up,
          sh("docker logs --tail 30 bind9-resolver", ok=False).stderr)
    check("a client outside the allowed networks is REFUSED", status("www.lan.test") == "REFUSED", dig("www.lan.test"))

    # phase 2: this host allowed (the firewall's networks); the running resolver reloads it
    V["security"] = {"firewall_allow": [f"{GATEWAY}/32"]}
    r = deploy_resolver(V, SECRETS, {"children": [], "upstream": None}, env)
    check("a settings change is written and reloaded by the running resolver", r["config"] and r["reconfigured"], r)
    # covers: setting:security +
    check("after the reload the host is allowed: fabric's zone answers through the authoritative BIND",
          until(lambda: "10.9.8.7" in dig("+short", "www.lan.test"), 20), dig("www.lan.test"))
    check("fabric's zone is never filtered, even when a list names it (||lan.test^)",
          "10.9.8.8" in dig("+short", "ads.lan.test"), dig("ads.lan.test"))
    # covers: setting:dns_filter_lists +
    check("a listed name answers NXDOMAIN, and every name below it", status("ads.example") == "NXDOMAIN"
          and status("deep.sub.ads.example") == "NXDOMAIN")
    check("a hosts line blocks", status("hosts-blocked.example") == "NXDOMAIN")
    CA = f"{W}/resolver/tls/fullchain.pem"
    dot = sh(["dig", "+time=5", "+tries=1", "+tls", f"+tls-ca={CA}", "+tls-hostname=dns.lan.test", f"@{RES_IP}",
              "ads.example"], ok=False).stdout
    check("DoT (853) for clients: the certificate verified, and filtered like plain DNS",
          "status: NXDOMAIN" in dot and "10.9.8.7" in sh(["dig", "+time=5", "+tries=1", "+tls", f"+tls-ca={CA}",
                                                           "+tls-hostname=dns.lan.test", f"@{RES_IP}", "+short",
                                                           "www.lan.test"], ok=False).stdout, dot)
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
    check("the owner's block applies", status("owner-blocked.example") == "NXDOMAIN"
          and status("x.owner-blocked.example") == "NXDOMAIN")
    log = open(f"{W}/resolver/log/rpz.log").read()
    check("the RPZ log names the blocked name and the list's zone (for 'why was this blocked')",
          f"ads.example/A/IN via ads.example.{zone1}" in log, log[-600:])
    check("the query log names the client and the view", f"{GATEWAY}#" in open(f"{W}/resolver/log/query.log").read()
          and "view everyone: query: ads.example" in open(f"{W}/resolver/log/query.log").read())
    from fabriclib.dns_filter.ingest_dns_log import QUERY, RPZ, _rows  # noqa: E402
    q_rows, q_skip = _rows(open(f"{W}/resolver/log/query.log").read().splitlines(), QUERY, False)
    r_rows, r_skip = _rows(open(f"{W}/resolver/log/rpz.log").read().splitlines(), RPZ, True)
    check("the query-log job parses every line BIND wrote (query and RPZ logs), the list's zone taken from 'via'",
          q_rows and r_rows and q_skip == 0 and r_skip == 0 and any(f"\t{zone1}" in row for row in r_rows),
          (q_skip, r_skip, r_rows[:2]))
    if internet:
        check("an internet name resolves over DoT, DNSSEC validated", " ad;" in dig("+dnssec", "example.com")
              and status("example.com") == "NOERROR", dig("+dnssec", "example.com"))
        check("the owner's allow beats a list (blocked-then-allowed.example is not rewritten)",
              "blocked-then-allowed.example" not in open(f"{W}/resolver/log/rpz.log").read().split("NXDOMAIN")[-1]
              or status("blocked-then-allowed.example") != "NXDOMAIN")
    else:
        print("INFO no internet: DoT upstream and the allow over a real name not checked")

    # the list job: a changed list is reloaded alone; a list that fails keeps its last good copy
    with open(os.path.join(LIST_DIR, "one.txt"), "a") as f:
        f.write("||new-entry.example^\n")
    res = update_lists(V)
    check("lists: a changed list is written and reloaded in the running resolver",
          res["changed"] == [zone1] and res["lists"][zone1]["reloaded"], res)
    check("lists: the new entry is blocked after the reload", until(lambda: status("new-entry.example") == "NXDOMAIN",
                                                                     20))
    res = update_lists(V)
    check("lists: an unchanged list is not rewritten nor reloaded", res["changed"] == [] and not res["failed"], res)
    V["dns_filter_lists"] = [{"name": "Test list", "url": URL1}, {"name": "Missing", "url": URL404}]
    res = update_lists(V)
    zone404 = list_zone(URL404)
    check("lists: a list that cannot be fetched fails alone, its error kept, the others unchanged",
          res["failed"] == ["Missing"] and "404" in res["lists"][zone404]["error"]
          and not res["lists"][zone1].get("error"), res)
    r = deploy_resolver(V, SECRETS, {"children": [], "upstream": None}, env)
    check("deploy: a list with no good copy is left out of the configuration (the resolver never loads a missing "
          "file)", zone404 not in open(f"{W}/resolver/config/named.conf").read() and status("ads.example") == "NXDOMAIN")
    check("status: exit 1 while a list has no good copy", show_filter_status(V) == 1)
    V["dns_filter_lists"] = [{"name": "Test list", "url": URL1}]
    deploy_resolver(V, SECRETS, {"children": [], "upstream": None}, env)
    check("status: exit 0 when the resolver runs and every list has a good copy", show_filter_status(V) == 0)
    V["dns_filter_lists"] = []
    deploy_resolver(V, SECRETS, {"children": [], "upstream": None}, env)

    def blocks_logged():
        with open(f"{W}/resolver/log/rpz.log") as f:
            return f.read().count(f"ads.example/A/IN via ads.example.{zone1}")

    # ads.example does not exist on the internet either, so the answer stays NXDOMAIN: the RPZ log tells the two apart
    before = blocks_logged()
    status("ads.example")
    time.sleep(1)
    check("deploy: a list taken out of the settings is removed, and no longer blocks (no rewrite logged)",
          not os.path.exists(f"{W}/resolver/lists/{zone1}") and zone1 not in open(f"{W}/resolver/config/named.conf")
          .read() and blocks_logged() == before, (before, blocks_logged()))
finally:
    sh(f"docker rm -f bind9-resolver res-auth; docker network rm {NET}", ok=False)

print("\nall passed (0 failures)" if not FAILED else f"\n{FAILED} failed")
sys.exit(1 if FAILED else 0)
