"""Drive AdGuard Home through its HTTP API only, as fabric-agent would (manual 2.3.1.18): first-run setup, its own
query log and statistics off, upstreams, the lists, a group as a client, rules; timings for adding and toggling
lists. Throwaway (global Rule 4). The account's password is read from a file, never given on a command line.

    python3 adguard.py <base url> <password file> setup
    python3 adguard.py <base url> <password file> lists <list base url> <ids...>
    python3 adguard.py <base url> <password file> call <METHOD> <path> [json body]
"""
import base64
import json
import sys
import time
import urllib.error
import urllib.request

BASE, PWFILE, CMD = sys.argv[1].rstrip("/"), sys.argv[2], sys.argv[3]
USER = "fabric-agent"
PW = open(PWFILE).read().strip()


def api(method, path, body=None, auth=True, timeout=600):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{USER}:{PW}".encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            text = r.read().decode()
            return r.status, (json.loads(text) if text.strip().startswith(("{", "[")) else text)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


if CMD == "setup":
    st, res = api("POST", "/control/install/configure", {
        "web": {"ip": "0.0.0.0", "port": 3000}, "dns": {"ip": "0.0.0.0", "port": 53},
        "username": USER, "password": PW}, auth=False)
    print("install", st, res)
    for _ in range(30):                     # the web server restarts on its configured port
        time.sleep(1)
        try:
            if api("GET", "/control/status")[0] == 200:
                break
        except OSError:
            pass
    steps = [
        ("POST", "/control/dns_config", {"upstream_dns": ["tls://1.1.1.1", "tls://1.0.0.1"],
                                         "bootstrap_dns": ["1.1.1.1"], "blocking_mode": "nxdomain",
                                         "dnssec_enabled": True, "cache_size": 4194304, "ratelimit": 0,
                                         "blocked_response_ttl": 10}),
        ("PUT", "/control/querylog/config/update", {"enabled": False, "interval": 86400000,
                                                    "anonymize_client_ip": False, "ignored": []}),
        ("PUT", "/control/stats/config/update", {"enabled": False, "interval": 86400000, "ignored": []}),
        ("POST", "/control/filtering/config", {"enabled": True, "interval": 24}),
        # the group: the resolver's kids view forwards from its own address on the second network
        ("POST", "/control/clients/add", {"name": "kids", "ids": ["172.30.55.30"], "use_global_settings": True,
                                          "filtering_enabled": True, "parental_enabled": False,
                                          "safebrowsing_enabled": False, "safe_search": {"enabled": False},
                                          "use_global_blocked_services": True, "blocked_services": [],
                                          "upstreams": [], "tags": []}),
        # a group's own block, and a block on fabric's zone that must never be reached (BIND answers it)
        ("POST", "/control/filtering/set_rules", {"rules": ["||wikipedia.org^$client='kids'", "||site.test^"]}),
    ]
    for method, path, body in steps:
        print(path, *api(method, path, body))
    print("querylog", api("GET", "/control/querylog/config")[1])
    print("stats", api("GET", "/control/stats/config")[1])

elif CMD == "lists":
    src, ids = sys.argv[4].rstrip("/"), sys.argv[5:]
    t0 = time.time()
    for i in ids:
        t = time.time()
        st, res = api("POST", "/control/filtering/add_url", {"name": f"list {i}", "url": f"{src}/filter_{i}.txt",
                                                             "whitelist": False})
        print(f"add list {i}: {st} {time.time() - t:.1f}s {'' if st == 200 else res}")
    total = time.time() - t0
    rules = sum(f.get("rules_count", 0) for f in api("GET", "/control/filtering/status")[1].get("filters") or [])
    print(json.dumps({"added": len(ids), "seconds": round(total, 1), "rules": rules}))

elif CMD == "call":
    t = time.time()
    st, res = api(sys.argv[4], sys.argv[5], json.loads(sys.argv[6]) if len(sys.argv) > 6 else None)
    print(json.dumps({"status": st, "seconds": round(time.time() - t, 2), "result": res})[:1500])
