#!/usr/bin/env python3
"""The console's page speed on a real host (manual 1.8.8.2, decision 2.1.8.35), run there as root: signs in through
nginx and Keycloak as a person would (password only, the default), then loads each page ROUNDS times over one session,
each through a new TLS connection, as a browser's new navigation might, and prints each page's times.

    sudo python3 page_speed.py <vars.yaml> <user> <password-file> [--rounds N] [--json out.json]

Prints one line per page: its status, the median and the best of its server time (request sent to the whole body read,
which on the host itself is the server's time), after one load not counted. With --budget it fails on a median over
100 ms, /secrets apart (decision 2.1.8.43). The Overview meets it only once no reminder shows (1.8.9.2): delete the file
it names first. The password is read from a 0600 file and never printed."""
import argparse
import html
import http.client
import json
import re
import socket
import ssl
import statistics
import sys
import time
import urllib.parse

import yaml

# every navigation page, and a detail page of each kind that has one here (1.8.6.4); {person} and so on are the signed-in
# person and what the install has
PAGES = ["/", "/overview/doctor", "/overview/updates", "/audit", "/dns/zones", "/dns-filter", "/networks", "/pki",
         "/pki/acme", "/directory", "/directory/people", "/directory/people/{user}", "/directory/groups",
         "/directory/groups/directory-admins", "/directory/computers", "/directory/computers/_groups",
         "/directory/ous", "/directory/tree", "/directory/tree?ou=people", "/directory/access", "/directory/sites",
         "/directory/kerberos", "/directory/policies", "/directory/policies/gpo", "/directory/policies/sudo", "/8021x",
         "/8021x/decisions", "/8021x/guides", "/secrets", "/federation", "/settings", "/account", "/account/groups"]


BUDGET_MS = 100        # decision 2.1.8.43: each page's median on the test Pi's 5-person install
OUTSIDE = {"/secrets"}  # decision 2.1.8.43: its reads of OpenBao stay live, a best effort


class Browser:
    """Cookies per host, no redirects followed, TLS verified against fabric's root CA, reaching nginx by its address."""

    def __init__(self, ca, nginx):
        self.ctx, self.nginx, self.jar = ssl.create_default_context(cafile=ca), nginx, {}

    def go(self, method, url, form=None):
        u = urllib.parse.urlsplit(url)
        jar = self.jar.setdefault(u.hostname, {})
        headers = {"Host": u.hostname}
        if jar:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Origin"] = f"https://{u.hostname}"
        conn = http.client.HTTPSConnection(self.nginx, 443, timeout=120)
        conn.sock = self.ctx.wrap_socket(socket.create_connection((self.nginx, 443), 30), server_hostname=u.hostname)
        start = time.perf_counter()
        conn.request(method, u.path + (f"?{u.query}" if u.query else ""), body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode(errors="replace")
        took = time.perf_counter() - start
        for k, v in resp.getheaders():
            if k.lower() == "set-cookie":
                name, _, rest = v.partition("=")
                value = rest.split(";", 1)[0]
                if value and "Max-Age=0" not in v:
                    jar[name] = value
                else:
                    jar.pop(name, None)
        loc = resp.getheader("Location")
        conn.close()
        return resp.status, (urllib.parse.urljoin(url, loc) if loc else None), data, took


def form_of(page):
    m = re.search(r'<form[^>]*action="([^"]+)"', page, re.I)
    fields = {}
    for tag in re.findall(r"<input[^>]*>", page, re.I):
        n = re.search(r'name="([^"]+)"', tag, re.I)
        if n:
            val = re.search(r'value="([^"]*)"', tag)
            fields[n.group(1)] = html.unescape(val.group(1)) if val else ""
    return (html.unescape(m.group(1)) if m else None), fields


def sign_in(b, mgr, user, password):
    """Through Keycloak's pages as the default sign-in has them: a password, nothing else asked."""
    st, loc, page, _ = b.go("GET", f"https://{mgr}/")
    for _ in range(12):
        while st in (301, 302, 303) and loc:
            if urllib.parse.urlsplit(loc).hostname == mgr and "/oidc" not in loc and "/login" not in loc:
                return True
            st, loc, page, _ = b.go("GET", loc)
        action, fields = form_of(page)
        if not action:
            return st == 200 and urllib.parse.urlsplit(loc or f"https://{mgr}/").hostname == mgr
        if "username" in fields and "password" in fields:
            fields.update(username=user, password=password)
        elif set(fields) != {"continue"} and "password-new" not in fields and "csrf" not in fields:
            raise SystemExit(f"an unexpected sign-in page: {sorted(fields)}")
        if "password-new" in fields:
            raise SystemExit("this account has a one-time password: sign in once by hand first")
        st, loc, page, _ = b.go("POST", urllib.parse.urljoin(f"https://{mgr}/", action), fields)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("vars")
    ap.add_argument("user")
    ap.add_argument("password_file")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--json", default="")
    ap.add_argument("--pages", default="", help="a comma-separated list instead of every page")
    ap.add_argument("--budget", action="store_true", help="fail when a page's median is over BUDGET_MS (2.1.8.43)")
    args = ap.parse_args()
    v = yaml.safe_load(open(args.vars))
    ca = f"{v['deploy_base_dir']}/stepca/data/certs/root_ca.crt"
    with open(args.password_file) as f:
        password = f.read().strip()
    b = Browser(ca, v["ip_nginx"])
    if not sign_in(b, v["hostname_mgr"], args.user, password):
        raise SystemExit("not signed in")
    pages = args.pages.split(",") if args.pages else PAGES
    out = {}
    for page in pages:
        path = page.replace("{user}", args.user)
        b.go("GET", f"https://{v['hostname_mgr']}{path}")       # a first load may be read live, or redirect once (1.8.9.2)
        times, status = [], 0
        for _ in range(args.rounds):
            status, _, _, took = b.go("GET", f"https://{v['hostname_mgr']}{path}")
            times.append(took)
        out[path] = {"status": status, "median_ms": round(statistics.median(times) * 1000),
                     "best_ms": round(min(times) * 1000)}
        print(f"{status} {out[path]['median_ms']:>6} ms median {out[path]['best_ms']:>6} ms best  {path}", flush=True)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(out, f)
    over = [p for p, r in out.items() if r["status"] != 200 or (r["median_ms"] > BUDGET_MS and p not in OUTSIDE)]
    if args.budget and over:
        print(f"over the budget of {BUDGET_MS} ms, or not answered: {over}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
