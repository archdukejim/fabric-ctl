#!/usr/bin/env python3
"""Real end-to-end web UI sign-in tests, run inside the sandbox after setup.

Drives the real stack like a browser — nginx (TLS + client certificate) ->
web UI -> Keycloak (password, TOTP; a forced change after a reset) -> OIDC
callback -> dashboard — using only what setup and `fabricctl client-cert`
handed out. Proves the admin gets in and that everyone else is refused:

  - plain HTTP is redirected to HTTPS
  - no client certificate / a certificate from another CA  -> nginx 400
  - a real directory user without the console's admin role -> 403
  - a valid certificate presented for another user        -> 403
  - the admin's password: the one chosen in setup (FABRIC_ADMIN_PW, no change asked), or a reset's one-time
    password from the kit, which stops working after the first login
  - a directory group gives a role bundle: an auditor reads, a change is refused
  - OpenBao's own UI: the admin signs in with Keycloak (TOTP) and gets the
    fabric-console-admin policy (apps/ yes, fabric's own secrets no); others refused
  - people: the admin adds a person and resets a sign-in
  - the top bar's site selector: this site marked, its own link home, an unknown site refused

  python3 login_test.py <vars.yaml> <other-user> <other-password> <other-p12-password>
Prints PASS/FAIL lines.
"""
import hashlib
import hmac
import html
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse

import yaml

V = yaml.safe_load(open(sys.argv[1]))
OTHER, OTHER_PW, OTHER_P12_PW = sys.argv[2], sys.argv[3], sys.argv[4]
ADMIN = V["webui_admin_user"]
CHOSEN = bool(os.environ.get("FABRIC_ADMIN_PW"))   # the password chosen in setup (2.1.6.33), not a reset's
# The login kit lands in the home of the account that ran `sudo fabricctl setup`.
KIT = os.environ.get("FABRIC_KIT") or os.path.join(os.path.expanduser("~"), "fabric-admin")
ROOT_CA = os.path.join(V["deploy_base_dir"], "stepca", "data", "certs", "root_ca.crt")
MGR, SSO, NGINX, VAULT = V["hostname_mgr"], V["hostname_keycloak"], V["ip_nginx"], V["hostname_openbao"]
TMP = tempfile.mkdtemp()
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))
    return cond


def read(name):
    return open(os.path.join(KIT, name)).read().strip()


def admin_pw():
    return os.environ.get("FABRIC_ADMIN_PW") or read("initial-password.txt")


def pem_from_p12(p12, password, name):
    out = os.path.join(TMP, name)
    subprocess.run(["openssl", "pkcs12", "-in", p12, "-nodes", "-passin", "stdin", "-out", out],
                   input=password, text=True, check=True, capture_output=True)
    os.chmod(out, 0o600)
    return out


class Browser:
    """Per-host cookies, manual redirects, TLS verified against the fabric
    root CA, optional client certificate."""

    def __init__(self, client_cert=None):
        self.ctx = ssl.create_default_context(cafile=ROOT_CA)
        if client_cert:
            self.ctx.load_cert_chain(client_cert)
        self.cookies = {}

    def request(self, method, url, form=None, json_body=None, token=None):
        u = urllib.parse.urlsplit(url)
        conn = http.client.HTTPSConnection(NGINX, 443, timeout=30)
        conn.sock = self.ctx.wrap_socket(socket.create_connection((NGINX, 443), 30), server_hostname=u.hostname)
        jar = self.cookies.setdefault(u.hostname, {})
        headers = {"Host": u.hostname}
        if jar:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Origin"] = f"https://{u.hostname}"
        if json_body is not None:
            body = json.dumps(json_body)
            headers["Content-Type"] = "application/json"
        if token:
            headers["X-Vault-Token"] = token
        conn.request(method, u.path + (f"?{u.query}" if u.query else ""), body=body, headers=headers)
        resp = conn.getresponse()
        for k, v in resp.getheaders():
            if k.lower() == "set-cookie":
                name, _, rest = v.partition("=")
                value = rest.split(";", 1)[0]
                if value and "Max-Age=0" not in v:
                    jar[name] = value
                else:
                    jar.pop(name, None)
        data = resp.read().decode(errors="replace")
        loc = resp.getheader("Location")
        conn.close()
        return resp.status, (urllib.parse.urljoin(url, loc) if loc else None), data


def form_of(page):
    m = re.search(r'<form[^>]*action="([^"]+)"', page, re.I)
    fields = {}
    for tag in re.findall(r"<input[^>]*>", page, re.I):
        n = re.search(r'name="([^"]+)"', tag, re.I)
        if n:
            val = re.search(r'value="([^"]*)"', tag)
            fields[n.group(1)] = html.unescape(val.group(1)) if val else ""
    return (html.unescape(m.group(1)) if m else None), fields


def totp(secret, at=None):
    """Keycloak default policy: HmacSHA1, 6 digits, 30 s, key = raw secret bytes."""
    counter = int((at or time.time()) // 30)
    mac = hmac.new(secret.encode(), struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return f"{(struct.unpack('>I', mac[off:off + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


TOTP = {}                 # user -> enrolled TOTP secret (kept across logins)
NEW_PW = {}               # user -> password after a forced change
LAST_OTP = {}             # user -> last code sent: Keycloak refuses a code twice


def fresh_totp(user):
    """A code Keycloak has not seen yet: after a login in the same 30 s window,
    wait for the next one (as a person with an authenticator app would)."""
    code = totp(TOTP[user])
    if LAST_OTP.get(user) == code:
        time.sleep(31 - time.time() % 30)
        code = totp(TOTP[user])
    LAST_OTP[user] = code
    return code


def through_keycloak(browser, url, user, password, done):
    """Keycloak's pages as a person would fill them (password, forced change,
    TOTP enrolment or code) until it redirects to `done`. Returns
    (redirect URL or None, pages seen, last status, last page)."""
    st, loc, page = browser.request("GET", url)
    seen = []
    for _ in range(12):
        while st in (301, 302, 303) and loc and not loc.startswith(done):
            st, loc, page = browser.request("GET", loc)
        if loc and loc.startswith(done):
            return loc, seen, st, page
        action, fields = form_of(page)
        if not action:
            return None, seen, st, page
        if set(fields) == {"continue"}:           # Kerberos asked for (401 Negotiate) and none given: go on
            seen.append("no-kerberos")
        elif "username" in fields and "password" in fields:
            seen.append("login")
            fields.update(username=user, password=NEW_PW.get(user, password))
        elif "password-new" in fields:
            seen.append("update-password")
            NEW_PW[user] = secrets.token_urlsafe(18)
            fields.update({"password-new": NEW_PW[user], "password-confirm": NEW_PW[user]})
        elif "totpSecret" in fields:
            seen.append("configure-totp")
            TOTP[user] = fields["totpSecret"]
            fields.update(totp=fresh_totp(user), userLabel="fabric sandbox")
        elif "otp" in fields and user in TOTP:
            seen.append("otp")
            fields.update(otp=fresh_totp(user))
        elif {"firstName", "lastName", "email"} & set(fields):
            seen.append("update-profile")
        else:
            return None, seen, st, f"unknown Keycloak page {sorted(fields)}"
        st, loc, page = browser.request("POST", action, {k: v for k, v in fields.items() if k != "cancel-aia"})
    return None, seen, st, page


def applied(browser, page_id, csrf):
    """Apply a page's held changes (manual 1.8.6.5) and wait on its Review for the job: (status, page) of the Review
    once it no longer runs (up to 3 minutes)."""
    st, loc, page = browser.request("POST", f"https://{MGR}/changes/{page_id}/apply", {"csrf": csrf})
    if st != 303:
        return st, page
    for _ in range(90):
        st, _, page = browser.request("GET", f"https://{MGR}/changes/{page_id}")
        if st != 200 or 'http-equiv="refresh"' not in page:
            return st, page
        time.sleep(2)
    return st, page


def login(browser, user, password):
    """Full browser login as `user`. Returns (status, page) of the web UI's
    OIDC callback, and the Keycloak pages seen on the way."""
    st, loc, _ = browser.request("GET", f"https://{MGR}/login")
    if not (st == 303 and loc and loc.startswith(f"https://{SSO}/")):
        return st, f"login did not redirect to Keycloak: {loc}", []
    done, seen, st, page = through_keycloak(browser, loc, user, password, f"https://{MGR}/oidc/callback")
    if not done:
        return st, page, seen
    st, _, page = browser.request("GET", done)
    return st, page, seen


def vault_login(user, password):
    """OpenBao's UI sign-in (OIDC auth at auth/oidc): auth URL, Keycloak,
    then the callback OpenBao's UI would call. Returns (status, response)."""
    b = Browser()
    cb = f"https://{VAULT}/ui/vault/auth/oidc/oidc/callback"
    st, _, page = b.request("POST", f"https://{VAULT}/v1/auth/oidc/oidc/auth_url",
                            json_body={"role": "people", "redirect_uri": cb})
    url = (json.loads(page).get("data") or {}).get("auth_url") if page.startswith("{") else ""
    if not url:
        return st, page
    done, _, st, page = through_keycloak(b, url, user, password, cb)
    if not done:
        return st, page
    st, _, page = b.request("GET", f"https://{VAULT}/v1/auth/oidc/oidc/callback?{urllib.parse.urlsplit(done).query}")
    return st, (json.loads(page) if page.startswith("{") else page)


# -- the default (2.1.6.23, 0.6.1): no client certificate, a password only; then stop (SIGNIN_MODE=plain) --------------
if os.environ.get("SIGNIN_MODE") == "plain":
    b = Browser()
    st, loc, _ = b.request("GET", f"https://{MGR}/")
    check("no certificate asked: a newcomer is sent to sign in (/login), not refused", st == 303 and
          loc.endswith("/login"), (st, loc))
    st, page, seen = login(b, ADMIN, admin_pw())
    check("the admin signs in with a password only, no TOTP (2.1.6.23); a new password asked only after a reset "
          "(2.1.6.33)", st == 200 and ("update-password" in seen) != CHOSEN and "configure-totp" not in seen
          and "otp" not in seen, (st, seen))
    st, _, page = b.request("GET", f"https://{MGR}/settings/sign-in")
    # covers: web:get.settings.sign-in +
    check("the Security page shows the layers to raise", st == 200 and "admin-2fa" in page, st)
    bob = Browser()
    st, page, seen = login(bob, OTHER, OTHER_PW)
    check("a person without a fabric role is still refused (403)", st == 403, (st, seen))
    sys.exit(1 if FAILED else 0)

admin_pem = pem_from_p12(os.path.join(KIT, f"{ADMIN}.p12"), read("p12-password.txt"), "admin.pem")
other_pem = pem_from_p12(os.path.join(KIT, f"{OTHER}.p12"), OTHER_P12_PW, "other.pem")

# -- transport: HTTPS only, client certificate from this CA only ------------------------
conn = http.client.HTTPConnection(NGINX, 80, timeout=15)
conn.request("GET", "/", headers={"Host": MGR})
r = conn.getresponse()
check("plain HTTP is redirected to HTTPS", r.status in (301, 308) and (r.getheader("Location") or "").startswith("https://"),
      (r.status, r.getheader("Location")))
st, _, _ = Browser().request("GET", f"https://{MGR}/")
check("no client certificate -> refused by nginx (400)", st == 400, st)
foreign = os.path.join(TMP, "foreign.pem")
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", f"/CN={ADMIN}",
                "-keyout", foreign, "-out", foreign + ".crt"], check=True, capture_output=True)
with open(foreign, "a") as f:
    f.write(open(foreign + ".crt").read())
try:
    st, _, _ = Browser(foreign).request("GET", f"https://{MGR}/")
except (ssl.SSLError, ConnectionError) as e:
    st = f"TLS refused ({type(e).__name__})"
check("certificate from another CA (even with the admin's name) -> refused", st == 400 or "refused" in str(st), st)

# -- the admin gets in ------------------------------------------------------------------
b = Browser(admin_pem)
st, loc, _ = b.request("GET", f"https://{MGR}/")
check("admin cert, no session -> /login", st == 303 and loc.endswith("/login"), (st, loc))
st, page, seen = login(b, ADMIN, admin_pw())
check("Keycloak required TOTP enrolment (and a new password only after a reset)",
      [p for p in seen if p != "no-kerberos"][:1] == ["login"] and ("update-password" in seen) != CHOSEN
      and "configure-totp" in seen, seen)
check("admin: callback accepted (cert CN = user, the console's admin role)",
      st == 200 and "__Host-webui" in b.cookies.get(MGR, {}), (st, page[:300]))
# the setup wizard (manual 1.8.5.3, 1.8.5.10 "Finished"): until it is applied once or dismissed, the first Overview of
# each sign-in of an admin opens it; the admin dismisses it, as a real one would, through the console's own route.
# WIZARD=open (a fresh install: the sandbox) requires it to open; a reused host (tests/host) may have finished it.
st, loc, _ = b.request("GET", f"https://{MGR}/")
if os.environ.get("WIZARD") == "open" or (st == 303 and (loc or "").endswith("/settings")):
    # covers: web:get.settings agent:get.settings +
    check("setup wizard: a fresh install's first Overview of a sign-in is sent to Settings (303)",
          st == 303 and (loc or "").endswith("/settings"), (st, loc))
    st, _, page = b.request("GET", f"https://{MGR}/settings")
    check("setup wizard: its first step, with Dismiss", st == 200 and 'action="/settings/dismiss"' in page,
          (st, page[:300]))
    wcsrf = page.split('name="csrf" value="')[1].split('"')[0] if 'name="csrf"' in page else ""
    st, loc, _ = b.request("POST", f"https://{MGR}/settings/dismiss", {"csrf": wcsrf})
    # covers: web:post.settings.dismiss agent:post.settings.dismiss +
    check("setup wizard: Dismiss -> back to the Overview", st == 303 and (loc or "").rstrip("/") == f"https://{MGR}",
          (st, loc))
else:
    print(f"    (the setup wizard did not open: finished on this host before; first Overview answered {st})")
st, _, page = b.request("GET", f"https://{MGR}/")
check("admin: overview renders", st == 200 and "services healthy" in page and ADMIN in page, (st, page[:300]))
check("setup wizard finished: the Overview no longer offers Finish setting up", "Finish setting up" not in page,
      page[:300])
SITE = str(V.get("site_name") or "")
pick = page.split('<details class="sitepick">', 1)[-1].split("</details>", 1)[0]
check("the top bar's site selector (1.8.6.12): this site's name as the menu, this site marked in the domain's list",
      f'<summary aria-label="Site: {SITE}. Pick a site">{SITE}</summary>' in page
      and f'<a href="/" aria-current="true"><strong>{SITE}</strong>' in pick, pick[:600] or page[:600])
st, loc, _ = b.request("GET", f"https://{MGR}/sites/{SITE}")
check("the site selector: this site's own link goes to its Overview (303 /)", st == 303 and loc == "/", (st, loc))
st, _, page = b.request("GET", f"https://{MGR}/sites/ghost")
check("refused: a site the domain does not hold (404, said; no redirect)", st == 404
      and "No site ghost in the domain." in page, (st, page[:300]))

# -- everyone else is refused -----------------------------------------------------------
ob = Browser(other_pem)
st, page, seen = login(ob, OTHER, OTHER_PW)
st2, loc2, _ = ob.request("GET", f"https://{MGR}/")
st3, _, page3 = ob.request("GET", f"https://{MGR}/dns/zones")
check(f"'{OTHER}' (directory user, no fabric role) with own valid cert signs in to My account only (2.1.8.11): "
      "the Overview sends it there, DNS refused", st == 200 and st2 == 303 and (loc2 or "").endswith("/account")
      and st3 == 403, (st, st2, loc2, st3, page[:200], seen))
st, page, _ = login(Browser(admin_pem), OTHER, OTHER_PW)
check(f"admin's certificate used to sign in as '{OTHER}' -> 403 not your certificate",
      st == 403 and "does not belong" in page, (st, page[:300]))
st, page, _ = login(Browser(other_pem), ADMIN, NEW_PW.get(ADMIN, admin_pw()))
check(f"'{OTHER}''s certificate used to sign in as the admin -> 403 not your certificate",
      st == 403 and "does not belong" in page, (st, page[:300]))

# -- the reset's one-time password is dead (a chosen one: a wrong password is refused) ----
fresh = Browser(admin_pem)
st, loc, _ = fresh.request("GET", f"https://{MGR}/login")
st, loc, page = fresh.request("GET", loc)
action, fields = form_of(page)
if set(fields) == {"continue"}:                   # Kerberos asked for and none given: on to the password form
    st, loc, page = fresh.request("POST", action, fields)
    action, fields = form_of(page)
fields.update(username=ADMIN, password=admin_pw() + "x" if CHOSEN else read("initial-password.txt"))
st, loc, page = fresh.request("POST", action, fields)
check("a wrong password is refused" if CHOSEN else "initial password no longer accepted",
      st == 200 and "Invalid" in page, (st, loc))

# -- a role bundle through a directory group (real Keycloak composite roles) --------------
if os.environ.get("CAROL_PW"):
    carol_pem = pem_from_p12(os.path.join(KIT, "carol.p12"), os.environ["CAROL_P12_PW"], "carol.pem")
    cb = Browser(carol_pem)
    st, page, seen = login(cb, "carol", os.environ["CAROL_PW"])
    st, _, page = cb.request("GET", f"https://{MGR}/")
    check("carol (auditors group -> fabric-auditor bundle) signs in and sees the overview",
          st == 200 and "services healthy" in page, (st, page[:300], seen))
    st, _, page = cb.request("GET", f"https://{MGR}/dns/zones")
    check("auditor: DNS records readable, no add form, no Apply", st == 200 and "/add" not in page
          and 'action="/changes/zones/apply"' not in page, (st, page[:200]))
    csrf = page.split('name="csrf" value="')[1].split('"')[0] if 'name="csrf"' in page else ""
    st, loc, page = cb.request("POST", f"https://{MGR}/bind9/zone/dynamic_zone_var/add",
                               {"csrf": csrf, "type": "A", "name": "carol-was-here", "ip": "10.77.0.66"})
    if st == 303 and loc:                         # the page says why, after the redirect (its message, 1.8.6.7)
        _, _, shown = cb.request("GET", loc)
        page = shown.split("<main>")[-1]
    said = urllib.parse.unquote_plus(loc or "") + page
    # covers: web:post.bind9.zone.*.add agent:post.zones.*.records -
    check("auditor: a DNS change is refused by fabric-agent when held (dns:write named), nothing held",
          st in (303, 403) and "dns:write" in said and "Waiting for Apply" not in said, (st, loc, page[:300]))

# -- OpenBao's own UI with Keycloak single sign-on ---------------------------------------
st, res = vault_login(ADMIN, NEW_PW.get(ADMIN, admin_pw()))
token = (res.get("auth") or {}).get("client_token") if isinstance(res, dict) else None


def policies(res):
    auth = (res.get("auth") or {}) if isinstance(res, dict) else {}
    return set(auth.get("policies") or []) | set(auth.get("identity_policies") or [])


check("OpenBao UI: the admin signs in with Keycloak (TOTP) and gets the fabric-console-admin policy (bundle group)",
      st == 200 and token and "fabric-console-admin" in policies(res), (st, str(res)[:300]))
vb = Browser()
if token:
    st, _, _ = vb.request("POST", f"https://{VAULT}/v1/apps/data/sandbox/probe", json_body={"data": {"v": "1"}},
                          token=token)
    check("OpenBao UI: the admin may write their applications' secrets (apps/)", st == 200, st)
    st, _, _ = vb.request("GET", f"https://{VAULT}/v1/fabric/data/secrets", token=token)
    check("OpenBao UI: fabric's own secrets stay unreadable to people", st == 403, st)
st, res = vault_login(OTHER, OTHER_PW)
check(f"OpenBao UI: '{OTHER}' (no admin role) is refused", st in (400, 403) and not (
    isinstance(res, dict) and res.get("auth")), (st, str(res)[:300]))

if os.environ.get("CAROL_PW"):
    st, res = vault_login("carol", NEW_PW.get("carol", os.environ["CAROL_PW"]))
    ctok = (res.get("auth") or {}).get("client_token") if isinstance(res, dict) else None
    check("OpenBao UI: carol (auditor bundle) gets fabric-auditor, not fabric-console-admin",
          st == 200 and "fabric-auditor" in policies(res) and "fabric-console-admin" not in policies(res), (st, str(res)[:300]))
    if ctok:
        st1, _, page = vb.request("LIST", f"https://{VAULT}/v1/apps/metadata", token=ctok)
        st2, _, _ = vb.request("GET", f"https://{VAULT}/v1/apps/data/sandbox/probe", token=ctok)
        check("OpenBao UI: the auditor lists application secrets but cannot read one",
              st1 == 200 and "sandbox" in page and st2 == 403, (st1, st2, page[:200]))

# -- people (Directory -> People): add a person, reset a sign-in ---------------------------
# NEW_PERSON: a reused host (tests/host) already has the previous run's person
NEW = os.environ.get("NEW_PERSON", "dave")
st, _, page = b.request("GET", f"https://{MGR}/directory/people")
if st == 303:       # the admin's session went idle (session_idle, 900 s) during the slower checks above
    print("    (admin session idle-expired; signing in again)")
    login(b, ADMIN, NEW_PW.get(ADMIN, admin_pw()))
    st, _, page = b.request("GET", f"https://{MGR}/directory/people")
csrf = page.split('name="csrf" value="')[1].split('"')[0] if 'name="csrf"' in page else ""
if not csrf or "/directory/people/_new" not in page:     # what the People page showed instead of its forms
    print(f"    people page ({st}): {page.split('<main>')[-1][:600]!r}")
st, loc, page = b.request("POST", f"https://{MGR}/directory/people/_new",
                          {"csrf": csrf, "uid": NEW, "first": "Dave", "last": "Doe", "email": f"{NEW}@lan.test"})
st, page = applied(b, "people", csrf)       # Apply per page: the job, then its Review
# covers: web:post.directory.people._new agent:post.people +
check(f"people: the admin adds {NEW}, applies -> one-time password shown once, on the Review",
      st == 200 and "Shown only now" in page, (st, page.split("<main>")[-1][:300]))     # the page's own message
st, _, page = b.request("GET", f"https://{MGR}/directory/people")
# covers: web:get.directory.people agent:get.people +
check(f"people: {NEW} is in the directory (written by Keycloak)", f"{NEW}@lan.test" in page, page[:200])
st, loc, page = b.request("POST", f"https://{MGR}/directory/people/{NEW}/reset", {"csrf": csrf})
st, page = applied(b, "people", csrf)
# covers: web:post.directory.people.*.reset agent:post.people.*.reset +
check(f"people: the admin resets {NEW}'s sign-in, applies -> its one-time password shown once",
      st == 200 and f"Reset the sign-in of {NEW}" in page and "Shown only now" in page,
      (st, page.split("<main>")[-1][:300]))

sys.exit(1 if FAILED else 0)
