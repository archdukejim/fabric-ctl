#!/usr/bin/env python3
"""End-to-end test of the web UI container against a mock Keycloak and the
real fabric-agent (Linux, root):
    sudo python3 tests/webui/test_container.py
Builds a throwaway PKI with openssl, starts a TLS mock Keycloak that signs
real RS256 ID tokens, starts fabric-agent from the installed tree and the
web UI image on a unix socket, and drives it the way nginx would (forwarded
client-certificate headers)."""
import base64
import hashlib
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), REPO]
from fabriclib.rbac.permissions import BUNDLES  # noqa: E402


def bundle_roles(bundle, name=None):
    """The roles claim Keycloak issues for a bundle: the composite and its permissions."""
    return [name or bundle] + [f"fabric:{p}" for p in BUNDLES[bundle]]


ADMIN_ROLES = bundle_roles("admin", "fabric-console-admin")
AUDITOR_ROLES = bundle_roles("fabric-auditor")
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/webui"
shutil.rmtree(W, ignore_errors=True)
os.makedirs(W)


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True, cwd=W, **kw).stdout


# ---------------------------------------------------------------- PKI
sh("openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.crt -days 2 -subj '/O=Test/CN=Test Root CA' "
   "-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign")


def ca_cert(name, cn, issuer):
    sh(f"openssl req -newkey rsa:2048 -nodes -keyout {name}.key -out {name}.csr -subj '/C=US/O=Test Org/CN={cn}'")
    open(f"{W}/{name}.ext", "w").write("basicConstraints=critical,CA:TRUE,pathlen:1\nkeyUsage=critical,keyCertSign,cRLSign\n")
    sh(f"openssl x509 -req -in {name}.csr -CA {issuer}.crt -CAkey {issuer}.key -CAcreateserial -out {name}.crt -days 2 -extfile {name}.ext")


def leaf(name, cn, issuer, san=None):
    sh(f"openssl req -newkey rsa:2048 -nodes -keyout {name}.key -out {name}.csr -subj '/C=US/O=Test Org/OU=IT/CN={cn}'")
    ext = "basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth,clientAuth\n" + (f"subjectAltName=DNS:{san}\n" if san else "")
    open(f"{W}/{name}.ext", "w").write(ext)
    sh(f"openssl x509 -req -in {name}.csr -CA {issuer}.crt -CAkey {issuer}.key -CAcreateserial -out {name}.crt -days 2 -extfile {name}.ext")


ca_cert("int", "Test Intermediate CA", "root")
ca_cert("sub", "Rogue Sub CA", "int")
leaf("sso", "sso.test", "int", san="sso.test")
open(f"{W}/sso-chain.crt", "w").write(open(f"{W}/sso.crt").read() + open(f"{W}/int.crt").read())


def dn(path, which):
    return sh(f"openssl x509 -in {path} -noout -{which} -nameopt RFC2253").split("=", 1)[1].strip()


INT_DN = dn(f"{W}/int.crt", "subject")
SUB_DN = dn(f"{W}/sub.crt", "subject")

# ------------------------------------------------------- mock Keycloak
sh("openssl genrsa -out sign.key 2048")
modulus = int(sh("openssl rsa -in sign.key -noout -modulus").split("=")[1].strip(), 16)


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


JWKS = {"keys": [{"kid": "k1", "kty": "RSA", "alg": "RS256", "use": "sig",
                  "n": b64u(modulus.to_bytes(256, "big")), "e": b64u((65537).to_bytes(3, "big"))}]}
ISSUER = "https://sso.test/realms/test"
CODES = {}          # code -> dict(nonce, challenge, user, roles, tamper)
MOCK = {"user": "alice", "roles": ["fabric-console-admin"], "tamper": None}
REFRESH = {}        # refresh token -> {"user", "roles", "short"}: what a refresh grant returns (roles can be revoked)


def sign_jwt(claims, kid="k1"):
    header = b64u(json.dumps({"alg": "RS256", "kid": kid, "typ": "JWT"}).encode())
    payload = b64u(json.dumps(claims).encode())
    open(f"{W}/tosign", "wb").write(f"{header}.{payload}".encode())
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", f"{W}/sign.key", f"{W}/tosign"],
                         capture_output=True, check=True).stdout
    return f"{header}.{payload}.{b64u(sig)}"


class KC(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/realms/test/protocol/openid-connect/certs":
            return self.reply(200, JWKS)
        self.reply(404, {})

    def do_POST(self):
        form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode()))
        if self.path != "/realms/test/protocol/openid-connect/token":
            return self.reply(404, {})
        if form.get("grant_type") == "refresh_token":
            r = REFRESH.get(form.get("refresh_token"))
            if not r or form.get("client_secret") != "s3cret" or r["user"] is None:
                return self.reply(400, {"error": "invalid_grant"})
            now = int(time.time())
            return self.reply(200, {"id_token": sign_jwt({
                "iss": ISSUER, "aud": "fabric-webui", "azp": "fabric-webui", "sub": "u1", "iat": now,
                "exp": now + (20 if r["short"] else 300), "preferred_username": r["user"], "roles": r["roles"]}),
                "refresh_token": form["refresh_token"]})
        entry = CODES.pop(form.get("code"), None)
        if not entry or form.get("client_secret") != "s3cret" or form.get("client_id") != "fabric-webui":
            return self.reply(400, {"error": "invalid_grant"})
        if b64u(hashlib.sha256(form["code_verifier"].encode()).digest()) != entry["challenge"]:
            return self.reply(400, {"error": "invalid_grant", "error_description": "PKCE"})
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": "fabric-webui", "azp": "fabric-webui", "sub": "u1", "iat": now, "exp": now + 300,
                  "nonce": entry["nonce"], "preferred_username": entry["user"], "roles": entry["roles"]}
        t = entry["tamper"]
        if t == "nonce":
            claims["nonce"] = "wrong"
        if t == "aud":
            claims["aud"] = "other-client"
        if t == "stale":                 # signed in long ago (step-up for vault changes)
            claims["auth_time"] = now - 3600
        if t == "expired":
            claims["exp"] = now - 600
        if t == "short":                 # expires soon: the next request renews it
            claims["exp"] = now + 20
        token = sign_jwt(claims)
        if t == "sig":
            h, p, s = token.split(".")
            p = b64u(json.dumps({**claims, "roles": ["fabric-console-admin", "x"]}).encode())
            token = f"{h}.{p}.{s}"
        rt = f"rt-{os.urandom(6).hex()}"
        REFRESH[rt] = {"user": entry["user"], "roles": entry["roles"], "short": t == "short"}
        self.reply(200, {"id_token": token, "access_token": "unused", "token_type": "Bearer", "refresh_token": rt})


kc = ThreadingHTTPServer(("0.0.0.0", 18443), KC)
ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ctx.load_cert_chain(f"{W}/sso-chain.crt", f"{W}/sso.key")
kc.socket = ctx.wrap_socket(kc.socket, server_side=True)
threading.Thread(target=kc.serve_forever, daemon=True).start()

# ------------------------------------------- fabric-agent (host, root)
subprocess.run(["bash", f"{REPO}/packaging/deb/assemble-tree.sh", W], check=True)   # the installed tree
os.makedirs(f"{W}/fabric/config")
# fabric's own services declined on this host (1.2.9.4): every apply the console starts is refused at once, so nothing
# is ever deployed to the machine running the suite, whatever the settings below make possible
open(f"{W}/fabric/config/consent.yaml", "w").write("groups:\n  services: {answer: 'no', changes: []}\n")
open(f"{W}/fabric/VERSION", "w").write("9.9.9\n")
open(f"{W}/fabric/config/vars.yaml", "w").write(
    f"deploy_base_dir: {W}\nhost_ip: 192.168.7.53\nlan_cidr: 192.168.7.0/24\nhostname_landing: info.lan.test\n"
    "hostname_stepca: ca.lan.test\n"
    f"hostname_openbao: vault.lan.test\nip_openbao: 10.254.8.99\nopenbao_key_dir: {W}/nokeys\nhostname: pi-core\n"
    "service_users: {openbao: {uid: 913, gid: 913}}\n"
    "domain: lan.test\ndns:\n  dynamic_zone_var:\n    zone_authority: true\n    A:\n    - {name: pi-core, ip: 192.168.7.53}\n"
    "    CNAME:\n    - {name: calibre, canonical: nas25-apps}\n    - {name: info, canonical: pi-core}\n"
    "    - {name: ca, canonical: pi-core}\n"
    "ad_domain: ad.lan.test\ndc_name: dc-pi-core\nad_password_policy: {minimum_length: 12, complexity: true, "
    "history: 5, minimum_age_days: 0, maximum_age_days: 0, lockout_threshold: 10, lockout_minutes: 15, "
    "lockout_window_minutes: 15}\n"
    "logon_policies:\n  machines: {console: [lan-admins], remote: [lan-admins]}\n"
    "  machines/lab: {console: [lan-users], remote: []}\n")
UID = 912
DEBIAN = subprocess.run([sys.executable, f"{REPO}/tests/image_ref.py", "debian"], capture_output=True, text=True,
                        check=True).stdout.strip()
for d, owner, group, mode in [("agent", 0, UID, 0o750), ("run", UID, 0, 0o750), ("config", 0, UID, 0o750),
                              ("certs", 0, 0, 0o755)]:
    os.makedirs(f"{W}/{d}", exist_ok=True)
    os.chown(f"{W}/{d}", owner, group)
    os.chmod(f"{W}/{d}", mode)
shutil.copy(f"{W}/root.crt", f"{W}/certs/root_ca.crt")
shutil.copy(f"{W}/int.crt", f"{W}/certs/intermediate_ca.crt")
shutil.copytree(f"{W}/certs", f"{W}/stepca/data/certs")      # what the agent's PKI pages read
# the agent's systemctl answers questions but never starts, stops or reloads anything: whatever fabric units the machine
# running the suite has, no change made in the console runs a job or touches a service there
os.makedirs(f"{W}/bin")
REAL_SYSTEMCTL = shutil.which("systemctl") or "/usr/bin/systemctl"
open(f"{W}/bin/systemctl", "w").write(
    "#!/bin/sh\n"
    "for a in \"$@\"; do case $a in start|stop|restart|reload|reload-or-restart|try-restart|enable|disable|"
    "daemon-reload) echo \"Unit not started: the webui suite's agent changes nothing on this machine.\" >&2; "
    "exit 5;; esac; done\n"
    f"exec {REAL_SYSTEMCTL} \"$@\"\n")
os.chmod(f"{W}/bin/systemctl", 0o755)
agent = subprocess.Popen([sys.executable, f"{W}/fabric/lib/agent/server.py", "--socket", f"{W}/agent/agent.sock",
                          "--socket-gid", str(UID), "--allow-uid", str(UID)],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                         env={**os.environ, "PATH": f"{W}/bin:" + os.environ.get("PATH", "/usr/bin:/bin")})

# ------------------------------------------- webui container (uid 912)
sh("docker rm -f cwebui >/dev/null 2>&1; docker network rm cwnet >/dev/null 2>&1; true")
sh("docker network create --subnet 10.254.8.0/24 --gateway 10.254.8.1 cwnet >/dev/null")
cfg = {"socket": "/run/webui/web.sock", "socket_gid": 0, "agent_socket": "/agent/agent.sock",
       "public_url": "https://mgr.test", "ca_file": "/certs/root_ca.crt", "intermediate_ca": "/certs/intermediate_ca.crt",
       "admin_role": "fabric-console-admin", "session_idle": 900, "session_max": 28800,
       "keycloak": {"ip": "10.254.8.1", "port": 18443, "hostname": "sso.test", "realm": "test",
                    "client_id": "fabric-webui", "client_secret": "s3cret"}}
json.dump(cfg, open(f"{W}/config/webui.json", "w"))
os.makedirs(f"{W}/webui/config")                 # where fabric-agent reads the Keycloak settings it verifies against
json.dump(cfg, open(f"{W}/webui/config/webui.json", "w"))
os.chown(f"{W}/config/webui.json", UID, UID)
os.chmod(f"{W}/config/webui.json", 0o400)
os.makedirs(f"{W}/build")
sh(f"cp -a {W}/fabric/jinja/webui/build/. {W}/build/ && cp -a {W}/fabric/lib/webui {W}/build/app")
sh(f"docker build -q --build-arg BASE_IMAGE={DEBIAN} --build-arg WEBUI_UID={UID} --build-arg WEBUI_GID={UID} -t fabric/webui:test {W}/build >/dev/null")
sh(f"docker run -d --name cwebui --network cwnet --ip 10.254.8.80 --user {UID}:{UID} --group-add 0 "
   f"--read-only --security-opt no-new-privileges:true --cap-drop ALL --tmpfs /tmp:noexec,nosuid,size=16m "
   f"-v {W}/config:/config:ro -v {W}/certs:/certs:ro -v {W}/run:/run/webui -v {W}/agent:/agent:ro "
   f"fabric/webui:test >/dev/null")
for _ in range(100):
    if os.path.exists(f"{W}/run/web.sock"):
        break
    time.sleep(0.2)
os.symlink(f"{W}/run/web.sock", f"{W}/web.sock")


class UConn(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(f"{W}/web.sock")


ALICE = {"X-SSL-Client-Verify": "SUCCESS", "X-SSL-Client-S-DN": "CN=alice,OU=IT,O=Test Org,C=US",
         "X-SSL-Client-I-DN": INT_DN, "X-SSL-Client-Fingerprint": "aa" * 20}


def req(method, path, headers=None, body=None, cookie=None):
    h = dict(headers or {})
    if cookie:
        h["Cookie"] = cookie
    if body is not None:
        body = urllib.parse.urlencode(body)
        h["Content-Type"] = "application/x-www-form-urlencoded"
    c = UConn("x")
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    data = r.read().decode()
    return r.status, dict(r.getheaders()), r.getheader("Set-Cookie") or "", data


def req_upload(path, headers, fields, files, cookie):
    """multipart/form-data POST, as a browser sends a form with a file input."""
    boundary = "----fabrictest" + os.urandom(8).hex()
    out = b""
    for k, v in fields.items():
        out += f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
    for k, (fname, data) in files.items():
        out += (f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"; filename="{fname}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n").encode() + data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    c = UConn("x")
    c.request("POST", path, body=out, headers={**headers, "Cookie": cookie,
                                               "Content-Type": f"multipart/form-data; boundary={boundary}"})
    r = c.getresponse()
    return r.status, dict(r.getheaders()), r.read().decode()


def cookie_csrf(session_cookie):
    """The session's CSRF token, from the sign-out form every page has."""
    body = req("GET", "/", ALICE, cookie=session_cookie)[3]
    return body.split('name="csrf" value="')[1].split('"')[0]


def cookie_val(set_cookie, name):
    for part in set_cookie.split(", "):
        if part.startswith(name + "="):
            return part.split(";")[0]
    return ""


results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def login(cert=ALICE, user="alice", roles=tuple(ADMIN_ROLES), tamper=None, callback_cert=None, next_path=None):
    st, hd, sc, _ = req("GET", "/login" + (f"?next={urllib.parse.quote(next_path)}" if next_path else ""), cert)
    loc = urllib.parse.urlparse(hd.get("Location", ""))
    q = dict(urllib.parse.parse_qsl(loc.query))
    code = os.urandom(8).hex()
    CODES[code] = {"nonce": q.get("nonce"), "challenge": q.get("code_challenge"), "user": user,
                   "roles": list(roles), "tamper": tamper}
    lc = cookie_val(sc, "__Host-webui-login")
    return req("GET", f"/oidc/callback?code={code}&state={q.get('state')}", callback_cert or cert, cookie=lc), q, hd


# ---------------------------------------------------------------- tests
st, *_ = req("GET", "/")
# covers: web:get.home -
check("no client cert -> 403", st == 403, st)
st, *_ = req("GET", "/", {**ALICE, "X-SSL-Client-Verify": "FAILED:unable to verify"})
check("unverified cert -> 403", st == 403, st)
st, *_ = req("GET", "/", {**ALICE, "X-SSL-Client-I-DN": SUB_DN})
check("cert from subordinate CA -> 403", st == 403, st)
st, hd, *_ = req("GET", "/", ALICE)
check("valid cert, no session -> redirect to /login", st == 303 and hd.get("Location") == "/login", (st, hd))

st, hd, sc, _ = req("GET", "/login", ALICE)
q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(hd["Location"]).query))
check("login redirects to Keycloak auth endpoint",
      hd["Location"].startswith(ISSUER + "/protocol/openid-connect/auth?"), hd["Location"])
check("login uses PKCE S256 + state + nonce + exact redirect_uri",
      q.get("code_challenge_method") == "S256" and q.get("state") and q.get("nonce")
      and q.get("redirect_uri") == "https://mgr.test/oidc/callback", q)
check("login cookie is __Host-, Secure, HttpOnly", "__Host-webui-login=" in sc and "Secure" in sc and "HttpOnly" in sc, sc)

(st, hd, sc, body), _, _ = login(user="bob")
check("Keycloak user != cert CN -> 403", st == 403, st)
(st, hd, sc, body), _, _ = login(roles=("offline_access", "fabric-console-admin"))
check("user without any fabric permission -> 403 (a bundle name alone grants nothing)",
      st == 403 and "no fabric role" in body, (st, body[:200]))
for t in ("nonce", "aud", "expired", "sig"):
    (st, *_), _, _ = login(tamper=t)
    check(f"ID token with bad {t} -> 401", st == 401, st)
BOB_CERT = {**ALICE, "X-SSL-Client-Fingerprint": "bb" * 20}
(st, *_), _, _ = login(callback_cert=BOB_CERT)
check("callback presented with a different cert -> 400", st == 400, st)
st, *_ = req("GET", "/oidc/callback?code=x&state=forged", ALICE)
check("forged state -> 400", st == 400, st)

(st, hd, sc, body), _, _ = login()
session = cookie_val(sc, "__Host-webui")
check("valid login -> session cookie (Strict)", st == 200 and session and "SameSite=Strict" in sc, (st, sc))
check("security headers present", "default-src 'none'" in hd.get("Content-Security-Policy", "")
      and hd.get("X-Frame-Options") == "DENY" and hd.get("Cache-Control") == "no-store", hd)

st, hd, sc, body = req("GET", "/", ALICE, cookie=session)
# covers: web:get.home agent:get.services +
check("overview tab renders service health", st == 200 and "Overview" in body and "services healthy" in body, st)
# covers: agent:get.host-changes +
check("overview: the host changes through the agent (this test install declined fabric's services, never asked the rest)",
      "Host changes" in body and ">declined<" in body and ">not asked<" in body, body[-600:])
st, hd, sc, body = req("GET", "/kea", ALICE, cookie=session)
# covers: web:get.kea agent:get.dhcp +
check("Kea tab: DHCP off on this host, a form to turn it on (interface, subnet, pool) naming the firewall change",
      st == 200 and "DHCP is off" in body and 'action="/kea/on"' in body and 'name="interface"' in body
      and "67/udp" in body, (st, body[:300]))
st, hd, sc, body = req("GET", "/freeradius", ALICE, cookie=session)
# covers: web:get.freeradius agent:get.radius +
check("FreeRADIUS tab: 802.1X off on this host, how to turn it on",
      st == 200 and "802.1X is off" in body and "install_freeradius" in body and 'class="tab active"' in body,
      (st, body[:300]))
st, hd, sc, body = req("GET", "/", ALICE, cookie=session)
# covers: agent:get.version +
check("footer shows real version", "fabricctl 9.9.9" in body, body[-300:])
st, hd, sc, body = req("GET", "/bind9?zone=dynamic_zone_var", ALICE, cookie=session)
# covers: web:get.bind9 agent:get.zones.* +
check("BIND9 tab shows the zone's records and CNAME targets", st == 200 and "nas25-apps" in body and "192.168.7.53" in body, body[:500])
csrf = body.split('name="csrf" value="')[1].split('"')[0]
check("A record shows its automatic PTR", "53.7.168.192.in-addr.arpa" in body, body[:300])
st, hd, sc, body = req("GET", "/bind9?view=reverse", ALICE, cookie=session)
# covers: agent:get.reverse-zones +
check("reverse zones section lists generated PTRs", st == 200 and "7.168.192.in-addr.arpa" in body
      and "pi-core.lan.test." in body, body[:300])

st, hd, sc, body = req("GET", "/", BOB_CERT, cookie=session)
check("session cookie replayed with another cert -> redirect to login", st == 303, st)
st, hd, sc, body = req("GET", "/", ALICE, cookie=session)
check("...and that session is now destroyed", st == 303, st)

(st, hd, sc, body), _, _ = login()
session = cookie_val(sc, "__Host-webui")
st, hd, sc, body = req("GET", "/bind9?zone=dynamic_zone_var", ALICE, cookie=session)
csrf = body.split('name="csrf" value="')[1].split('"')[0]
# a browser sends its form posts' Origin only under a referrer policy that allows it to the same site: no-referrer
# makes it "Origin: null", which the CSRF check refuses, so every button failed in rc.2 (2.3.1.13 finding 9)
check("pages send Referrer-Policy: same-origin (the browser then sends the real Origin on its own form posts)",
      hd.get("Referrer-Policy") == "same-origin", hd.get("Referrer-Policy"))
st, *_ = req("POST", "/bind9/zone/dynamic_zone_var/add", {**ALICE, "Origin": "null"},
             {"csrf": csrf, "type": "CNAME", "name": "nullorigin", "target": "nas25-apps"}, cookie=session)
check("...and a post that arrives with Origin: null is still refused (what no-referrer made browsers send)",
      st == 403, st)
POSTH = {**ALICE, "Origin": "https://mgr.test"}
add = {"csrf": csrf, "type": "CNAME", "name": "shelfmark", "target": "nas25-apps"}
st, *_ = req("POST", "/bind9/zone/dynamic_zone_var/add", ALICE, dict(add), cookie=session)
# covers: web:post.bind9.zone.*.add -
check("POST without Origin -> 403", st == 403, st)
st, *_ = req("POST", "/bind9/zone/dynamic_zone_var/add", POSTH, {**add, "csrf": "nope"}, cookie=session)
check("POST with bad CSRF -> 403", st == 403, st)
st, *_ = req("POST", "/bind9/zone/dynamic_zone_var/add", {**POSTH, "Origin": "https://evil.test"}, dict(add), cookie=session)
check("POST from foreign origin -> 403", st == 403, st)
st, hd, *_ = req("POST", "/bind9/zone/dynamic_zone_var/add", POSTH, dict(add), cookie=session)
vars_text = open(f"{W}/fabric/config/vars.yaml").read()
# covers: web:post.bind9.zone.*.add agent:post.zones.*.records +
check("add CNAME -> saved to vars.yaml", st == 303 and "shelfmark" in vars_text and "msg=" in hd["Location"], (st, hd))
st, hd, *_ = req("POST", "/bind9/zone/dynamic_zone_var/add", POSTH,
                 {"csrf": csrf, "type": "A", "name": "bad name;rm", "ip": "1.2.3.4"}, cookie=session)
# covers: web:post.bind9.zone.*.add agent:post.zones.*.records -
check("invalid record name rejected", st == 303 and "err=" in hd["Location"], hd)
st, hd, *_ = req("POST", "/bind9/zone/dynamic_zone_var/add", POSTH,
                 {"csrf": csrf, "type": "TXT", "name": "x", "text": 'a"\n$INCLUDE /etc/shadow'}, cookie=session)
check("zone-file injection via TXT rejected", st == 303 and "err=" in hd["Location"], hd)
# zones (manual 1.4.1.3) through the real agent and fabriclib: refusals here (no BIND runs in this suite, so a valid
# name is refused too and rolled back); the zone served by BIND is tests/zones/run.py's
check("BIND9 tab: the New zone form (the site's own zone has no Remove)", 'action="/bind9/zones/new"' in body
      and "/bind9/zones/dynamic_zone_var/remove" not in body, body[:300])
for form, why in (({"name": "shop.example.com"}, "Hide the public name"), ({"name": "lan.test"}, "site's own domain"),
                  ({"name": "home.lan"}, "not added")):
    st, hd, *_ = req("POST", "/bind9/zones/new", POSTH, {"csrf": csrf, **form}, cookie=session)
    loc = urllib.parse.unquote_plus(hd.get("Location", ""))
    check(f"New zone refused ({why}): said why on the page, vars.yaml unchanged",
          st == 303 and why in loc and "home.lan" not in open(f"{W}/fabric/config/vars.yaml").read()
          and "shop.example.com" not in open(f"{W}/fabric/config/vars.yaml").read(), loc)
st, hd, *_ = req("POST", "/bind9/zones/dynamic_zone_var/remove", POSTH, {"csrf": csrf, "confirm": "lan.test"},
                 cookie=session)
check("Remove zone refused for the site's own zone, saying why",
      "cannot be removed" in urllib.parse.unquote_plus(hd.get("Location", "")), hd)
# DHCP on and off from the console (manual 1.10.3.5): refusals here, the real turn-on in the lab suite
for form, why, label in (({}, "give the interface, the subnet and a pool", "no settings and no first subnet"),
                         ({"interface": "eth9", "subnet": "10.20.0.0/24", "pool": "10.20.0.100 - 10.20.0.199"},
                          "no interface 'eth9'", "an interface this host does not have")):
    st, hd, *_ = req("POST", "/kea/on", POSTH, {"csrf": csrf, **form}, cookie=session)
    loc = urllib.parse.unquote_plus(hd.get("Location", ""))
    # covers: web:post.kea.on agent:post.dhcp.on -
    check(f"turn DHCP on refused: {label} (said why, nothing saved)",
          st == 303 and why in loc and "install_kea: true" not in open(f"{W}/fabric/config/vars.yaml").read(), loc)
st, hd, *_ = req("POST", "/kea/off", POSTH, {"csrf": csrf}, cookie=session)
# covers: web:post.kea.off agent:post.dhcp.off -
check("turn DHCP off when it is off: refused, saying so", "already off" in urllib.parse.unquote_plus(
    hd.get("Location", "")), hd)
# who may sign in, per OU (manual 1.6.11.4): the editor's refusals and a clear here; a set (groups checked in the
# domain) against a real DC in tests/samba/logon.py
vt = open(f"{W}/fabric/config/vars.yaml").read()
st, hd, *_ = req("POST", "/directory/logon/set", POSTH, {"csrf": csrf, "ou": "OU=x,DC=y", "console": "lan-admins"},
                 cookie=session)
loc = urllib.parse.unquote_plus(hd.get("Location", ""))
# covers: web:post.directory.logon.set agent:post.domain.logon.set -
check("log-on policy: an OU given as a DN is refused, saying why, nothing saved",
      st == 303 and "view=machines" in loc and "a path below" in loc
      and open(f"{W}/fabric/config/vars.yaml").read() == vt, (st, loc))
st, hd, *_ = req("POST", "/directory/logon/clear", POSTH, {"csrf": csrf, "ou": "machines"}, cookie=session)
loc = urllib.parse.unquote_plus(hd.get("Location", ""))
# covers: web:post.directory.logon.clear agent:post.domain.logon.clear -
check("log-on policy: clearing OU=machines, the site's machines' only policy, is refused, saying why, nothing saved",
      st == 303 and "no policy on the site's OU" in loc and open(f"{W}/fabric/config/vars.yaml").read() == vt,
      (st, loc))
st, hd, *_ = req("POST", "/directory/logon/clear", POSTH, {"csrf": csrf, "ou": "machines/lab"}, cookie=session)
loc = urllib.parse.unquote_plus(hd.get("Location", ""))
vt = open(f"{W}/fabric/config/vars.yaml").read()
# covers: web:post.directory.logon.clear agent:post.domain.logon.clear +
check("log-on policy: clearing OU=lab's own policy saves it (then the apply runs)",
      st == 303 and "machines/lab: cleared" in loc and "machines/lab" not in vt and "lan-admins" in vt, (st, loc))
st, hd, sc, body = req("GET", "/bind9?zone=dynamic_zone_var", ALICE, cookie=session)
idx = [row for row in body.split("<tr>") if "shelfmark" in row][0].split('name="index" value="')[1].split('"')[0]
st, hd, *_ = req("POST", "/bind9/zone/dynamic_zone_var/delete", POSTH,
                 {"csrf": csrf, "type": "CNAME", "index": idx, "name": "wrong-name"}, cookie=session)
# covers: web:post.bind9.zone.*.delete agent:post.zones.*.records.delete -
check("stale delete (name mismatch) refused", "err=" in hd.get("Location", ""), hd)
st, hd, *_ = req("POST", "/bind9/zone/dynamic_zone_var/delete", POSTH,
                 {"csrf": csrf, "type": "CNAME", "index": idx, "name": "shelfmark"}, cookie=session)
# covers: web:post.bind9.zone.*.delete agent:post.zones.*.records.delete +
check("delete CNAME -> removed from vars.yaml", "shelfmark" not in open(f"{W}/fabric/config/vars.yaml").read(), hd)
# 2.1.2.22: the record form asks type, name, value (and priority, weight, port for MX and SRV only)
st, hd, *_ = req("POST", "/bind9/zone/dynamic_zone_var/add", POSTH,
                 {"csrf": csrf, "type": "CNAME", "name": "valued", "value": "nas25-apps"}, cookie=session)
check("add a CNAME from the form's one value -> saved with its target",
      st == 303 and "name: valued" in open(f"{W}/fabric/config/vars.yaml").read(), hd)
st, hd, *_ = req("POST", "/bind9/zone/dynamic_zone_var/add", POSTH,
                 {"csrf": csrf, "type": "MX", "name": "@", "value": "mail"}, cookie=session)
check("an MX record without its priority is refused, saying why",
      "priority must be a number" in urllib.parse.unquote_plus(hd.get("Location", "")), hd)
# fabric's own names: marked, and a delete refused naming the setting (the apply would add them back); the landing
# page's info is the admin's since 0.7.1 (2.1.4.6): not marked, deleted, and added again pointing elsewhere
st, hd, sc, body = req("GET", "/bind9?zone=dynamic_zone_var", ALICE, cookie=session)
rows = body.split("<tr>")
mark = {n: any(f"<td>{n} " in r and "provided by fabric" in r for r in rows)
        for n in ("pi-core", "ca", "info", "calibre")}
check("fabric's own names (the host's A, ca) marked 'provided by fabric'; info and the admin's not",
      mark == {"pi-core": True, "ca": True, "info": False, "calibre": False}, mark)
# covers: web:post.bind9.zone.*.delete agent:post.zones.*.records.delete +
st, hd, *_ = req("POST", "/bind9/zone/dynamic_zone_var/delete", POSTH,
                 {"csrf": csrf, "type": "CNAME", "index": "1", "name": "info"}, cookie=session)
check("deleting info.<domain> works: an ordinary record now, gone from vars.yaml (the page stays at /info/)",
      st == 303 and "provided by fabric" not in urllib.parse.unquote_plus(hd.get("Location", ""))
      and "name: info" not in open(f"{W}/fabric/config/vars.yaml").read(), hd)
# covers: web:post.bind9.zone.*.add +
st, hd, *_ = req("POST", "/bind9/zone/dynamic_zone_var/add", POSTH,
                 {"csrf": csrf, "type": "CNAME", "name": "info", "value": "nas25-apps"}, cookie=session)
_cnames = (yaml.safe_load(open(f"{W}/fabric/config/vars.yaml"))["dns"]["dynamic_zone_var"].get("CNAME") or [])
check("info added again pointing at another machine (repointed), saved as the admin's record",
      st == 303 and {"name": "info", "canonical": "nas25-apps"} in _cnames, (hd, _cnames))
# covers: web:post.bind9.zone.*.delete agent:post.zones.*.records.delete -
st, hd, *_ = req("POST", "/bind9/zone/dynamic_zone_var/delete", POSTH,
                 {"csrf": csrf, "type": "CNAME", "index": "1", "name": "ca"}, cookie=session)
loc = urllib.parse.unquote_plus(hd.get("Location", ""))
check("deleting ca.<domain> is still refused: fabric's (the CA, and the CRL point), named with its setting",
      "provided by fabric" in loc and "cname_ca" in loc
      and any(r.get("name") == "ca" for r in yaml.safe_load(open(f"{W}/fabric/config/vars.yaml"))["dns"][
          "dynamic_zone_var"]["CNAME"]), loc)
st, hd, *_ = req("POST", "/bind9/zone/dynamic_zone_var/delete", POSTH,
                 {"csrf": csrf, "type": "A", "index": "0", "name": "pi-core"}, cookie=session)
check("deleting the host's own A record is refused, naming hostname",
      "provided by fabric" in urllib.parse.unquote_plus(hd.get("Location", ""))
      and "hostname" in urllib.parse.unquote_plus(hd.get("Location", "")), hd)
# the landing page's links, in their own section (2.1.2.22 item 4); kept on the record as before (2.1.4.2)
st, hd, sc, body = req("GET", "/bind9?view=landing", ALICE, cookie=session)
check("Landing page section: none linked yet, the add form lists the zone's records",
      st == 200 and "links to none of your records" in body and 'value="CNAME|0|calibre"' in body, body[:400])
# covers: web:post.bind9.landing.add agent:post.zones.*.records.link +
st, hd, *_ = req("POST", "/bind9/landing/add", POSTH, {"csrf": csrf, "record": "CNAME|0|calibre",
                                                       "link_label": "Calibre", "link_port": "8083"}, cookie=session)
vars_text = open(f"{W}/fabric/config/vars.yaml").read()
check("link calibre from the landing page -> saved on the record (link: label, port), listed",
      st == 303 and "label: Calibre" in vars_text and "port: 8083" in vars_text
      and "https://calibre.lan.test:8083/" in req("GET", "/bind9?view=landing", ALICE, cookie=session)[3], hd)
for form, why in (({"record": "CNAME|0|calibre", "link_port": "99999"}, "link port must be between"),
                  ({"record": "CNAME|0|calibre", "link_path": "no-slash"}, "invalid link path"),
                  ({"record": "CNAME|0|other"}, "record changed"), ({"record": ""}, "pick a record")):
    # covers: web:post.bind9.landing.add -
    st, hd, *_ = req("POST", "/bind9/landing/add", POSTH, {"csrf": csrf, **form}, cookie=session)
    check(f"link refused ({why}), saying why", why in urllib.parse.unquote_plus(hd.get("Location", "")), hd)
# covers: web:post.bind9.landing.remove -
st, hd, *_ = req("POST", "/bind9/landing/remove", POSTH, {"csrf": csrf, "type": "CNAME", "index": "0",
                                                          "name": "other"}, cookie=session)
check("stop linking a record changed since it was shown -> refused, saying why, the link kept",
      "record changed" in urllib.parse.unquote_plus(hd.get("Location", ""))
      and "Calibre" in open(f"{W}/fabric/config/vars.yaml").read(), hd)
# covers: web:post.bind9.landing.remove +
st, hd, *_ = req("POST", "/bind9/landing/remove", POSTH, {"csrf": csrf, "type": "CNAME", "index": "0",
                                                          "name": "calibre"}, cookie=session)
check("stop linking calibre -> its link gone from vars.yaml",
      st == 303 and "Calibre" not in open(f"{W}/fabric/config/vars.yaml").read(), hd)
# the password policy edited in the Domain section (2.1.2.22 item 2), checked as the command checks it
POLICY = {"minimum_length": "14", "history": "24", "minimum_age_days": "1", "maximum_age_days": "365",
          "lockout_threshold": "5", "lockout_minutes": "30", "lockout_window_minutes": "15", "complexity": "on"}
# covers: web:post.directory.domain.password-policy agent:post.domain.password-policy +
st, hd, *_ = req("POST", "/directory/domain/password-policy", POSTH, {"csrf": csrf, **POLICY}, cookie=session)
vars_text = open(f"{W}/fabric/config/vars.yaml").read()
check("password policy saved from the console (domain:admin) -> in vars.yaml, the next apply writes it",
      st == 303 and "Apply" in urllib.parse.unquote_plus(hd.get("Location", "")) and "minimum_length: 14" in vars_text
      and "lockout_minutes: 30" in vars_text, (hd, vars_text[-400:]))
for form, why in (({"lockout_minutes": "5", "lockout_window_minutes": "15"}, "at least as long"),
                  ({"minimum_age_days": "400"}, "must be below"), ({"minimum_length": "x"}, "whole number")):
    # covers: web:post.directory.domain.password-policy -
    st, hd, *_ = req("POST", "/directory/domain/password-policy", POSTH, {"csrf": csrf, **POLICY, **form},
                     cookie=session)
    check(f"password policy refused ({why}): said why, vars.yaml unchanged",
          why in urllib.parse.unquote_plus(hd.get("Location", ""))
          and "minimum_length: 14" in open(f"{W}/fabric/config/vars.yaml").read()
          and "lockout_minutes: 30" in open(f"{W}/fabric/config/vars.yaml").read(), hd)
st, hd, sc, body = req("GET", "/audit", ALICE, cookie=session)
# covers: web:get.audit agent:get.audit agent:post.events +
check("audit log records web actions with user", "User: alice (web) | Action: DNS_ADD" in body
      and "LOGIN_DENIED" in body, body[:400])

# ---- Step-CA tab: manual PKI through the agent
st, hd, sc, body = req("GET", "/stepca", ALICE, cookie=session)
# covers: web:get.stepca agent:get.pki.ca +
check("Step-CA tab shows the CA certificates", st == 200 and "Test Root CA" in body and "Test Intermediate CA" in body
      and "http://ca.lan.test/certs/" in body, body[:400])
views_ok = all(req("GET", f"/stepca?view={v}", ALICE, cookie=session)[0] == 200
               for v in ("sign", "issue", "inspect", "convert", "issued"))
check("every Step-CA menu page renders", views_ok)
sso_pem, sso_key = open(f"{W}/sso.crt").read(), open(f"{W}/sso.key").read()
sso_der = subprocess.run(["openssl", "x509", "-in", f"{W}/sso.crt", "-outform", "DER"], capture_output=True).stdout
st, hd, body = req_upload("/stepca/inspect", POSTH, {"csrf": csrf}, {"file": ("sso.cer", sso_der)}, session)
# covers: web:post.stepca.inspect agent:post.pki.inspect +
check("inspect a DER upload -> decoded, marked as issued by this fabric",
      st == 200 and "sso.test" in body and "issued by this fabric" in body, (st, body[:300]))
st, hd, body = req_upload("/stepca/inspect", POSTH, {"csrf": csrf, "data": sso_key}, {}, session)
# covers: web:post.stepca.inspect agent:post.pki.inspect -
check("inspect refuses a pasted private key (400, not echoed)",
      st == 400 and "private key" in body and "BEGIN" not in body.split("<textarea")[0], st)
st, hd, body = req_upload("/stepca/inspect", POSTH, {"csrf": "nope"}, {"file": ("x.crt", sso_pem.encode())}, session)
check("upload with bad CSRF -> 403", st == 403, st)
subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{W}/dev.key", "-out",
                f"{W}/dev.csr", "-subj", "/CN=dev.lan.test", "-addext", "subjectAltName=DNS:dev.lan.test,IP:192.168.7.9"],
               check=True, capture_output=True)
st, hd, body = req_upload("/stepca/sign/review", POSTH, {"csrf": csrf}, {"csr_file": ("dev.csr", open(f"{W}/dev.csr", "rb").read())}, session)
# covers: web:post.stepca.sign.review agent:post.pki.describe-csr +
check("CSR upload -> review with names and a Sign button",
      st == 200 and "dev.lan.test, 192.168.7.9" in body and "Sign certificate" in body, body[:400])
st, hd, body = req_upload("/stepca/convert", POSTH, {"csrf": csrf, "key": sso_key}, {"cert_file": ("sso.crt", sso_pem.encode())}, session)
# covers: web:post.stepca.convert agent:post.pki.convert +
check("convert cert + key -> downloads incl. .p12 and a one-time password",
      st == 200 and 'download="sso.test.p12"' in body and 'download="sso.test.cer"' in body and "shown once" in body,
      body[:400])
st, hd, sc, body = req("POST", "/stepca/issue", POSTH, {"csrf": csrf, "cn": "bad name!", "key_type": "RSA-2048",
                                                        "days": "30"}, cookie=session)
# covers: web:post.stepca.issue agent:post.pki.issue -
check("invalid request -> form again with the reason (400)", st == 400 and "not a host name" in body, (st, body[:300]))

# ---- the Directory tab without the domain controller: the page says so, nothing breaks
st, hd, sc, body = req("GET", "/directory", ALICE, cookie=session)
check("Directory tab reports an unreachable directory instead of failing", st == 200 and "could not be read" in body, (st, body[:300]))
st, hd, sc, body = req("GET", "/stepca?view=issue", ALICE, cookie=session)
check("Step-CA still works without the directory (no device list)", st == 200 and 'select name="device"' not in body, st)

st, hd, sc, body = req("GET", "/openbao", ALICE, cookie=session)
check("OpenBao tab reports an unreachable vault instead of failing", st == 200 and "Unreachable" in body, (st, body[:300]))
st, hd, sc, body = req("GET", "/openbao?view=unlock", ALICE, cookie=session)
# covers: web:get.openbao +
check("unlock methods page renders from the host, every method type addable",
      st == 200 and "Add an unlock method" in body and "arrives next" not in body, (st, body[:300]))
st, hd, *_ = req("POST", "/openbao/rotate", POSTH, {"csrf": csrf, "confirm": "x"}, cookie=session)
# covers: web:post.openbao.rotate -
check("vault change: the host name must be typed", st == 303 and "Type+this+host" in hd.get("Location", ""), hd)
st, hd, *_ = req("POST", "/openbao/rotate", POSTH, {"csrf": csrf, "confirm": "pi-core"}, cookie=session)
# covers: agent:post.vault.rotate -
check("vault change: confirmed and fresh -> reaches the agent (which refuses: this test host has no vault key)",
      st == 303 and "no+vault+key" in hd.get("Location", ""), hd)
st, hd, *_ = req("POST", "/openbao/slots/add-hsm", POSTH, {"csrf": csrf, "confirm": "pi-core"}, cookie=session)
# covers: web:post.openbao.slots.add-hsm agent:post.vault.slots.add-hsm -
check("add HSM: the agent refuses an empty endpoint (validated before anything is touched)",
      "endpoint" in hd.get("Location", "") and "err=" in hd.get("Location", ""), hd)
st, hd, *_ = req("POST", "/openbao/slots/add-usb", POSTH, {"csrf": csrf, "confirm": "pi-core", "disk": "/dev/nope"},
                 cookie=session)
# covers: web:post.openbao.slots.add-usb agent:post.vault.slots.add-usb -
check("add USB: the agent refuses a disk that does not exist", "not+a+disk" in hd.get("Location", ""), hd)
st, hd, *_ = req("POST", "/openbao/slots/add-security-key", POSTH,
                 {"csrf": csrf, "confirm": "pi-core", "token": "/tmp/evil.so|1234", "pin": "123456", "key": "new"},
                 cookie=session)
# covers: web:post.openbao.slots.add-security-key agent:post.vault.slots.add-security-key -
check("add security key: a library not on the allowed list is never loaded", "allowed+list" in hd.get("Location", ""), hd)
(st, hd, sc, body), _, _ = login(tamper="stale")
stale = cookie_val(sc, "__Host-webui")
st, hd, sc, body = req("GET", "/openbao?view=unlock", ALICE, cookie=stale)
stale_csrf = body.split('name="csrf" value="')[1].split('"')[0]
st, hd, *_ = req("POST", "/openbao/rotate", POSTH, {"csrf": stale_csrf, "confirm": "pi-core"}, cookie=stale)
check("vault change with a sign-in older than 5 minutes -> sign in again first (step-up)",
      st == 303 and hd.get("Location", "").startswith("/login?next=%2Fopenbao"), hd)
(st, hd, sc, body), _, _ = login(next_path="/openbao?view=unlock")
check("after signing in, back to where the change was made", st == 200 and "url=/openbao?view=unlock" in body, body[:300])
(st, hd, sc, body), _, _ = login(next_path="//evil.test/x")
check("next= cannot leave this site (no open redirect)", st == 200 and 'url=/"' in body and "evil" not in body, body[:300])

# ---- BIND9 tab: TSIG keys for a zone
st, hd, sc, body = req("GET", "/bind9?view=tsig", ALICE, cookie=session)
check("TSIG view renders the create form", st == 200 and "New TSIG key for a zone" in body, st)
st, hd, sc, body = req("POST", "/bind9/tsig/create", POSTH, {"csrf": csrf, "name": "npm-certbot", "zone": "lan.test",
                                                              "scope": "acme-hosts", "hosts": "npm, nas"}, cookie=session)
secret = body.split('<code class="secret">')[1].split("<")[0] if '<code class="secret">' in body else ""
# covers: web:post.bind9.tsig.create agent:post.tsig +
check("create TSIG key -> secret and rfc2136.ini shown once", st == 200 and secret
      and "dns_rfc2136_name = npm-certbot" in body, body[:300])
vt = open(f"{W}/fabric/config/vars.yaml").read()
check("...key saved, secret kept out of vars.yaml", "npm-certbot" in vt and secret not in vt
      and secret in open(f"{W}/fabric/config/fabric-secrets.yml").read())
st, hd, sc, body = req("GET", "/bind9?view=tsig", ALICE, cookie=session)
# covers: agent:get.tsig +
check("TSIG list shows the key's rights, never its secret",
      "_acme-challenge.npm.lan.test" in body and secret not in body, body[:300])
st, hd, sc, body = req("POST", "/bind9/tsig/create", POSTH, {"csrf": csrf, "name": "x", "zone": "evil.test",
                                                              "scope": "acme-zone"}, cookie=session)
# covers: web:post.bind9.tsig.create agent:post.tsig -
check("TSIG key for a zone fabric does not serve -> refused", st == 400 and "forward zones" in body, st)
st, hd, sc, body = req("POST", "/bind9/tsig/npm-certbot/rotate", POSTH, {"csrf": csrf}, cookie=session)
new = body.split('<code class="secret">')[1].split("<")[0] if '<code class="secret">' in body else ""
# covers: web:post.bind9.tsig.*.rotate agent:post.tsig.*.rotate +
check("rotate -> a new secret", st == 200 and new and new != secret, st)
st, hd, *_ = req("POST", "/bind9/tsig/npm-certbot/delete", POSTH, {"csrf": csrf}, cookie=session)
# covers: web:post.bind9.tsig.*.delete agent:post.tsig.*.delete +
check("delete TSIG key -> removed", st == 303 and "npm-certbot" not in open(f"{W}/fabric/config/vars.yaml").read(), st)
vt = open(f"{W}/fabric/config/vars.yaml").read()
st, hd, sc, body = req("POST", "/bind9/tsig/ghost/rotate", POSTH, {"csrf": csrf}, cookie=session)
# covers: web:post.bind9.tsig.*.rotate -
check("rotate a TSIG key that does not exist -> refused (400, named), nothing changed",
      st == 400 and "no TSIG key named" in body and "ghost" in body
      and open(f"{W}/fabric/config/vars.yaml").read() == vt, (st, body[:300]))
st, hd, sc, body = req("POST", "/bind9/tsig/ghost/delete", POSTH, {"csrf": csrf}, cookie=session)
# covers: web:post.bind9.tsig.*.delete -
check("delete a TSIG key that does not exist -> refused (400, named), nothing changed",
      st == 400 and "no TSIG key named" in body and open(f"{W}/fabric/config/vars.yaml").read() == vt,
      (st, body[:300]))
st, hd, sc, body = req("POST", "/bind9/tsig/acme-old/delete", POSTH, {"csrf": "nope"}, cookie=session)
check("TSIG delete with a bad CSRF token -> 403, nothing changed",
      st == 403 and open(f"{W}/fabric/config/vars.yaml").read() == vt, st)
st, hd, sc, body = req("POST", "/stepca/acme/enroll", POSTH, {"csrf": csrf, "host": "nas", "domain": "lan.test"},
                       cookie=session)
# covers: web:post.stepca.acme.enroll +
check("ACME enroll a machine for DNS-01 -> its key acme-nas, the secret and rfc2136.ini shown once",
      st == 200 and '<code class="secret">' in body and "dns_rfc2136_name = acme-nas" in body
      and "acme-nas" in open(f"{W}/fabric/config/vars.yaml").read(), (st, body[:300]))
st, hd, sc, body = req("GET", "/stepca?view=acme", ALICE, cookie=session)
check("Step-CA ACME view lists the enrolled machine and the directory",
      st == 200 and "nas.lan.test" in body and "https://ca.lan.test/acme/acme/directory" in body, (st, body[:300]))
vt = open(f"{W}/fabric/config/vars.yaml").read()
st, hd, sc, body = req("POST", "/stepca/acme/enroll", POSTH, {"csrf": csrf, "host": "nas2", "domain": "evil.test"},
                       cookie=session)
# covers: web:post.stepca.acme.enroll -
check("ACME enroll for a zone fabric does not serve -> the ACME view again with the reason (400), no key made",
      st == 400 and "forward zones" in body and open(f"{W}/fabric/config/vars.yaml").read() == vt, (st, body[:300]))
st, hd, sc, body = req("GET", "/audit", ALICE, cookie=session)
check("audit log records TSIG and PKI actions", "TSIG_ADD" in body and "TSIG_SECRET" in body
      and "PKI_CONVERT" in body, body[:300])

st, hd, sc, body = req("POST", "/logout", POSTH, {"csrf": csrf}, cookie=session)
# covers: web:post.logout +
check("logout -> Keycloak end-session with id_token_hint",
      st == 303 and "/protocol/openid-connect/logout?id_token_hint=" in hd.get("Location", ""), hd)
st, *_ = req("GET", "/", ALICE, cookie=session)
check("session invalid after logout", st == 303, st)

print("--- role bundles in the pages (RBAC)")
(st, hd, sc, body), _, _ = login(roles=tuple(AUDITOR_ROLES))
aud = cookie_val(sc, "__Host-webui")
check("an auditor signs in", st == 200 and aud, st)
st, _, _, body = req("GET", "/bind9", ALICE, cookie=aud)
check("auditor: DNS records shown, no add/delete forms, no Apply", st == 200 and "nas25-apps" in body
      and "/bind9/zone/dynamic_zone_var/add" not in body and "/bind9/zones/new" not in body and 'action="/apply"' not in body, body[:300])
st, _, _, body = req("GET", "/stepca", ALICE, cookie=aud)
check("auditor: Step-CA without Sign / New key / Convert", st == 200 and "Sign a CSR" not in body
      and "New key + certificate" not in body and "Certificate authority" in body, body[:300])
st, _, _, body = req("GET", "/openbao?view=unlock", ALICE, cookie=aud)
check("auditor: unlock methods listed, no rotate / add / remove", st == 200 and 'action="/openbao/rotate"' not in body
      and "/openbao/slots/add-usb" not in body, body[:300])
st, hd, _, body = req("GET", "/", ALICE, cookie=aud)
check("auditor: every tab shown (all read permissions)", all(t in body for t in ("/bind9", "/stepca", "/directory", "/openbao")))
st, _, _, body = req("POST", "/bind9/zone/dynamic_zone_var/add", POSTH,
                     {"csrf": cookie_csrf(aud), "type": "A", "name": "sneaky", "ip": "192.168.7.9"}, cookie=aud)
# covers: web:post.bind9.zone.*.add agent:post.zones.*.records -
check("auditor: a crafted POST is refused by fabric-agent (403, permission named)",
      st == 403 and "dns:write" in body and "sneaky" not in open(f"{W}/fabric/config/vars.yaml").read(), (st, body[:200]))
st, _, _, body = req("POST", "/kea/on", POSTH, {"csrf": cookie_csrf(aud), "interface": "eth0",
                                                "subnet": "10.20.0.0/24", "pool": "10.20.0.100 - 10.20.0.199"}, cookie=aud)
# covers: web:post.kea.on agent:post.dhcp.on -
check("auditor: turning DHCP on is refused by fabric-agent (403, dhcp:write)",
      st == 403 and "dhcp:write" in body and "install_kea: true" not in open(f"{W}/fabric/config/vars.yaml").read(),
      (st, body[:200]))
netops = bundle_roles("fabric-network-operator")
(st, hd, sc, body), _, _ = login(roles=tuple(netops))
net = cookie_val(sc, "__Host-webui")
st, _, _, body = req("GET", "/", ALICE, cookie=net)
check("network operator: no Directory or 802.1X tab (no device management)",
      "/directory" not in body and "/freeradius" not in body and "/bind9" in body, body[:300])
(st, hd, sc, body), _, _ = login(roles=tuple(bundle_roles("fabric-pki-operator")))
pkiop = cookie_val(sc, "__Host-webui")
st, _, _, body = req("GET", "/bind9", ALICE, cookie=pkiop)
# covers: web:get.bind9 -
check("PKI operator (no dns:read): the BIND9 page is refused by fabric-agent (403, the permission named)",
      st == 403 and "dns:read" in body and "nas25-apps" not in body, (st, body[:300]))
vt = open(f"{W}/fabric/config/vars.yaml").read()
st, _, _, body = req("POST", "/directory/devices/printer/certs/unlink", POSTH,
                     {"csrf": cookie_csrf(aud), "sha256": "aa" * 32}, cookie=aud)
# covers: web:post.directory.devices.*.certs.unlink -
check("auditor: unlinking a device's certificate is refused by fabric-agent (403, pki:link-device), nothing changed",
      st == 403 and "pki:link-device" in body and open(f"{W}/fabric/config/vars.yaml").read() == vt, (st, body[:300]))
for path, form in (("/directory/logon/set", {"ou": "machines", "console": "lan-users", "remote": "lan-users"}),
                   ("/directory/logon/clear", {"ou": "machines"})):
    st, _, _, body = req("POST", path, POSTH, {"csrf": cookie_csrf(aud), **form}, cookie=aud)
    # covers: web:post.directory.logon.set web:post.directory.logon.clear -
    check(f"auditor: {path} (who may sign in) is refused by fabric-agent (403, gpo:admin), nothing changed",
          st == 403 and "gpo:admin" in body and open(f"{W}/fabric/config/vars.yaml").read() == vt, (st, body[:300]))
# host groups and sudo rules (manual 1.6.11.7): refused before the directory is asked; the changes themselves against a
# real DC in tests/samba/hostgroups.py
for path, form, perm in (("/directory/hostgroups/_new", {"name": "web"}, "machines:admin"),
                         ("/directory/hostgroups/_form/members", {"group": "web", "machine": "ws1", "action": "add"},
                          "machines:admin"),
                         ("/directory/hostgroups/web/delete", {}, "machines:admin"),
                         ("/directory/sudo/_new", {"name": "r", "users": "alice", "commands": "/bin/true"},
                          "sudo:admin"),
                         ("/directory/sudo/r/delete", {}, "sudo:admin")):
    st, _, _, body = req("POST", path, POSTH, {"csrf": cookie_csrf(aud), **form}, cookie=aud)
    # covers: web:post.directory.hostgroups._new web:post.directory.hostgroups._form.members -
    # covers: web:post.directory.hostgroups.*.delete web:post.directory.sudo._new web:post.directory.sudo.*.delete -
    check(f"auditor: {path} is refused by fabric-agent (403, {perm})", st == 403 and perm in body, (st, body[:300]))

(st, hd, sc, body), _, _ = login(tamper="short")
short = cookie_val(sc, "__Host-webui")
st, *_ = req("GET", "/", ALICE, cookie=short)
check("a token about to expire is renewed (refresh grant), the session goes on", st == 200, st)
for r in REFRESH.values():
    r["roles"] = []                    # an administrator removed the user from every fabric group
st, hd, *_ = req("GET", "/", ALICE, cookie=short)
check("roles removed in Keycloak: at the next renewal the session ends", st == 303 and hd.get("Location") == "/login",
      (st, hd.get("Location")))

print("--- isolation")
def dexec(cmd):
    return subprocess.run(["docker", "exec", "cwebui", "sh", "-c", cmd], capture_output=True, text=True)
check("container runs as uid 912", dexec("id -u").stdout.strip() == "912", dexec("id -u").stdout)
check("container has no capabilities", "CapEff:\t0000000000000000" in dexec("cat /proc/1/status").stdout)
check("container root filesystem is read-only", dexec("touch /app/x").returncode != 0)
check("container cannot write the agent mount", dexec("touch /agent/x").returncode != 0)
check("no Docker socket in the container", dexec("test -e /var/run/docker.sock").returncode != 0)
check("container cannot read host fabric config", dexec("test -e /fabric").returncode != 0)
probe = ("import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); "
         "s.sendall(b'GET /v1/zones HTTP/1.0\\r\\n\\r\\n'); print(s.recv(200).split(b'\\r\\n')[0].decode())")
r = subprocess.run(["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", sys.executable, "-c", probe,
                    f"{W}/agent/agent.sock"], capture_output=True, text=True)
check("other users cannot reach the agent socket", "Permission denied" in r.stderr, r.stdout + r.stderr[-200:])
r = subprocess.run(["setpriv", "--reuid=913", f"--regid={UID}", "--clear-groups", sys.executable, "-c", probe,
                    f"{W}/agent/agent.sock"], capture_output=True, text=True)
check("agent rejects a wrong uid even with the right group (SO_PEERCRED)", "403" in r.stdout, r.stdout + r.stderr[-200:])
r = subprocess.run(["docker", "exec", "cwebui", "python3", "-c", probe, "/agent/agent.sock"],
                   capture_output=True, text=True)
check("from the web UI container, a call without a sign-in token is refused (401)", "401" in r.stdout,
      r.stdout + r.stderr[-200:])

print("--- fabric-agent: permissions from the signed token (RBAC)")
CALL = ("import json,socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); b=sys.argv[4].encode(); "
        "s.sendall(f'{sys.argv[2]} {sys.argv[3]} HTTP/1.0\\r\\nAuthorization: Bearer {sys.argv[5]}\\r\\n"
        "Content-Type: application/json\\r\\nContent-Length: {len(b)}\\r\\n\\r\\n'.encode()+b); "
        "r=b''\nwhile True:\n c=s.recv(65536)\n if not c: break\n r+=c\n"
        "print(r.split(b'\\r\\n')[0].decode()); print(r.split(b'\\r\\n\\r\\n',1)[1].decode()[:300])")


def agent_call(method, path, user, roles, body=None, exp=300):
    now = int(time.time())
    token = sign_jwt({"iss": ISSUER, "aud": "fabric-webui", "azp": "fabric-webui", "sub": "u1", "iat": now,
                      "exp": now + exp, "preferred_username": user, "roles": list(roles)})
    r = subprocess.run(["setpriv", f"--reuid={UID}", f"--regid={UID}", "--clear-groups", sys.executable, "-c", CALL,
                        f"{W}/agent/agent.sock", method, path, json.dumps(body or {}), token],
                       capture_output=True, text=True)
    return r.stdout + r.stderr[-300:]


out = agent_call("GET", "/v1/zones", "alice", AUDITOR_ROLES)
check("auditor token: may read zones", " 200 " in out, out)
out = agent_call("POST", "/v1/zones/dynamic_zone_var/records", "carol", AUDITOR_ROLES,
                 {"actor": "carol", "type": "A", "name": "nope", "ip": "192.168.7.9"})
# covers: agent:post.zones.*.records -
check("auditor token: may not add a record (403, the permission named)", " 403 " in out and "dns:write" in out, out)
# covers: agent:post.zones.*.records.link -
out = agent_call("POST", "/v1/zones/dynamic_zone_var/records/link", "carol", AUDITOR_ROLES,
                 {"type": "CNAME", "index": 0, "name": "calibre", "link": "on"})
check("auditor token: may not link a record from the landing page (403, dns:write)", " 403 " in out and "dns:write" in out,
      out)
# covers: agent:post.domain.password-policy -
out = agent_call("POST", "/v1/domain/password-policy", "carol", AUDITOR_ROLES, {"minimum_length": 4})
check("auditor token: may not change the password policy (403, domain:admin)", " 403 " in out and "domain:admin" in out,
      out)
out = agent_call("POST", "/v1/domain/password-policy", "carol", bundle_roles("fabric-equipment-operator"),
                 {"minimum_length": 4})
check("equipment operator token: may not change it either (domain:admin is the admins' only)",
      " 403 " in out and "domain:admin" in out, out)
out = agent_call("POST", "/v1/zones/dynamic_zone_var/records/link", "alice", ADMIN_ROLES,
                 {"type": "TXT", "index": 0, "name": "x", "link": "on"})
check("refused through the agent: linking a TXT record (400)", " 400 " in out and "only A, AAAA and CNAME" in out, out)
out = agent_call("POST", "/v1/zones", "carol", AUDITOR_ROLES, {"actor": "carol", "name": "home.lan"})
check("auditor token: may not add a zone (403, dns:write)", " 403 " in out and "dns:write" in out, out)
out = agent_call("POST", "/v1/zones/home.lan/delete", "carol", AUDITOR_ROLES, {"actor": "carol", "confirm": "home.lan"})
check("auditor token: may not remove a zone (403, dns:write)", " 403 " in out and "dns:write" in out, out)
out = agent_call("POST", "/v1/people", "carol", AUDITOR_ROLES, {"uid": "mallory", "first": "M", "last": "M",
                                                                "email": "m@x.test"})
# covers: agent:post.people -
check("auditor token: may not create people (403, people:create)", " 403 " in out and "people:create" in out, out)
out = agent_call("POST", "/v1/people/alice/reset", "carol", AUDITOR_ROLES)
# covers: agent:post.people.*.reset -
check("auditor token: may not reset a sign-in (403, people:reset)", " 403 " in out and "people:reset" in out, out)
for route, perm in (("disable", "people:disable"), ("enable", "people:disable"), ("delete", "people:remove"),
                    ("groups", "people:groups")):
    out = agent_call("POST", f"/v1/people/alice/{route}", "carol", AUDITOR_ROLES, {"confirm": "alice"})
    # covers: agent:post.people.*.disable agent:post.people.*.enable agent:post.people.*.delete agent:post.people.*.groups -
    check(f"auditor token: may not {route} a person (403, {perm})", " 403 " in out and perm in out, out)
out = agent_call("POST", "/v1/jobs/images", "carol", AUDITOR_ROLES, {"action": "update", "service": "nginx"})
# covers: agent:post.jobs.images -
check("auditor token: may not update an image (403, images:update)", " 403 " in out and "images:update" in out, out)
out = agent_call("POST", "/v1/jobs/doctor", "carol", AUDITOR_ROLES)
job = json.loads(out.split("\n", 1)[1]).get("id", "") if " 200 " in out else ""
# covers: agent:post.jobs.doctor +
check("auditor token: may run doctor as a job (status:read): an id comes back", bool(job), out)
out = agent_call("GET", f"/v1/jobs/{job}", "carol", AUDITOR_ROLES)
# covers: agent:get.jobs.* +
check("...and read it back (running, done or failed: it is theirs)", " 200 " in out and '"kind": "doctor"' in out, out)
out = agent_call("GET", f"/v1/jobs/{job}", "alice", ADMIN_ROLES)
# covers: agent:get.jobs.* -
check("refused: another person's job, even an admin's request (no such job)", " 400 " in out and "no such job" in out,
      out)
out = agent_call("GET", "/v1/images", "carol", AUDITOR_ROLES)
check("auditor token: may read the image status (status:read)", " 200 " in out, out)
for route, perm in (("delete", "people:remove"), ("groups", "people:groups")):
    out = agent_call("POST", f"/v1/people/alice/{route}", "carol", bundle_roles("fabric-helpdesk"), {"confirm": "alice"})
    check(f"helpdesk token: may not {route} a person (403, {perm}: admins only)", " 403 " in out and perm in out, out)
out = agent_call("POST", "/v1/radius/clients", "carol", AUDITOR_ROLES, {"name": "evil", "address": "192.168.7.66"})
# covers: agent:post.radius.clients -
check("auditor token: may not add a RADIUS client (403, radius:admin)", " 403 " in out and "radius:admin" in out, out)
out = agent_call("POST", "/v1/radius/clients", "carol", bundle_roles("fabric-network-operator"),
                 {"name": "evil", "address": "192.168.7.66"})
out2 = agent_call("POST", "/v1/radius/people", "carol", AUDITOR_ROLES, {"group": "admins"})
# covers: agent:post.radius.people -
check("auditor token: may not map a group for network logins (403, radius:admin)",
      " 403 " in out2 and "radius:admin" in out2, out2)
check("network operator token: may not add a RADIUS client either (802.1X is equipment operators')",
      " 403 " in out and "radius:admin" in out, out)
# DNS and PKI routes: each refuses a token without its permission, naming it; nothing changes
DNS_ONLY = ("fabric:dns:read",)                      # a person granted only dns:read
PKI_OPS = bundle_roles("fabric-pki-operator")        # no dns:read
out = agent_call("GET", "/v1/zones", "carol", AUDITOR_ROLES)
# covers: agent:get.zones +
check("auditor token: GET /v1/zones lists the zones", " 200 " in out and '"key": "dynamic_zone_var"' in out, out)
for path, roles, perm, ids in (("/v1/zones", PKI_OPS, "dns:read", "agent:get.zones"),
                               ("/v1/zones/dynamic_zone_var", PKI_OPS, "dns:read", "agent:get.zones.*"),
                               ("/v1/reverse-zones", PKI_OPS, "dns:read", "agent:get.reverse-zones"),
                               ("/v1/tsig", PKI_OPS, "dns:read", "agent:get.tsig"),
                               ("/v1/pki/ca", DNS_ONLY, "pki:read", "agent:get.pki.ca"),
                               ("/v1/pki/issued", DNS_ONLY, "pki:read", "agent:get.pki.issued"),
                               ("/v1/pki/acme", DNS_ONLY, "pki:read", "agent:get.pki.acme"),
                               ("/v1/cert-warnings", DNS_ONLY, "status:read", "agent:get.cert-warnings")):
    out = agent_call("GET", path, "carol", roles)
    # covers: agent:get.zones agent:get.zones.* agent:get.reverse-zones agent:get.tsig agent:get.pki.ca -
    # covers: agent:get.pki.issued agent:get.pki.acme agent:get.cert-warnings -
    check(f"refused: GET {path} without {perm} ({ids}): 403, the permission named",
          " 403 " in out and f"you need the permission {perm}" in out, out)
out = agent_call("GET", "/v1/domain/logon", "carol", AUDITOR_ROLES)
# covers: agent:get.domain.logon +
check("auditor token: GET /v1/domain/logon shows each OU's policy (domain:read)",
      " 200 " in out and '"ou": "machines"' in out and "lan-admins" in out, out)
out = agent_call("GET", "/v1/domain/logon", "carol", PKI_OPS)
# covers: agent:get.domain.logon -
check("refused: GET /v1/domain/logon without domain:read (403, the permission named)",
      " 403 " in out and "you need the permission domain:read" in out, out)
for path in ("/v1/host-groups", "/v1/sudo"):
    out = agent_call("GET", path, "carol", PKI_OPS)
    # covers: agent:get.host-groups agent:get.sudo -
    check(f"refused: GET {path} without domain:read (403, the permission named)",
          " 403 " in out and "you need the permission domain:read" in out, out)
for path, perm in (("/v1/host-groups", "machines:admin"), ("/v1/host-groups/web/members", "machines:admin"),
                   ("/v1/host-groups/web/delete", "machines:admin"), ("/v1/sudo", "sudo:admin"),
                   ("/v1/sudo/r/delete", "sudo:admin")):
    out = agent_call("POST", path, "carol", AUDITOR_ROLES, {"name": "web", "action": "add", "machine": "ws1"})
    # covers: agent:post.host-groups agent:post.host-groups.*.members agent:post.host-groups.*.delete -
    # covers: agent:post.sudo agent:post.sudo.*.delete -
    check(f"auditor token: may not change host groups or sudo rules, POST {path} (403, {perm})",
          " 403 " in out and perm in out, out)
for path in ("/v1/domain/logon/set", "/v1/domain/logon/clear"):
    out = agent_call("POST", path, "carol", AUDITOR_ROLES, {"ou": "machines", "console": ["lan-users"]})
    # covers: agent:post.domain.logon.set agent:post.domain.logon.clear -
    check(f"auditor token: may not change who signs in, POST {path} (403, gpo:admin)",
          " 403 " in out and "gpo:admin" in out, out)
out = agent_call("GET", "/v1/zones/nope", "alice", ADMIN_ROLES)
# covers: agent:get.zones.* -
check("refused: a zone that does not exist (400, unknown zone)", " 400 " in out and "unknown zone" in out, out)
vt = open(f"{W}/fabric/config/vars.yaml").read()
issued_ledger = f"{W}/fabric/archive/issued-certs.jsonl"
ledger_before = open(issued_ledger).read() if os.path.exists(issued_ledger) else ""
csr_pem = open(f"{W}/dev.csr").read()
for path, body_, roles, perm, ids in (
        ("/v1/pki/sign", {"csr": csr_pem, "days": 30}, AUDITOR_ROLES, "pki:sign", "agent:post.pki.sign"),
        ("/v1/pki/issue", {"cn": "x.lan.test", "key_type": "RSA-2048", "days": 30}, AUDITOR_ROLES, "pki:issue",
         "agent:post.pki.issue"),
        ("/v1/pki/convert", {"cert": sso_pem, "key": sso_key}, AUDITOR_ROLES, "pki:issue", "agent:post.pki.convert"),
        ("/v1/pki/revoke", {"target": "sso.test"}, AUDITOR_ROLES, "pki:revoke", "agent:post.pki.revoke"),
        ("/v1/pki/describe-csr", {"csr": csr_pem}, DNS_ONLY, "pki:read", "agent:post.pki.describe-csr"),
        ("/v1/tsig/acme-nas/rotate", {}, AUDITOR_ROLES, "tsig:manage", "agent:post.tsig.*.rotate"),
        ("/v1/tsig/acme-nas/delete", {}, AUDITOR_ROLES, "tsig:manage", "agent:post.tsig.*.delete"),
        ("/v1/devices/printer/certs", {"sha256": "aa" * 32}, AUDITOR_ROLES, "pki:link-device",
         "agent:post.devices.*.certs")):
    out = agent_call("POST", path, "carol", roles, body_)
    # covers: agent:post.pki.sign agent:post.pki.issue agent:post.pki.convert agent:post.pki.revoke -
    # covers: agent:post.pki.describe-csr agent:post.tsig.*.rotate agent:post.tsig.*.delete agent:post.devices.*.certs -
    check(f"refused: POST {path} without {perm} ({ids}): 403, the permission named, nothing changed",
          " 403 " in out and f"you need the permission {perm}" in out
          and open(f"{W}/fabric/config/vars.yaml").read() == vt
          and (open(issued_ledger).read() if os.path.exists(issued_ledger) else "") == ledger_before, out)
out = agent_call("GET", "/v1/nope", "alice", ADMIN_ROLES)
check("a route that is not in the permission table is refused even for the admin", " 403 " in out, out)
out = agent_call("GET", "/v1/zones", "alice", ADMIN_ROLES, exp=-600)
check("an expired token is refused (401)", " 401 " in out, out)
out = agent_call("POST", "/v1/zones/dynamic_zone_var/records", "alice", ADMIN_ROLES,
                 {"actor": "mallory", "type": "A", "name": "rbac-probe", "ip": "192.168.7.9"})
audit_tail = open(f"{W}/fabric/archive/audit.log").read().splitlines()[-1] if os.path.exists(
    f"{W}/fabric/archive/audit.log") else ""
check("the audit log names the token's user, not the actor the request claims",
      " 200 " in out and "alice" in audit_tail and "mallory" not in audit_tail, (out, audit_tail))

print("--- DHCP, DNS filter, 802.1X, vault and images through the console (the real agent, the real vars.yaml)")
VARS = f"{W}/fabric/config/vars.yaml"
SECRETS = f"{W}/fabric/config/fabric-secrets.yml"


def vars_now():
    return open(VARS).read()


def secrets_now():
    return open(SECRETS).read() if os.path.exists(SECRETS) else ""


def vars_key(key):
    import yaml
    return yaml.safe_load(vars_now()).get(key)


def web_post(path, form, sess, token):
    """A console form: its status, the Location it sends back (decoded) and its body."""
    st, hd, _, body = req("POST", path, POSTH, {"csrf": token, **form}, cookie=sess)
    return st, urllib.parse.unquote_plus(hd.get("Location", "")), body


(st, hd, sc, body), _, _ = login()
adm = cookie_val(sc, "__Host-webui")
acsrf = cookie_csrf(adm)


def fresh(roles=tuple(ADMIN_ROLES)):
    """A new sign-in with these roles: its session cookie and CSRF token (vault changes need one under 5 minutes)."""
    (_st, _hd, set_cookie, _body), _, _ = login(roles=tuple(roles))
    cookie = cookie_val(set_cookie, "__Host-webui")
    return cookie, cookie_csrf(cookie)


aud, aud_csrf = fresh(AUDITOR_ROLES)
# Every change below runs fabric's apply. This test install has no deployment to apply to: the apply must fail here,
# so nothing is deployed and the host firewall is never touched (post_dhcp refreshes it only after an apply that worked).
applies = [ln for ln in open(f"{W}/fabric/archive/audit.log").read().splitlines() if "Action: APPLY" in ln]
SAFE = bool(applies) and all("exit=0" not in ln for ln in applies)
check("this test install cannot apply (no deployment): the changes below are saved, never deployed to this host",
      SAFE, applies[-3:])

# ---- the pages: each refused without its read permission, the permission named
for path, roles, perm, ident in (("/kea", PKI_OPS, "dhcp:read", "web:get.kea"),
                                 ("/freeradius", netops, "radius:read", "web:get.freeradius"),
                                 ("/openbao", bundle_roles("fabric-helpdesk"), "vault:status", "web:get.openbao"),
                                 ("/dns-filter", AUDITOR_ROLES, "dns:filter", "web:get.dns-filter")):
    (st, hd, sc, body), _, _ = login(roles=tuple(roles))
    st, _, _, body = req("GET", path, ALICE, cookie=cookie_val(sc, "__Host-webui"))
    if path == "/dns-filter":           # without dns:filter only the query log section is left, and it says why
        # covers: web:get.dns-filter -
        check("refused: the DNS filter tab without dns:filter: no list, rule or group form, the permission named",
              st == 200 and "dns:querylog" in body and 'action="/dns-filter/' not in body, (st, body[:300]))
        continue
    # covers: web:get.kea web:get.freeradius web:get.openbao -
    check(f"refused: the {path} page without {perm} ({ident}): 403, the permission named",
          st == 403 and perm in body, (st, body[:300]))
st, _, _, body = req("GET", "/dns-filter", ALICE, cookie=adm)
# covers: web:get.dns-filter agent:get.dns-filter +
check("DNS filter tab: the filter off on this host, how to turn it on (dns_filter in vars.yaml)",
      st == 200 and "The DNS filter is off" in body and "dns_filter: bind" in body, (st, body[:300]))

# ---- the agent's read routes: what each returns, and each refused without its permission
out = agent_call("GET", "/v1/images", "alice", ADMIN_ROLES)
# covers: agent:get.images +
check("admin token: GET /v1/images answers with the image rows (none: no service is installed on this test host)",
      " 200 " in out and out.split("\n", 1)[1].strip().startswith("["), out)
for path, want, ident in (("/v1/radius/guides", '"windows"', "agent:get.radius.guides"),
                          ("/v1/vault", '"reachable"', "agent:get.vault"),
                          ("/v1/vault/devices", '"disks"', "agent:get.vault.devices"),
                          ("/v1/vault/slots", '"pi-core"', "agent:get.vault.slots")):
    out = agent_call("GET", path, "alice", ADMIN_ROLES)
    # covers: agent:get.radius.guides agent:get.vault agent:get.vault.devices agent:get.vault.slots +
    check(f"admin token: GET {path} answers ({ident})", " 200 " in out and want in out, out)
for path, roles, perm, ident in (("/v1/dhcp", PKI_OPS, "dhcp:read", "agent:get.dhcp"),
                                 ("/v1/dns-filter", AUDITOR_ROLES, "dns:filter", "agent:get.dns-filter"),
                                 ("/v1/images", DNS_ONLY, "status:read", "agent:get.images"),
                                 ("/v1/radius", netops, "radius:read", "agent:get.radius"),
                                 ("/v1/radius/guides", netops, "radius:read", "agent:get.radius.guides"),
                                 ("/v1/vault", PKI_OPS, "vault:status", "agent:get.vault"),
                                 ("/v1/vault/devices", PKI_OPS, "vault:status", "agent:get.vault.devices"),
                                 ("/v1/vault/slots", PKI_OPS, "vault:status", "agent:get.vault.slots")):
    out = agent_call("GET", path, "carol", roles)
    # covers: agent:get.dhcp agent:get.dns-filter agent:get.images agent:get.radius agent:get.radius.guides -
    # covers: agent:get.vault agent:get.vault.devices agent:get.vault.slots -
    check(f"refused: GET {path} without {perm} ({ident}): 403, the permission named",
          " 403 " in out and f"you need the permission {perm}" in out, out)

# ---- the agent's change routes: each refused without its permission, nothing changed
vt, st_before = vars_now(), secrets_now()
for path, roles, perm in (("/v1/dhcp/on", AUDITOR_ROLES, "dhcp:write"), ("/v1/dhcp/off", AUDITOR_ROLES, "dhcp:write"),
                          ("/v1/dhcp/reservations", AUDITOR_ROLES, "dhcp:write"),
                          ("/v1/dhcp/reservations/02:00:00:00:00:01/delete", AUDITOR_ROLES, "dhcp:write"),
                          ("/v1/dhcp/subnets", AUDITOR_ROLES, "dhcp:write"),
                          ("/v1/dhcp/subnets/update", AUDITOR_ROLES, "dhcp:write"),
                          ("/v1/dhcp/subnets/delete", AUDITOR_ROLES, "dhcp:write"),
                          ("/v1/dhcp/options", AUDITOR_ROLES, "dhcp:write"),
                          ("/v1/dhcp/options/delete", AUDITOR_ROLES, "dhcp:write"),
                          ("/v1/dhcp/classes", AUDITOR_ROLES, "dhcp:write"),
                          ("/v1/dhcp/classes/pxe/delete", AUDITOR_ROLES, "dhcp:write"),
                          ("/v1/dns-filter/lists", AUDITOR_ROLES, "dns:filter"),
                          ("/v1/dns-filter/lists/delete", AUDITOR_ROLES, "dns:filter"),
                          ("/v1/dns-filter/rules", AUDITOR_ROLES, "dns:filter"),
                          ("/v1/dns-filter/rules/delete", AUDITOR_ROLES, "dns:filter"),
                          ("/v1/dns-filter/upstreams", AUDITOR_ROLES, "dns:filter"),
                          ("/v1/dns-filter/groups/delete", AUDITOR_ROLES, "dns:filter"),
                          ("/v1/dns-filter/safe-search", AUDITOR_ROLES, "dns:filter"),
                          ("/v1/dns-filter/fetch", AUDITOR_ROLES, "dns:filter"),
                          ("/v1/dns-filter/querylog", netops, "dns:querylog"),
                          ("/v1/radius/clients/switch1/rotate", AUDITOR_ROLES, "radius:admin"),
                          ("/v1/radius/clients/switch1/delete", AUDITOR_ROLES, "radius:admin"),
                          ("/v1/radius/people/lan-users/delete", AUDITOR_ROLES, "radius:admin"),
                          ("/v1/vault/slots/s1/test", AUDITOR_ROLES, "vault:unlock"),
                          ("/v1/vault/slots/s1/remove", AUDITOR_ROLES, "vault:unlock")):
    out = agent_call("POST", path, "carol", roles, {"name": "x", "group": "", "subnet": "10.9.0.0/24"})
    # covers: agent:post.dhcp.reservations agent:post.dhcp.reservations.*.delete agent:post.dhcp.subnets -
    # covers: agent:post.dhcp.subnets.update agent:post.dhcp.subnets.delete agent:post.dhcp.options -
    # covers: agent:post.dhcp.options.delete agent:post.dhcp.classes agent:post.dhcp.classes.*.delete -
    # covers: agent:post.dns-filter.lists.delete agent:post.dns-filter.rules agent:post.dns-filter.rules.delete -
    # covers: agent:post.dns-filter.upstreams agent:post.dns-filter.groups.delete agent:post.dns-filter.safe-search -
    # covers: agent:post.dns-filter.fetch agent:post.dns-filter.querylog agent:post.radius.clients.*.rotate -
    # covers: agent:post.radius.clients.*.delete agent:post.radius.people.*.delete agent:post.vault.slots.*.test -
    # covers: agent:post.vault.slots.*.remove -
    check(f"refused: POST {path} without {perm}: 403, the permission named, nothing changed",
          " 403 " in out and f"you need the permission {perm}" in out and vars_now() == vt
          and secrets_now() == st_before, out)

# ---- the Kea tab (manual 1.10.2.5): DHCP stays off on this host (settings kept from an earlier turn-on: an interface
# and a first subnet); its settings are edited all the same
open(VARS, "a").write("dhcp:\n  interfaces: [eth0]\n  subnets:\n  - {subnet: 10.29.0.0/24, pools: [10.29.0.100 - 10.29.0.150]}\n")
st, loc, _ = web_post("/kea/subnets", {"network": "10.30.0.0/24", "name": "lab", "vlan": "30", "router": "10.30.0.1",
                                       "pools": "10.30.0.100 - 10.30.0.150", "notes": "the lab bench"}, adm, acsrf)
subs = {s["subnet"]: s for s in ((vars_key("dhcp") or {}).get("subnets") or [])}
lab = subs.get("10.30.0.0/24", {})
# covers: web:post.kea.subnets agent:post.dhcp.subnets +
check("Kea tab: add a subnet -> saved with its name, VLAN, router, pool, notes and an id, said so",
      SAFE and st == 303 and "Subnet 10.30.0.0/24 (lab) added." in loc and lab.get("name") == "lab"
      and lab.get("vlan") == 30 and lab.get("pools") == ["10.30.0.100 - 10.30.0.150"] and lab.get("id"), (loc, subs))
vt = vars_now()
for form, why in (({"network": "10.31.0.0/24", "name": "lab"}, "unique"),):
    st, loc, _ = web_post("/kea/subnets", form, adm, acsrf)
    # covers: web:post.kea.subnets agent:post.dhcp.subnets -
    check(f"Kea tab: a subnet refused ({why}): said why, nothing saved",
          st == 303 and "err=" in loc and why in loc and vars_now() == vt, loc)
st, loc, _ = web_post("/kea/subnets/update", {"subnet": "lab", "name": "lab", "vlan": "30", "router": "10.30.0.1",
                                              "notes": "moved to bench 2",
                                              "add_pools": "10.30.0.200 - 10.30.0.210"}, adm, acsrf)
lab = {s["subnet"]: s for s in vars_key("dhcp")["subnets"]}.get("10.30.0.0/24", {})
# covers: web:post.kea.subnets.update agent:post.dhcp.subnets.update +
check("Kea tab: change a subnet -> notes and pools saved, the id kept",
      st == 303 and "Subnet 10.30.0.0/24 saved." in loc and lab.get("notes") == "moved to bench 2"
      and "10.30.0.200 - 10.30.0.210" in lab.get("pools", []), (loc, lab))
vt = vars_now()
st, loc, _ = web_post("/kea/subnets/update", {"subnet": "lab", "name": "lab", "vlan": "30",
                                              "router": "10.30.0.1", "notes": "moved to bench 2",
                                              "remove_pools": "10.30.0.1 - 10.30.0.9"}, adm, acsrf)
# covers: web:post.kea.subnets.update agent:post.dhcp.subnets.update -
check("Kea tab: removing a pool the subnet does not have is refused, named, nothing saved",
      "has no pool 10.30.0.1 - 10.30.0.9" in loc and vars_now() == vt, loc)
st, loc, _ = web_post("/kea/reservations", {"mac": "02:00:00:00:00:44", "ip": "10.30.0.44", "hostname": "scope"},
                      adm, acsrf)
lab = {s["subnet"]: s for s in vars_key("dhcp")["subnets"]}.get("10.30.0.0/24", {})
# covers: web:post.kea.reservations agent:post.dhcp.reservations +
check("Kea tab: reserve an address -> saved in its subnet with the host name",
      "Reserved 10.30.0.44 for 02:00:00:00:00:44." in loc
      and any(r.get("ip") == "10.30.0.44" and r.get("hostname") == "scope" for r in lab.get("reservations", [])),
      (loc, lab))
vt = vars_now()
st, loc, _ = web_post("/kea/reservations", {"mac": "02:00:00:00:00:45", "ip": "10.99.0.5"}, adm, acsrf)
# covers: web:post.kea.reservations agent:post.dhcp.reservations -
check("Kea tab: a reservation outside every subnet is refused, said why, nothing saved",
      "10.99.0.5 is in none of the DHCP subnets" in loc and vars_now() == vt, loc)
st, loc, _ = web_post("/kea/options", {"option": "ntp-servers", "data": "10.30.0.1", "scope": "subnet",
                                       "target": "lab"}, adm, acsrf)
lab = {s["subnet"]: s for s in vars_key("dhcp")["subnets"]}.get("10.30.0.0/24", {})
# covers: web:post.kea.options agent:post.dhcp.options +
check("Kea tab: set an option on a subnet -> saved there",
      "Option ntp-servers set for" in loc and {"name": "ntp-servers", "data": "10.30.0.1"} in lab.get("options", []),
      (loc, lab))
vt = vars_now()
st, loc, _ = web_post("/kea/options", {"option": "ntp-servers", "data": "10.30.0.1", "scope": "subnet",
                                       "target": "nope"}, adm, acsrf)
# covers: web:post.kea.options agent:post.dhcp.options -
check("Kea tab: an option for a subnet that does not exist is refused, named, nothing saved",
      "no DHCP subnet 'nope'" in loc and vars_now() == vt, loc)
st, loc, _ = web_post("/kea/options/delete", {"option": "ntp-servers", "scope": "subnet", "target": "lab"}, adm, acsrf)
lab = {s["subnet"]: s for s in vars_key("dhcp")["subnets"]}.get("10.30.0.0/24", {})
# covers: web:post.kea.options.delete agent:post.dhcp.options.delete +
check("Kea tab: remove the option -> gone from the subnet", "Option ntp-servers removed from" in loc
      and not lab.get("options"), (loc, lab))
vt = vars_now()
st, loc, _ = web_post("/kea/options/delete", {"option": "ntp-servers", "scope": "subnet", "target": "lab"}, adm, acsrf)
# covers: web:post.kea.options.delete agent:post.dhcp.options.delete -
check("Kea tab: removing an option that is not set is refused, said so, nothing saved",
      "option ntp-servers is not set for" in loc and vars_now() == vt, loc)
st, loc, _ = web_post("/kea/classes", {"name": "pxe-uefi", "test": "option[93].hex == 0x0007",
                                       "next_server": "10.30.0.5", "boot_file": "ipxe.efi"}, adm, acsrf)
classes = {c["name"]: c for c in (vars_key("dhcp").get("client_classes") or [])}
# covers: web:post.kea.classes agent:post.dhcp.classes +
check("Kea tab: add a client class -> saved with its test, next server and boot file",
      "Client class pxe-uefi added." in loc and classes.get("pxe-uefi", {}).get("test") == "option[93].hex == 0x0007",
      (loc, classes))
vt = vars_now()
st, loc, _ = web_post("/kea/classes", {"name": "pxe-uefi", "test": "option[93].hex == 0x0009"}, adm, acsrf)
# covers: web:post.kea.classes agent:post.dhcp.classes -
check("Kea tab: a class that exists already is refused, named, nothing saved",
      "client class pxe-uefi exists" in loc and vars_now() == vt, loc)
st, loc, _ = web_post("/kea/classes/pxe-uefi/delete", {}, adm, acsrf)
# covers: web:post.kea.classes.*.delete agent:post.dhcp.classes.*.delete +
check("Kea tab: remove the client class -> gone", "Client class pxe-uefi removed." in loc
      and not vars_key("dhcp").get("client_classes"), loc)
vt = vars_now()
st, loc, _ = web_post("/kea/classes/ghost/delete", {}, adm, acsrf)
# covers: web:post.kea.classes.*.delete agent:post.dhcp.classes.*.delete -
check("Kea tab: removing a class that does not exist is refused, named, nothing saved",
      "no client class 'ghost'" in loc and vars_now() == vt, loc)
st, loc, _ = web_post("/kea/reservations/02:00:00:00:00:44/delete", {}, adm, acsrf)
lab = {s["subnet"]: s for s in vars_key("dhcp")["subnets"]}.get("10.30.0.0/24", {})
# covers: web:post.kea.reservations.*.delete agent:post.dhcp.reservations.*.delete +
check("Kea tab: remove the reservation -> gone", "Reservation for 02:00:00:00:00:44 removed." in loc
      and not lab.get("reservations"), (loc, lab))
vt = vars_now()
st, loc, _ = web_post("/kea/reservations/02:00:00:00:00:99/delete", {}, adm, acsrf)
# covers: web:post.kea.reservations.*.delete agent:post.dhcp.reservations.*.delete -
check("Kea tab: removing a reservation that does not exist is refused, named, nothing saved",
      "no reservation for 02:00:00:00:00:99" in loc and vars_now() == vt, loc)
vt = vars_now()
st, loc, _ = web_post("/kea/subnets/delete", {"subnet": "nope"}, adm, acsrf)
# covers: web:post.kea.subnets.delete agent:post.dhcp.subnets.delete -
check("Kea tab: removing a subnet that does not exist is refused, named, nothing saved",
      "no DHCP subnet 'nope'" in loc and vars_now() == vt, loc)
st, loc, _ = web_post("/kea/subnets/delete", {"subnet": "lab"}, adm, acsrf)
check("Kea tab: removing a subnet while Kea's leases cannot be read is refused without force, saying why",
      "active leases in 10.30.0.0/24 cannot be ruled out" in loc and vars_now() == vt, loc)
st, loc, _ = web_post("/kea/subnets/delete", {"subnet": "lab", "force": "on"}, adm, acsrf)
# covers: web:post.kea.subnets.delete agent:post.dhcp.subnets.delete +
check("Kea tab: remove the subnet with force (Kea is not running here) -> gone", "Subnet 10.30.0.0/24 removed." in loc
      and "10.30.0.0/24" not in vars_now(), loc)
vt = vars_now()
aud, aud_csrf = fresh(AUDITOR_ROLES)
for path in ("/kea/subnets", "/kea/subnets/update", "/kea/subnets/delete", "/kea/options", "/kea/options/delete",
             "/kea/classes", "/kea/classes/x/delete", "/kea/reservations", "/kea/reservations/x/delete"):
    st, _, body = web_post(path, {"network": "10.32.0.0/24", "name": "x", "subnet": "x", "option": "x", "data": "1",
                                  "test": "member('ALL')", "mac": "02:00:00:00:00:01", "ip": "10.32.0.1"}, aud, aud_csrf)
    # covers: web:post.kea.subnets web:post.kea.subnets.update web:post.kea.subnets.delete web:post.kea.options -
    # covers: web:post.kea.options.delete web:post.kea.classes web:post.kea.classes.*.delete web:post.kea.reservations -
    # covers: web:post.kea.reservations.*.delete -
    check(f"auditor: {path} is refused by fabric-agent (403, dhcp:write), nothing saved",
          st == 403 and "dhcp:write" in body and vars_now() == vt, (st, body[:200]))

# ---- the DNS filter tab (manual 1.12.2.14): each change saved; the refusals say why and save nothing
st, loc, _ = web_post("/dns-filter/lists", {"name": "Test list", "url": "https://lists.example.test/hosts.txt"},
                      adm, acsrf)
check("DNS filter: add a list -> saved (fetched by the lists job once applied)",
      "Test list added" in loc and "https://lists.example.test/hosts.txt" in vars_now(), loc)
st, loc, _ = web_post("/dns-filter/lists/delete", {"url": "https://lists.example.test/hosts.txt"}, adm, acsrf)
# covers: web:post.dns-filter.lists.delete agent:post.dns-filter.lists.delete +
check("DNS filter: remove the list -> gone", "Test list removed" in loc
      and "lists.example.test" not in vars_now(), loc)
vt = vars_now()
st, loc, _ = web_post("/dns-filter/lists/delete", {"url": "https://lists.example.test/other.txt"}, adm, acsrf)
# covers: web:post.dns-filter.lists.delete agent:post.dns-filter.lists.delete -
check("DNS filter: removing a list that is not there is refused, named, nothing saved",
      "has no list with the url https://lists.example.test/other.txt" in loc and vars_now() == vt, loc)
st, loc, _ = web_post("/dns-filter/lists", {"name": "x" * 201, "url": "https://lists.example.test/long.txt"},
                      adm, acsrf)
# covers: web:post.dns-filter.lists -
check("DNS filter: a list name over 200 characters is refused, said why, nothing saved",
      "a list's name is at most 200 characters" in loc and vars_now() == vt, loc)
st, loc, _ = web_post("/dns-filter/rules", {"kind": "block", "name": "ads.example.test"}, adm, acsrf)
check("DNS filter: block a name -> saved", "ads.example.test blocked" in loc and "ads.example.test" in vars_now(), loc)
vt = vars_now()
for form, why in (({"kind": "maybe", "name": "x.example.test"}, "kind: allow or block"),
                  ({"kind": "block", "name": "bad name!"}, "is not a DNS name"),
                  ({"kind": "block", "name": "pi-core.lan.test"}, "inside fabric's own domains")):
    st, loc, _ = web_post("/dns-filter/rules", form, adm, acsrf)
    # covers: web:post.dns-filter.rules agent:post.dns-filter.rules -
    check(f"DNS filter: a rule refused ({why}): said why, nothing saved", why in loc and vars_now() == vt, loc)
st, loc, _ = web_post("/dns-filter/rules/delete", {"kind": "block", "name": "ads.example.test"}, adm, acsrf)
# covers: web:post.dns-filter.rules.delete agent:post.dns-filter.rules.delete +
check("DNS filter: lift the block -> gone", "ads.example.test is no longer blocked" in loc
      and "ads.example.test" not in vars_now(), loc)
vt = vars_now()
st, loc, _ = web_post("/dns-filter/rules/delete", {"kind": "block", "name": "ads.example.test"}, adm, acsrf)
# covers: web:post.dns-filter.rules.delete agent:post.dns-filter.rules.delete -
check("DNS filter: lifting a block that is not there is refused, named, nothing saved",
      "ads.example.test is not blocked by a rule of" in loc and vars_now() == vt, loc)
st, loc, _ = web_post("/dns-filter/upstreams", {"upstreams": "9.9.9.9 dns.quad9.net"}, adm, acsrf)
# covers: web:post.dns-filter.upstreams agent:post.dns-filter.upstreams +
check("DNS filter: set the upstreams -> saved with the name on each certificate",
      "Upstreams saved: 9.9.9.9 (dns.quad9.net)" in loc and "dns.quad9.net" in vars_now(), loc)
vt = vars_now()
st, loc, _ = web_post("/dns-filter/upstreams", {"upstreams": "9.9.9.9"}, adm, acsrf)
# covers: web:post.dns-filter.upstreams agent:post.dns-filter.upstreams -
check("DNS filter: an upstream without its certificate name is refused, said why, nothing saved",
      "an address and the name on its certificate" in loc and vars_now() == vt, loc)
vt = vars_now()
out = agent_call("POST", "/v1/dns-filter/safe-search", "alice", ADMIN_ROLES, {"group": "kids", "on": "on",
                                                                              "youtube": "loose"})
# covers: agent:post.dns-filter.safe-search -
check("refused: a YouTube level that is not one (400, said why), nothing saved",
      " 400 " in out and "youtube: strict or moderate" in out and vars_now() == vt, out)
out = agent_call("POST", "/v1/dns-filter/groups/delete", "alice", ADMIN_ROLES, {"name": "kids"})
# covers: agent:post.dns-filter.groups.delete -
check("refused: removing a client group that does not exist (400, named), nothing saved",
      " 400 " in out and "no client group is called kids" in out and vars_now() == vt, out)
# the console's own forms for groups and safe search (they answered 500 before 0.9: the web's list of changes lacked
# them, 2.3.1.16)
st, loc, _ = web_post("/dns-filter/groups", {"name": "kids", "clients": "192.168.7.64/27"}, adm, acsrf)
# covers: web:post.dns-filter.groups agent:post.dns-filter.groups +
check("DNS filter: a client group made from the console -> saved, its clients named",
      "Group kids added: 192.168.7.64/27" in loc and "kids" in vars_now(), (st, loc))
vt = vars_now()
st, loc, _ = web_post("/dns-filter/groups", {"name": "kids2", "clients": "not-an-address"}, adm, acsrf)
# covers: web:post.dns-filter.groups agent:post.dns-filter.groups -
check("DNS filter: a group whose client is not an address is refused, said why, nothing saved",
      "is not an address or a subnet" in loc and vars_now() == vt, (st, loc))
st, loc, _ = web_post("/dns-filter/safe-search", {"group": "kids", "on": "on", "youtube": "moderate", "back": "groups"},
                      adm, acsrf)
# covers: web:post.dns-filter.safe-search agent:post.dns-filter.safe-search +
check("DNS filter: strict safe search on for the group, from the console -> saved",
      "Strict safe search on, YouTube moderate" in loc and vars_now() != vt, (st, loc))
vt = vars_now()
st, loc, _ = web_post("/dns-filter/safe-search", {"group": "kids", "on": "on", "youtube": "loose"}, adm, acsrf)
# covers: web:post.dns-filter.safe-search -
check("DNS filter: a YouTube level that is not one is refused from the console, said why, nothing saved",
      "youtube: strict or moderate" in loc and vars_now() == vt, (st, loc))
st, loc, _ = web_post("/dns-filter/groups/delete", {"name": "kids"}, adm, acsrf)
# covers: web:post.dns-filter.groups.delete agent:post.dns-filter.groups.delete +
check("DNS filter: the group removed from the console -> gone, its clients answered as everyone",
      "Group kids removed" in loc and "kids" not in vars_now(), (st, loc))
vt = vars_now()
st, loc, _ = web_post("/dns-filter/groups/delete", {"name": "kids"}, adm, acsrf)
# covers: web:post.dns-filter.groups.delete -
check("DNS filter: removing a group that is not there, from the console, is refused, named, nothing saved",
      "no client group is called kids" in loc and vars_now() == vt, (st, loc))
st, loc, _ = web_post("/dns-filter/fetch", {}, adm, acsrf)
# covers: web:post.dns-filter.fetch agent:post.dns-filter.fetch -
check("DNS filter: Fetch now when the lists job cannot start (it never can here) is refused, saying so",
      "the lists job could not start" in loc and vars_now() == vt, loc)
out = agent_call("POST", "/v1/dns-filter/querylog", "alice", ADMIN_ROLES, {"name": "bad name!"})
# covers: agent:post.dns-filter.querylog -
check("refused: a query-log search for something that is not a DNS name (400, said why)",
      " 400 " in out and "is not a DNS name" in out, out)
aud, aud_csrf = fresh(AUDITOR_ROLES)
for path in ("/dns-filter/lists", "/dns-filter/lists/delete", "/dns-filter/rules", "/dns-filter/rules/delete",
             "/dns-filter/upstreams", "/dns-filter/fetch"):
    st, _, body = web_post(path, {"name": "x.example.test", "url": "https://x.example.test/l", "kind": "block",
                                  "upstreams": "none", "clients": "192.168.7.81"}, aud, aud_csrf)
    # covers: web:post.dns-filter.lists web:post.dns-filter.lists.delete web:post.dns-filter.rules -
    # covers: web:post.dns-filter.rules.delete web:post.dns-filter.upstreams web:post.dns-filter.fetch -
    check(f"auditor: {path} is refused by fabric-agent (403, dns:filter), nothing saved",
          st == 403 and "dns:filter" in body and vars_now() == vt, (st, body[:200]))

# ---- the FreeRADIUS tab (manual 1.11): refused while 802.1X is off; with it on, each change saved
vt, st_before = vars_now(), secrets_now()
for path, form in (("/freeradius/clients", {"name": "switch1", "address": "192.168.7.20"}),
                   ("/freeradius/people", {"group": "lan-users", "vlan": "20"})):
    st, loc, _ = web_post(path, form, adm, acsrf)
    # covers: web:post.freeradius.clients web:post.freeradius.people -
    check(f"802.1X off: {path} is refused, saying 802.1X is off, nothing saved",
          st == 303 and "802.1X is off (install_freeradius: false)" in loc and vars_now() == vt
          and secrets_now() == st_before, loc)
open(VARS, "a").write("install_freeradius: true\n")
st, _, body = web_post("/freeradius/clients", {"name": "switch1", "address": "192.168.7.20",
                                               "message_authenticator": "1"}, adm, acsrf)
secret1 = body.split('<pre class="secret">')[1].split("<")[0] if '<pre class="secret">' in body else ""
# covers: web:post.freeradius.clients agent:post.radius.clients +
check("802.1X on: add a RADIUS client -> its shared secret shown once, kept in the secrets, never in vars.yaml",
      st == 200 and secret1 and "switch1" in vars_now() and secret1 not in vars_now() and secret1 in secrets_now(),
      (st, body[:300]))
vt, st_before = vars_now(), secrets_now()
st, loc, _ = web_post("/freeradius/clients", {"name": "switch2", "address": "999.1.1.1"}, adm, acsrf)
# covers: web:post.freeradius.clients -
check("802.1X: a client whose address is not one is refused, said why, nothing saved",
      st == 303 and "switch2: address must be an IP address" in loc and vars_now() == vt and secrets_now() == st_before, loc)
st, _, body = web_post("/freeradius/clients/switch1/rotate", {}, adm, acsrf)
secret2 = body.split('<pre class="secret">')[1].split("<")[0] if '<pre class="secret">' in body else ""
# covers: web:post.freeradius.clients.*.rotate agent:post.radius.clients.*.rotate +
check("802.1X: a new shared secret for the client -> shown once, the old one replaced in the secrets",
      st == 200 and secret2 and secret2 != secret1 and secret2 in secrets_now() and secret1 not in secrets_now(),
      (st, body[:300]))
vt, st_before = vars_now(), secrets_now()
for path in ("/freeradius/clients/ghost/rotate", "/freeradius/clients/ghost/delete"):
    st, loc, _ = web_post(path, {}, adm, acsrf)
    # covers: web:post.freeradius.clients.*.rotate web:post.freeradius.clients.*.delete -
    # covers: agent:post.radius.clients.*.rotate agent:post.radius.clients.*.delete -
    check(f"802.1X: {path} for a client that does not exist is refused, named, nothing changed",
          st == 303 and "no RADIUS client ghost" in loc and vars_now() == vt and secrets_now() == st_before, loc)
st, loc, _ = web_post("/freeradius/people", {"group": "lan-users", "vlan": "20"}, adm, acsrf)
people = {p["group"]: p for p in (vars_key("radius_people") or [])}
# covers: web:post.freeradius.people agent:post.radius.people +
check("802.1X: members of a group may join by password, on their VLAN -> saved",
      "Members of lan-users may join by password on VLAN 20." in loc and str(people.get("lan-users", {}).get("vlan"))
      == "20", (loc, people))
vt = vars_now()
st, loc, _ = web_post("/freeradius/people", {"group": "lan-admins", "vlan": "5000"}, adm, acsrf)
# covers: web:post.freeradius.people -
check("802.1X: a VLAN outside 1-4094 is refused, said why, nothing saved",
      "lan-admins: VLAN must be 1-4094" in loc and vars_now() == vt, loc)
st, loc, _ = web_post("/freeradius/people/lan-users/delete", {}, adm, acsrf)
# covers: web:post.freeradius.people.*.delete agent:post.radius.people.*.delete +
check("802.1X: unmap the group -> its members may no longer join by password",
      "Members of lan-users may no longer join by password." in loc and not vars_key("radius_people"), loc)
vt = vars_now()
st, loc, _ = web_post("/freeradius/people/lan-users/delete", {}, adm, acsrf)
# covers: web:post.freeradius.people.*.delete agent:post.radius.people.*.delete -
check("802.1X: unmapping a group that is not mapped is refused, named, nothing saved",
      "group lan-users is not mapped for 802.1X" in loc and vars_now() == vt, loc)
st, loc, _ = web_post("/freeradius/clients/switch1/delete", {}, adm, acsrf)
# covers: web:post.freeradius.clients.*.delete agent:post.radius.clients.*.delete +
check("802.1X: remove the client -> gone from vars.yaml and its secret from the secrets",
      "RADIUS client switch1 removed." in loc and "switch1" not in vars_now() and secret2 not in secrets_now(), loc)
vt, st_before = vars_now(), secrets_now()
aud, aud_csrf = fresh(AUDITOR_ROLES)
for path in ("/freeradius/clients", "/freeradius/clients/switch1/rotate", "/freeradius/clients/switch1/delete",
             "/freeradius/people", "/freeradius/people/lan-users/delete"):
    st, _, body = web_post(path, {"name": "evil", "address": "192.168.7.66", "group": "lan-users"}, aud, aud_csrf)
    # covers: web:post.freeradius.clients web:post.freeradius.clients.*.rotate web:post.freeradius.clients.*.delete -
    # covers: web:post.freeradius.people web:post.freeradius.people.*.delete -
    check(f"auditor: {path} is refused by fabric-agent (403, radius:admin), nothing changed",
          st == 403 and "radius:admin" in body and vars_now() == vt and secrets_now() == st_before, (st, body[:200]))
text = vars_now().replace("install_freeradius: true\n", "")
open(VARS, "w").write(text)

# ---- the vault's unlock methods: this host has no vault key; a method that does not exist is refused by name
adm, acsrf = fresh()
for action in ("test", "remove"):
    st, loc, _ = web_post(f"/openbao/slots/ghost/{action}", {"confirm": "pi-core"}, adm, acsrf)
    # covers: web:post.openbao.slots.*.test web:post.openbao.slots.*.remove -
    # covers: agent:post.vault.slots.*.test agent:post.vault.slots.*.remove -
    check(f"vault: {action} an unlock method that does not exist -> refused, said why",
          st == 303 and "no unlock method 'ghost'" in loc, loc)

# ---- an image update or rollback from the Overview: refused without images:update; a service fabric does not run
# is refused by the job, saying so
aud, aud_csrf = fresh(AUDITOR_ROLES)
for action in ("update", "rollback"):
    st, _, body = web_post(f"/overview/images/nginx/{action}", {}, aud, aud_csrf)
    # covers: web:post.overview.images.*.update web:post.overview.images.*.rollback -
    check(f"auditor: an image {action} from the Overview is refused by fabric-agent (403, images:update)",
          st == 403 and "images:update" in body, (st, body[:200]))
# ---------------------------------------------- without a client certificate (webui_client_cert off, manual 2.3.6.2.6.3)
json.dump({**cfg, "client_cert": False}, open(f"{W}/config/webui.json", "w"))
os.remove(f"{W}/run/web.sock")
sh("docker restart cwebui >/dev/null")
for _ in range(100):
    if os.path.exists(f"{W}/run/web.sock"):
        break
    time.sleep(0.2)
st, hd, *_ = req("GET", "/")
check("certificate off: no certificate, no session -> redirect to /login (not 403)",
      st == 303 and hd.get("Location") == "/login", (st, hd))
(st, hd, sc, _), _, _ = login(cert={}, user="dave")
sess = cookie_val(sc, "__Host-webui")
check("certificate off: a Keycloak sign-in alone makes the session (no CN to match)", st == 200 and sess, (st, sc))
st, _, _, body = req("GET", "/", cookie=sess)
check("certificate off: the session cookie opens the console", st == 200 and "dave" in body, st)
st, hd, *_ = req("GET", "/")
check("certificate off: still no way in without a session", st == 303, st)
(st, *_), _, _ = login(cert={}, user="erin", roles=())
check("certificate off: a person without a fabric role is still refused", st == 403, st)
audit_tail = open(f"{W}/fabric/archive/audit.log").read() if os.path.exists(f"{W}/fabric/archive/audit.log") else ""
check("certificate off: the sign-in is audited as made without a certificate",
      "dave" in audit_tail and "no client certificate" in audit_tail, audit_tail[-300:])
# the Security page (manual 2.3.6.2.6.4): admins only; turning the certificate on needs this browser's own certificate
csrf = req("GET", "/", cookie=sess)[3].split('name="csrf" value="')[1].split('"')[0]
st, _, _, page = req("GET", "/security", cookie=sess)
# covers: web:get.security +
check("Security page: the admin sees each layer and its raises", st == 200 and "admin-2fa" in page
      and 'action="/security/raise"' in page, (st, page[:300]))
st, hd, *_ = req("POST", "/security/raise", {"Origin": "https://mgr.test"},
                 {"csrf": csrf, "layer": "client-cert", "value": "on"}, cookie=sess)
# covers: web:post.security.raise -
check("refused: turning the client certificate on while this browser presents none (never locks the admin out)",
      st == 303 and "did+not+present" in hd.get("Location", "").replace("%20", "+"), (st, hd.get("Location")))
out = agent_call("GET", "/v1/security", "carol", AUDITOR_ROLES)
# covers: agent:get.security -
check("auditor token: may not read or raise sign-in security (403, security:raise)",
      " 403 " in out and "security:raise" in out, out)
out = agent_call("GET", "/v1/security", "alice", ADMIN_ROLES)
check("admin token: may read the layers", " 200 " in out, out)
out = agent_call("POST", "/v1/security/raise", "alice", ADMIN_ROLES, {"layer": "admin-2fa", "value": "sms"})
# covers: agent:post.security.raise -
check("refused through the agent: a value that is no level (400)", " 400 " in out, out)
subprocess.run("docker rm -f cwebui >/dev/null; docker network rm cwnet >/dev/null; docker rmi fabric/webui:test >/dev/null",
               shell=True)
agent.terminate()
kc.shutdown()
failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
if failed:
    print(agent.stdout.read()[-3000:])
    print(subprocess.run(['docker', 'logs', 'cwebui'], capture_output=True, text=True).stdout[-2000:])
sys.exit(1 if failed else 0)
