"""The `keycloak` suite (manual 1.6.2, 1.6.3.11): keycloak_bootstrap against a real Keycloak and a real Samba AD
domain controller, twice (idempotent); the admin API's view of what it made; and a real browser sign-in by the first
admin, created by fabric with a one-time password: Keycloak makes them choose a new one (AD's pwdLastSet), which
lands in AD, then enrol TOTP. Refusals: a disabled person, a person outside the site's groups (2.1.6.14), an unregistered
redirect URI.
    sudo python3 tests/keycloak/run.py
"""
import hashlib
import hmac
import os
import re
import shutil
import struct
import subprocess
import sys
import time

import yaml
from cryptography.hazmat.primitives.asymmetric import ec

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path[0:0] = [os.path.join(REPO, "src"), REPO, os.path.join(REPO, "tests", "samba"), HERE]
from start_dc import start_dc  # noqa: E402
from soft_passkey import SoftPasskey  # noqa: E402
from fabriclib.directory.ensure_admin import ensure_admin  # noqa: E402
from fabriclib.directory.run_op import run_op  # noqa: E402
from fabriclib.keycloak.admin_client import Admin  # noqa: E402
from fabriclib.keycloak.install_sso_keytab import install_sso_keytab  # noqa: E402
from fabriclib.secrets.random_password import random_password  # noqa: E402
from webui.tlsclient import TLSClient  # noqa: E402

W = os.path.join(os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests"), "keycloak")
NET, SUBNET, DC_IP, KC_IP = "kctest", "10.254.9.0/24", "10.254.9.10", "10.254.9.60"
DC, KC = "kc-dc", "kc-keycloak"
HOST, REALM = "sso.lan.j-j.family", "lan.j-j.family"
PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


def sh(cmd, ok=True, **kw):
    res = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if ok and res.returncode:
        raise RuntimeError(f"{cmd[:4]}: {res.stderr.strip()[-400:]}")
    return res


def cleanup():
    sh(["docker", "rm", "-f", DC, KC], ok=False)
    sh(["docker", "network", "rm", NET], ok=False)


def ntlm_signs_in(user, password):
    """Whether a password signs in to AD directly (NTLM over LDAP at the DC), Keycloak not involved."""
    auth = os.path.join(W, f"{user}.auth")
    with open(auth, "w") as f:
        f.write(f"username={user}\npassword={password}\ndomain=AD\n")
    os.chmod(auth, 0o600)
    res = sh(["docker", "run", "--rm", "--network", NET, "-v", f"{auth}:/auth:ro", "--entrypoint", "ldbsearch",
              "fabric/samba:test", "-H", f"ldap://{DC_IP}", "-A", "/auth", "--use-kerberos=off", "-b",
              dc["v"]["ad_base_dn"], "-s", "base", "dn"], ok=False)
    return res.returncode == 0


class Browser:
    """Just enough of a browser for Keycloak's forms, through curl: a cookie jar, redirects not followed, the test CA
    trusted, and Keycloak reached at its address under its name (--connect-to: nothing on this machine changes)."""

    def __init__(self, ca):
        self.ca = ca
        self.jar = os.path.join(W, f"jar-{id(self)}")

    def go(self, url, form=None):
        cmd = ["curl", "-s", "-i", "-c", self.jar, "-b", self.jar, "--cacert", self.ca,
               "--connect-to", f"{HOST}:443:{KC_IP}:8443", "--connect-to", f"{HOST}:8443:{KC_IP}:8443", url]
        for key, value in (form or {}).items():
            cmd += ["--data-urlencode", f"{key}@-" if key.startswith("password") else f"{key}={value}"]
        # a password field goes on stdin, never on the command line (one per request at most)
        secret = next((val for key, val in (form or {}).items() if key.startswith("password")), None)
        if form and sum(1 for key in form if key.startswith("password")) > 1:
            cmd = cmd[:cmd.index("--data-urlencode")]
            for key, value in form.items():
                cmd += ["--data-urlencode", f"{key}@{self._file(key, value)}"]
            secret = None
        out = subprocess.run(cmd, input=secret, capture_output=True, text=True).stdout
        # text mode: curl's CRLF arrives as LF
        head, _, body = out.partition("\n\n")
        while head.startswith("HTTP/") and " 100 " in head.split("\n", 1)[0]:
            head, _, body = body.partition("\n\n")
        lines = head.split("\n")
        status = int(lines[0].split()[1]) if lines and lines[0].startswith("HTTP/") else 0
        headers = {k.strip().lower(): val.strip() for k, _, val in (ln.partition(":") for ln in lines[1:])}
        return status, headers, body

    def _file(self, key, value):
        path = os.path.join(W, f"form-{key}")
        with open(path, "w") as f:
            f.write(value)
        os.chmod(path, 0o600)
        return path


def action(page):
    m = re.search(r'action="([^"]+)"', page, re.I)
    return m.group(1).replace("&amp;", "&") if m else ""


def start(browser, url):
    """Open a sign-in as a browser without a Kerberos ticket: Keycloak answers 401 Negotiate with a page that
    continues to the next method (a browser submits it at once); returns the page after it."""
    st, hdr, page = browser.go(url)
    if st == 401 and 'name="continue"' in page:
        st, hdr, page = browser.go(action(page), {"continue": "CONTINUE"})
    return page


def totp_code(secret):
    """The current TOTP code for Keycloak's raw secret (RFC 6238, SHA-1, 6 digits, 30 s)."""
    mac = hmac.new(secret.encode(), struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    return f"{(struct.unpack('>I', mac[mac[-1] & 0x0F:(mac[-1] & 0x0F) + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


cleanup()
shutil.rmtree(W, ignore_errors=True)
# the DC first: Keycloak's account and the first admin come from it
dc = start_dc(os.path.join(W, "dc"), DC, NET, SUBNET, DC_IP, extra_vars={
    "ip_keycloak": KC_IP, "hostname_keycloak": HOST, "webui_realm": REALM, "install_webui": True, "install_keycloak": True,
    "hostname_mgr": "mgr.lan.j-j.family", "webui_hostname": "mgr.lan.j-j.family",
    "signin_kerberos": True})     # off by default since 0.6.4 (2.1.6.32): this suite proves it on
v, secrets, root_ca = dc["v"], dc["secrets"], dc["root_ca"]
check("a real DC from fabric's image, converged (Keycloak's service account made)", True)
state, otp = ensure_admin(v, secrets, "jim", "jim@lan.j-j.family", container=DC)
check("the first admin jim is created in the directory with a one-time password", state == "created" and otp)

# Keycloak, its certificate from the test root, the root as its truststore (fabric's LDAPS to the DC is verified)
kc_dir = os.path.join(W, "kc")
os.makedirs(kc_dir)
sh(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{kc_dir}/privkey.pem", "-out", f"{kc_dir}/kc.csr",
    "-subj", f"/CN={HOST}"])
with open(f"{kc_dir}/kc.ext", "w") as f:
    f.write(f"subjectAltName=DNS:{HOST}\nextendedKeyUsage=serverAuth\n")
sh(["openssl", "x509", "-req", "-in", f"{kc_dir}/kc.csr", "-CA", root_ca, "-CAkey", dc["root_key"], "-CAcreateserial",
    "-out", f"{kc_dir}/fullchain.pem", "-days", "2", "-extfile", f"{kc_dir}/kc.ext"])
sh(["cp", root_ca, f"{kc_dir}/root_ca.crt"])
for name in os.listdir(kc_dir):
    os.chmod(os.path.join(kc_dir, name), 0o644)
# Kerberos sign-in (manual 2.3.6.2.6.2): the DC's converge made fabric-sso-<site> and exported its keytab; fabric
# hands it to Keycloak with a krb5.conf (this test's Keycloak runs as the image's own user, 1000, so it owns them here)
krb_dir = os.path.join(v["deploy_base_dir"], "keycloak", "kerberos")
spns = sh(["docker", "exec", DC, "samba-tool", "spn", "list", "fabric-sso-lan", "-s", "/data/etc/smb.conf"],
          ok=False).stdout
enc = sh(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb", "(sAMAccountName=fabric-sso-lan)",
          "msDS-SupportedEncryptionTypes"], ok=False).stdout
check("the DC made the Kerberos sign-in account: both SPNs, AES only, its keytab handed to Keycloak",
      install_sso_keytab(v) and "HTTP/sso.lan.j-j.family" in spns and "HTTP/dc1.lan.j-j.family" in spns
      and "msDS-SupportedEncryptionTypes: 24" in enc and os.path.getsize(os.path.join(krb_dir, "sso.keytab")) > 0,
      (spns, enc))
check("handing the keytab over again changes nothing", not install_sso_keytab(v))
READ_POL = """
import os, sys
sys.path.insert(0, "/fabric")
from samba.dcerpc import preg
from samba.ndr import ndr_unpack
from open_samdb import open_samdb
import ldb
samdb, lp = open_samdb("/data/etc/smb.conf")
g = samdb.search(base="CN=Policies,CN=System," + str(samdb.domain_dn()), scope=ldb.SCOPE_ONELEVEL,
                 expression="(displayName=fabric: lan Windows baseline)", attrs=["cn"])[0]
path = os.path.join(lp.get("path", "sysvol"), lp.get("realm").lower(), "Policies", str(g["cn"]), "Machine",
                    "Registry.pol")
for e in ndr_unpack(preg.file, open(path, "rb").read()).entries:
    print(e.keyname, "|", e.valuename, "|", e.data)
"""
pol = sh(["docker", "exec", "-i", DC, "python3", "-"], ok=False, input=READ_POL).stdout
check("the site's Windows baseline GPO lets Edge, Chrome and Firefox use Kerberos for sso.<domain> (2.1.6.28)",
      f"Software\\Policies\\Microsoft\\Edge | AuthServerAllowlist | {HOST}" in pol
      and f"Software\\Policies\\Google\\Chrome | AuthServerAllowlist | {HOST}" in pol
      and f"Software\\Policies\\Mozilla\\Firefox\\Authentication\\SPNEGO | 1 | {HOST}" in pol, pol)
sh(["chown", "-R", "1000", krb_dir])
shutil.copytree(krb_dir, os.path.join(W, "opt", "keycloak", "kerberos"))
image = sh([sys.executable, os.path.join(REPO, "tests", "image_ref.py"), "keycloak"]).stdout.strip()
sh(["docker", "run", "-d", "--name", KC, "--network", NET, "--ip", KC_IP,
    "-v", f"{krb_dir}:/etc/keycloak/kerberos:ro",
    "-e", "JAVA_OPTS_APPEND=-Djava.security.krb5.conf=/etc/keycloak/kerberos/krb5.conf",
    "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin", "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=KcAdmin1",
    "-e", f"KC_HOSTNAME={HOST}", "-e", "KC_PROXY_HEADERS=xforwarded", "-e", "KC_HEALTH_ENABLED=true",
    "-e", "KC_HTTPS_CERTIFICATE_FILE=/certs/fullchain.pem", "-e", "KC_HTTPS_CERTIFICATE_KEY_FILE=/certs/privkey.pem",
    "-e", "KC_TRUSTSTORE_PATHS=/certs/root_ca.crt", "-v", f"{kc_dir}:/certs:ro", image, "start-dev"])
for _ in range(90):
    if sh(["curl", "-sf", "--cacert", root_ca, "--resolve", f"{HOST}:8443:{KC_IP}",
           f"https://{HOST}:8443/realms/master"], ok=False).returncode == 0:
        break
    time.sleep(3)
cfg = os.path.join(W, "opt", "fabric", "config")
os.makedirs(cfg)
os.makedirs(os.path.join(W, "opt", "stepca", "data", "certs"))
sh(["cp", root_ca, os.path.join(W, "opt", "stepca", "data", "certs", "root_ca.crt")])
with open(os.path.join(cfg, "vars.yaml"), "w") as f:
    yaml.safe_dump({**v, "deploy_base_dir": os.path.join(W, "opt")}, f)
with open(os.path.join(cfg, "fabric-secrets.yml"), "w") as f:
    yaml.safe_dump({"keycloak_admin_user": "admin", "keycloak_admin_password": "KcAdmin1",
                    "ad_keycloak_password": secrets["ad_keycloak_password"], "webui_oidc_secret": "OidcSecret1"}, f)
boot = [sys.executable, os.path.join(REPO, "src", "ux", "cli", "keycloak_bootstrap.py"),
        "--vars", os.path.join(cfg, "vars.yaml"), "--secrets", os.path.join(cfg, "fabric-secrets.yml")]
env = dict(os.environ, PYTHONPATH=f"{REPO}/src:{REPO}")
run1 = sh(boot, ok=False, env=env)
check("bootstrap run 1 succeeds", "Keycloak configuration complete" in run1.stdout, (run1.stdout + run1.stderr)[-600:])
run2 = sh(boot, ok=False, env=env)
check("bootstrap run 2 converges (no creates)", "complete" in run2.stdout and "created" not in run2.stdout,
      run2.stdout[-400:])

# the admin API's view
kc = Admin(TLSClient(KC_IP, 8443, HOST, root_ca), "admin", "KcAdmin1")
R = f"/{REALM}"
comps = kc.call("GET", f"{R}/components?type=org.keycloak.storage.UserStorageProvider")[1]
ldap = [c for c in comps if c["providerId"] == "ldap"]
check("exactly one LDAP provider: Samba AD, AD mode, LDAPS to the DC's address, verified",
      len(ldap) == 1 and ldap[0]["config"]["vendor"] == ["ad"]
      and ldap[0]["config"]["connectionUrl"] == [f"ldaps://{DC_IP}:636"]
      and ldap[0]["config"]["useTruststoreSpi"] == ["always"], ldap and ldap[0]["config"].get("connectionUrl"))
st, sync = kc.call("POST", f"{R}/user-storage/{ldap[0]['id']}/sync?action=triggerFullSync")
check("a full sync from AD over LDAPS works", st == 200 and not sync.get("failed"), sync)
users = kc.call("GET", f"{R}/users?username=jim&exact=true")[1]
check("jim (in OU=people) is visible in Keycloak", len(users) == 1, users)
fed = ldap[0]["config"] if ldap else {}
check("the federation: users from OU=people, every enabled person admitted (2.1.6.83), bound as this DC's "
      "fabric-keycloak-dc-0001 in OU=service-accounts (2.1.6.82)",
      fed.get("usersDn") == [f"OU=people,{v['ad_base_dn']}"]
      and fed.get("bindDn") == [f"CN=fabric-keycloak-dc-0001,OU=service-accounts,{v['ad_base_dn']}"]
      and "1.2.840.113556.1.4.803:=2" in (fed.get("customUserSearchFilter") or [""])[0], fed)
if users:
    roles = kc.call("GET", f"{R}/users/{users[0]['id']}/role-mappings/realm/composite")[1]
    check("jim gets fabric-console-admin through directory-admins (2.1.6.81)", any(r["name"] == "fabric-console-admin" for r in roles),
          [r["name"] for r in roles])
client = kc.call("GET", f"{R}/clients?clientId=fabric-webui")[1][0]
check("client: confidential, code flow only, exact redirect, PKCE S256, fullScopeAllowed off",
      not client["publicClient"] and client["standardFlowEnabled"] and not client["implicitFlowEnabled"]
      and not client["directAccessGrantsEnabled"] and client["redirectUris"] == ["https://mgr.lan.j-j.family/oidc/callback"]
      and client["attributes"].get("pkce.code.challenge.method") == "S256" and client["fullScopeAllowed"] is False)
flows = {f["alias"]: f["id"] for f in kc.call("GET", f"{R}/authentication/flows")[1]}


def steps(flow):
    """{providerId or sub-flow alias: requirement} of a flow."""
    return {(e.get("displayName") if e.get("authenticationFlow") else e.get("providerId")): e["requirement"]
            for e in kc.call("GET", f"{R}/authentication/flows/{flow}/executions")[1]}


realm_rep = kc.call("GET", R)[1]
signin, admin_flow = steps("fabric-signin"), steps("fabric-admin-signin")
check("sign-in flows (2.1.6.23): fabric-signin is the realm's, fabric-admin-signin the web UI's; 0.6.0's flow is gone",
      realm_rep["browserFlow"] == "fabric-signin" and "fabric-webui-mfa" not in flows
      and client["authenticationFlowBindingOverrides"].get("browser") == flows.get("fabric-admin-signin"),
      (realm_rep["browserFlow"], sorted(flows)))
check("by default: Kerberos or a password, no second factor; the admin flow never takes the session cookie",
      signin.get("auth-spnego") == admin_flow.get("auth-spnego") == "ALTERNATIVE"
      and signin.get("fabric-signin second factor") == admin_flow.get("fabric-admin-signin second factor") == "DISABLED"
      and signin.get("auth-cookie") == "ALTERNATIVE" and "auth-cookie" not in admin_flow, (signin, admin_flow))
check("Keycloak checks Kerberos tickets with the site's keytab; passwords stay with LDAP; passkeys need the device's"
      " unlock", ldap[0]["config"].get("allowKerberosAuthentication") == ["true"]
      and ldap[0]["config"].get("keyTab") == ["/etc/keycloak/kerberos/sso.keytab"]
      and ldap[0]["config"].get("useKerberosForPasswordAuthentication") == ["false"]
      and realm_rep.get("webAuthnPolicyUserVerificationRequirement") == "required"
      and realm_rep.get("webAuthnPolicyRpId") == HOST, ldap[0]["config"].get("keyTab"))

# a real browser sign-in by the first admin, with fabric's one-time password
AUTH = (f"https://{HOST}/realms/{REALM}/protocol/openid-connect/auth?client_id=fabric-webui&response_type=code"
        "&scope=openid&redirect_uri=https%3A%2F%2Fmgr.lan.j-j.family%2Foidc%2Fcallback&state=s&nonce=n"
        "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256")
b = Browser(root_ca)
page = start(b, AUTH)
st, hdr, page = b.go(action(page), {"username": "jim", "password": otp})
if st in (302, 303):
    st, hdr, page = b.go(hdr.get("location"))
if os.environ.get("KEYCLOAK_TEST_DEBUG"):
    print("DEBUG", st, re.findall(r"<title>([^<]*)", page), re.findall(r'name="([a-z-]+)"', page)[:12],
          re.findall(r'class="[^"]*(?:alert|error)[^"]*"[^>]*>\s*([^<]{0,200})', page)[:3])
check("jim signs in with fabric's one-time password", st == 200 and ("totp" in page or "password-new" in page),
      page[:300])
# Keycloak's required actions, in its own order: TOTP enrolment (MFA) and a new password (AD's must-change)
seen, new_pw, location = set(), "Kc-" + random_password(20), ""
for _ in range(4):
    if 'name="totp"' in page:
        fields = dict(re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', page))
        st, hdr, page = b.go(action(page), {**fields, "totp": totp_code(fields.get("totpSecret", "")),
                                            "userLabel": "test"})
        seen.add("totp")
    elif 'name="password-new"' in page:
        st, hdr, page = b.go(action(page), {"password-new": new_pw, "password-confirm": new_pw})
        seen.add("password")
    else:
        break
    location = hdr.get("location") or ""
    if st in (302, 303) and "code=" in location:
        break
    if st in (302, 303):
        st, hdr, page = b.go(location)
check("with a password only (2.1.6.23): Keycloak asks jim for a new password (AD's must-change), then signs him in",
      seen == {"password"} and "mgr.lan.j-j.family/oidc/callback" in location and "code=" in location,
      (seen, location[:120], page[:200]))
check("the new password chosen in Keycloak landed in AD", ntlm_signs_in("jim", new_pw))
check("the one-time password no longer signs in to AD", not ntlm_signs_in("jim", otp))

# refusals
def person(uid):
    """A person made by fabric's own operation (in OU=people and site-<site>); their one-time password."""
    pw = "Tst-" + random_password(20)
    run_op(v, secrets, "create_person", {"uid": uid, "first": uid, "last": "T", "email": f"{uid}@lan.j-j.family",
                                        "password": pw, "gid": 5000, "home_base": "/home", "shell": "/bin/bash"}, DC)
    return pw


bob_pw = person("bob")
sh(["docker", "exec", DC, "samba-tool", "user", "disable", "bob", "-s", "/data/etc/smb.conf"])
b2 = Browser(root_ca)
page = start(b2, AUTH)
_, _, page = b2.go(action(page), {"username": "bob", "password": bob_pw})
check("refused: a person disabled in AD", re.search(r"disabled|Invalid username or password", page, re.I), page[:300])
eve_pw = person("eve")
sh(["docker", "exec", DC, "samba-tool", "group", "removemembers", "site-lan", "eve", "-s",
    "/data/etc/smb.conf"])               # in OU=people, but in no group at all
b3 = Browser(root_ca)
page = start(b3, AUTH)
st, hdr, page = b3.go(action(page), {"username": "eve", "password": eve_pw})
if st in (302, 303):                     # the required action (AD's must-change) is a page of its own
    st, hdr, page = b3.go(hdr.get("location"))
check("every enabled person in OU=people is admitted, in a group or not (2.1.6.83): eve, in none, is asked for a new "
      "password", "Invalid username or password" not in page and "password-new" in page, page[:300])
b5 = Browser(root_ca)
page = start(b5, AUTH)
_, _, page = b5.go(action(page), {"username": "fabric-agent-dc-0001", "password": secrets["ad_agent_password"]})
check("refused: a service account (outside OU=people) never signs in to the console",
      "Invalid username or password" in page, page[:300])
bad = start(Browser(root_ca), AUTH.replace("mgr.lan.j-j.family%2Foidc", "evil.test%2Foidc"))
check("refused: a redirect URI that is not registered", "Invalid parameter: redirect_uri" in bad, bad[:200])

# ---- raising the admin tools' second factor (manual 2.3.6.2.6.1): what the Security page and `fabricctl security` set
def converge_with(**settings):
    """The settings changed in vars.yaml, then fabric's Keycloak configuration run again."""
    path = os.path.join(cfg, "vars.yaml")
    with open(path) as f:
        current = yaml.safe_load(f)
    current.update(settings)
    with open(path, "w") as f:
        yaml.safe_dump(current, f)
    return sh(boot, ok=False, env=env)


def sign_in(browser, url, user, password):
    """A password sign-in through Keycloak's forms; returns (status, location, page) after the password."""
    page = start(browser, url)
    st, hdr, page = browser.go(action(page), {"username": user, "password": password})
    location = hdr.get("location") or ""
    if st in (302, 303) and "code=" not in location:          # a required action (e.g. TOTP enrolment) next
        st, hdr, page = browser.go(location)
    return st, location, page


APP_AUTH = (f"https://{HOST}/realms/{REALM}/protocol/openid-connect/auth?client_id=account-console"
            f"&response_type=code&scope=openid&redirect_uri=https%3A%2F%2F{HOST}%2Frealms%2F{REALM}%2Faccount%2F"
            "&state=s&nonce=n&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256")
run3 = converge_with(signin_admin_second_factor="totp")
check("raising the admin tools' second factor to TOTP converges",
      "complete" in run3.stdout and "fabric-admin-signin: Kerberos on, second factor totp" in run3.stdout
      and steps("fabric-admin-signin").get("fabric-admin-signin totp") == "REQUIRED"
      and steps("fabric-signin").get("fabric-signin second factor") == "DISABLED", run3.stdout[-500:])
b4 = Browser(root_ca)
st, location, page = sign_in(b4, APP_AUTH, "jim", new_pw)
check("every other sign-in still asks only for the password (everyone: none)",
      st in (302, 303) and "code=" in location, (st, location[:120], page[:200]))
st, location, page = sign_in(b4, AUTH, "jim", new_pw)
# covers: setting:signin_admin_second_factor +
check("the admin tools never take that session: the console asks for the password, then for TOTP enrolment",
      st == 200 and 'name="totp"' in page and "code=" not in location, (st, location[:120], page[:200]))
fields = dict(re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', page))
st, hdr, page = b4.go(action(page), {**fields, "totp": totp_code(fields.get("totpSecret", "")), "userLabel": "t"})
check("with TOTP enrolled, jim reaches the console", st in (302, 303) and "code=" in hdr.get("location", ""),
      (st, page[:200]))
b5 = Browser(root_ca)
st, location, page = sign_in(b5, AUTH, "jim", new_pw)
check("refused: the console without the TOTP code (the form asks for it; a wrong code fails)",
      st == 200 and 'name="otp"' in page
      and "Invalid authenticator code" in b5.go(action(page), {"otp": "000000"})[2], page[:200])

# ---- Kerberos sign-in from a domain client (manual 2.3.6.2.6.2): a ticket from the DC, a browser's Negotiate
kerb_pw = person("kerb")
AD_REALM = v["ad_domain"].upper()
# a person made by fabric must change the one-time password first (the KDC refuses it until then); a real person does
# at the first Windows log-on: here the password counts as changed now (pwdLastSet -1)
kerb_dn = sh(["docker", "exec", DC, "sh", "-c", "samba-tool user show kerb -s /data/etc/smb.conf | sed -n 's/^dn: //p'"]
             ).stdout.strip()
sh(["docker", "exec", "-i", DC, "ldbmodify", "-H", "/data/private/sam.ldb"],
   input=f"dn: {kerb_dn}\nchangetype: modify\nreplace: pwdLastSet\npwdLastSet: -1\n")
sh(["docker", "exec", DC, "rm", "-f", "/data/kerb.keytab"])
sh(["docker", "exec", DC, "samba-tool", "domain", "exportkeytab", "/data/kerb.keytab", f"--principal=kerb@{AD_REALM}",
    "-s", "/data/etc/smb.conf"])
cw = os.path.join(W, "krb-client")
os.makedirs(cw)
sh(["docker", "cp", f"{DC}:/data/kerb.keytab", f"{cw}/kerb.keytab"])
sh(["cp", root_ca, f"{cw}/root_ca.crt"])
with open(f"{cw}/krb5.conf", "w") as f:
    f.write(f"[libdefaults]\n  default_realm = {AD_REALM}\n  dns_lookup_kdc = false\n  rdns = false\n"
            f"[realms]\n  {AD_REALM} = {{\n    kdc = {DC_IP}\n  }}\n[domain_realm]\n  .lan.j-j.family = {AD_REALM}\n")
for name in os.listdir(cw):
    os.chmod(os.path.join(cw, name), 0o644)
neg = (f"curl -s -o /dev/null -w '%{{http_code}} %{{redirect_url}}\\n' --negotiate -u : --cacert /w/root_ca.crt "
       f"--connect-to {HOST}:443:{KC_IP}:8443")
client = f"""apt-get -qq update >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get -qq install -y krb5-user curl >/dev/null 2>&1
cp /w/krb5.conf /etc/krb5.conf
kinit -k -t /w/kerb.keytab kerb@{AD_REALM}
echo "APP $({neg} '{APP_AUTH}')"
echo "CONSOLE $(curl -s -L -c /tmp/jar -b /tmp/jar --negotiate -u : --cacert /w/root_ca.crt --connect-to {HOST}:443:{KC_IP}:8443 '{AUTH}' | grep -oE 'name=.t?otp.' | head -1)"
echo "{KC_IP} dc1.lan.j-j.family {HOST}" >> /etc/hosts
sed -i 's/rdns = false/rdns = false\\n  dns_canonicalize_hostname = true/' /etc/krb5.conf
kdestroy; kinit -k -t /w/kerb.keytab kerb@{AD_REALM}
echo "CNAME $({neg} '{APP_AUTH}') $(klist | grep -o 'HTTP/[^@]*' | head -1)"
"""
out = sh(["docker", "run", "--rm", "--network", NET, "-v", f"{cw}:/w:ro", "debian:trixie", "bash", "-c", client],
         ok=False).stdout
lines = {ln.split(" ", 1)[0]: ln.split(" ", 1)[1] if " " in ln else "" for ln in out.splitlines()}
check("Kerberos: a domain person's ticket signs them in to an app, no password asked",
      lines.get("APP", "").startswith("302") and "code=" in lines.get("APP", ""), out[-400:])
check("Kerberos never skips a second factor: the console still asks kerb for TOTP after the ticket",
      "otp" in lines.get("CONSOLE", ""), out[-400:])
check("Kerberos through the name sso.<domain> is a CNAME of (the client asks for HTTP/<host>.<domain>)",
      lines.get("CNAME", "").startswith("302") and "HTTP/dc1.lan.j-j.family" in lines.get("CNAME", ""), out[-400:])
st, _, page = Browser(root_ca).go(APP_AUTH)
check("without a ticket Keycloak asks for one (401 Negotiate), then falls back to the password form",
      st == 401 and 'name="password"' in start(Browser(root_ca), APP_AUTH), (st, page[:200]))
run4 = converge_with(signin_kerberos=False)
st, _, _ = Browser(root_ca).go(APP_AUTH)
# covers: setting:signin_kerberos +
check("signin_kerberos off: no Negotiate, the password form at once",
      "complete" in run4.stdout and st == 200 and steps("fabric-signin").get("auth-spnego") == "DISABLED", st)
converge_with(signin_kerberos=True, signin_admin_second_factor="none")


def required_actions(browser, page, st, hdr, password, passkey=None):
    """Keycloak's required actions after a password, in its own order: a new password (AD's must-change), TOTP
    enrolment, passkey registration. Returns (what was asked, last status, last location, last page)."""
    seen, location = [], hdr.get("location") or ""
    for _ in range(5):
        if st in (302, 303) and "code=" in location:
            break
        if st in (302, 303):
            st, hdr, page = browser.go(location)
        if 'name="password-new"' in page:
            st, hdr, page = browser.go(action(page), {"password-new": password, "password-confirm": password})
            seen.append("password")
        elif 'name="totp"' in page:
            fields = dict(re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', page))
            st, hdr, page = browser.go(action(page), {**fields, "totp": totp_code(fields.get("totpSecret", "")),
                                                      "userLabel": "t"})
            seen.append("totp")
        elif "registerByWebAuthn" in page and passkey:
            st, hdr, page = browser.go(action(page), passkey.register(page))
            seen.append("passkey")
        else:
            break
        location = hdr.get("location") or ""
    return seen, st, location, page


# ---- passkeys (manual 2.3.6.2.6.1): a second factor that must be unlocked on the device
run5 = converge_with(signin_everyone_second_factor="passkey")
check("raising every sign-in to passkeys converges; the admin tools follow (never less than every sign-in)",
      "complete" in run5.stdout and steps("fabric-signin").get("fabric-signin passkey") == "REQUIRED"
      and steps("fabric-admin-signin").get("fabric-admin-signin passkey") == "REQUIRED"
      and steps("fabric-signin").get("fabric-signin totp") == "DISABLED", run5.stdout[-400:])
pk_pw, pk_new, device = person("pk"), "Kc-" + random_password(20), SoftPasskey(f"https://{HOST}")
b6 = Browser(root_ca)
page = start(b6, APP_AUTH)
st, hdr, page = b6.go(action(page), {"username": "pk", "password": pk_pw})
seen, st, location, page = required_actions(b6, page, st, hdr, pk_new, device)
# covers: setting:signin_everyone_second_factor +
check("passkeys required: pk chooses a password, must register a passkey (user verification), then gets in",
      seen == ["password", "passkey"] and "code=" in location, (seen, st, location[:120], page[:300]))
b7 = Browser(root_ca)
st, location, page = sign_in(b7, APP_AUTH, "pk", pk_new)
check("next time Keycloak asks for the passkey after the password", "authenticateByWebAuthn" in page, page[:300])
st, hdr, _ = b7.go(action(page), device.sign_in(page))
check("the passkey signs pk in", st in (302, 303) and "code=" in hdr.get("location", ""), (st, hdr.get("location")))
b8 = Browser(root_ca)
st, location, page = sign_in(b8, APP_AUTH, "pk", pk_new)
st, hdr, page = b8.go(action(page), device.sign_in(page, key=ec.generate_private_key(ec.SECP256R1())))
check("refused: a signature from another key", "code=" not in (hdr.get("location") or ""), (st, page[:200]))

# ---- "any": whichever second factor a person enrolled; someone with neither enrols TOTP
run6 = converge_with(signin_everyone_second_factor="any")
b9 = Browser(root_ca)
st, location, page = sign_in(b9, APP_AUTH, "pk", pk_new)
check("any: a person with a passkey uses it", "authenticateByWebAuthn" in page and st == 200
      and steps("fabric-signin").get("fabric-signin totp") == "CONDITIONAL", (run6.stdout[-200:], page[:200]))
any_pw = person("anyone")
b10 = Browser(root_ca)
page = start(b10, APP_AUTH)
st, hdr, page = b10.go(action(page), {"username": "anyone", "password": any_pw})
seen, st, location, page = required_actions(b10, page, st, hdr, "Kc-" + random_password(20))
check("any: a person with neither is made to enrol TOTP (and choose a password), then gets in",
      sorted(seen) == ["password", "totp"] and "code=" in location, (seen, location[:120], page[:300]))
converge_with(signin_everyone_second_factor="none")

# ---- apps signing people in through Keycloak (fabricctl sso, manual 4.6.2)
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.keycloak.add_app_client import add_app_client  # noqa: E402
from fabriclib.keycloak.list_app_clients import list_app_clients  # noqa: E402
from fabriclib.keycloak.remove_app_client import remove_app_client  # noqa: E402

SSO_V = {"hostname_keycloak": HOST}


def refused(fn, *a):
    try:
        fn(*a)
        return False
    except ValidationError:
        return True


app = add_app_client(kc, REALM, SSO_V, "proxmox", ["https://pve.lan.test:8006"])
rep = kc.call("GET", f"{R}/clients?clientId=app-proxmox")[1][0]
mappers = kc.call("GET", f"{R}/clients/{rep['id']}/protocol-mappers/models")[1]
flows = {f["id"]: f["alias"] for f in kc.call("GET", f"{R}/authentication/flows")[1]}
check("sso add: a confidential code-flow client, the exact redirect, the realm's sign-in (no override), groups",
      rep["publicClient"] is False and rep["standardFlowEnabled"] and not rep["directAccessGrantsEnabled"]
      and not rep["implicitFlowEnabled"] and rep["redirectUris"] == ["https://pve.lan.test:8006"]
      and not (rep.get("authenticationFlowBindingOverrides") or {}).get("browser")
      and any(m["protocolMapper"] == "oidc-group-membership-mapper" and m["config"]["claim.name"] == "groups"
              for m in mappers), rep)
oidc = TLSClient(KC_IP, 8443, HOST, root_ca)
token_path = f"/realms/{REALM}/protocol/openid-connect/token"
st_ok, body_ok = oidc.request("POST", token_path, form={"grant_type": "authorization_code", "code": "x",
                                                        "client_id": "app-proxmox", "client_secret": app["secret"],
                                                        "redirect_uri": "https://pve.lan.test:8006"})
st_bad, _ = oidc.request("POST", token_path, form={"grant_type": "authorization_code", "code": "x",
                                                   "client_id": "app-proxmox", "client_secret": "wrong",
                                                   "redirect_uri": "https://pve.lan.test:8006"})
check("the secret it printed is the client's (a bogus code is refused as such; a wrong secret as a bad client)",
      st_ok == 400 and "invalid_grant" in str(body_ok) and st_bad == 401, (st_ok, body_ok, st_bad))
st, disc = oidc.request("GET", f"/realms/{REALM}/.well-known/openid-configuration")
check("the discovery document it names answers with the issuer it names",
      st == 200 and disc.get("issuer") == app["issuer"] and app["discovery"].endswith("openid-configuration"),
      (st, str(disc)[:200]))
check("refused: the same name again, an http or wildcard redirect, no redirect, a bad name",
      refused(add_app_client, kc, REALM, SSO_V, "proxmox", ["https://other.test/cb"])
      and refused(add_app_client, kc, REALM, SSO_V, "nas", ["http://nas.lan.test/cb"])
      and refused(add_app_client, kc, REALM, SSO_V, "nas", ["https://*.lan.test/cb"])
      and refused(add_app_client, kc, REALM, SSO_V, "nas", [])
      and refused(add_app_client, kc, REALM, SSO_V, "Bad Name!", ["https://nas.lan.test/cb"]))
listed = list_app_clients(kc, REALM)
check("sso list: the app, its redirect, no secret and none of fabric's own clients",
      [a["name"] for a in listed] == ["proxmox"] and app["secret"] not in str(listed), listed)
remove_app_client(kc, REALM, "proxmox")
check("sso remove: the client is gone; removing it again is refused",
      kc.call("GET", f"{R}/clients?clientId=app-proxmox")[1] == []
      and refused(remove_app_client, kc, REALM, "proxmox"))

# ---- disabling and removing a person (fabricctl people, 2.1.6.30): their sessions end at once, sign-in refused
import fabriclib.directory.remove_person as remove_mod  # noqa: E402
import fabriclib.directory.set_person_enabled as enabled_mod  # noqa: E402

PEOPLE_AUDIT = []
for mod in (enabled_mod, remove_mod):
    mod.write_audit = lambda actor, event, detail, source: PEOPLE_AUDIT.append(event)
pv = {**v, "deploy_base_dir": os.path.join(W, "opt")}
ps = {**secrets, "keycloak_admin_user": "admin", "keycloak_admin_password": "KcAdmin1"}
fred_pw = "Fr-" + random_password(20)
person("fred")
sh(["docker", "exec", DC, "samba-tool", "user", "setpassword", "fred", f"--newpassword={fred_pw}", "-s",
    "/data/etc/smb.conf"])
st, location, page = sign_in(Browser(root_ca), APP_AUTH, "fred", fred_pw)
fred_kc = kc.call("GET", f"{R}/users?username=fred&exact=true")[1]
sessions = kc.call("GET", f"{R}/users/{fred_kc[0]['id']}/sessions")[1] if fred_kc else []
check("a person signs in through Keycloak (a session held)", "code=" in location and sessions,
      (st, location[:120], page[:200]))
def _no_sessions(user_id):
    """No Keycloak session for the user: none listed, or the user gone (Keycloak drops its copy of a person its
    filter, enabled people only, no longer finds: 2.1.6.83)."""
    st, body = kc.call("GET", f"{R}/users/{user_id}/sessions", allow=(404,))
    return st == 404 or body == []


done = enabled_mod.set_person_enabled(pv, "root", "fred", False, privileged=True, source="cli", secrets=ps,
                                      container=DC)
check("disable: their Keycloak sessions end at once", done["changed"]
      and _no_sessions(fred_kc[0]["id"]), done)
st, location, page = sign_in(Browser(root_ca), APP_AUTH, "fred", fred_pw)
check("disable: a new sign-in is refused, and so is NTLM", "code=" not in location and not ntlm_signs_in("fred", fred_pw),
      page[:300])
enabled_mod.set_person_enabled(pv, "root", "fred", True, privileged=True, source="cli", secrets=ps, container=DC)
st, location, page = sign_in(Browser(root_ca), APP_AUTH, "fred", fred_pw)
check("enable: they sign in again", "code=" in location,
      (st, location[:120], re.findall(r'(?s)<span[^>]*(?:kc-feedback-text|input-error)[^>]*>(.*?)</span>', page)))
check("refused: disabling the last admin who can sign in, or a remove without the user name typed back",
      refused(enabled_mod.set_person_enabled, pv, "root", "jim", False, True, "cli", ps, DC)
      and refused(remove_mod.remove_person, pv, "root", "fred", "fre", True, "cli", ps, DC))
check("refused: the helpdesk disabling an admin (a fabric group's member)",
      refused(enabled_mod.set_person_enabled, pv, "helper", "jim", False, False, "web", ps, DC))
ledger, revoked = os.path.join(W, "issued.jsonl"), os.path.join(W, "revoked.jsonl")
gone = remove_mod.remove_person(pv, "root", "fred", "fred", privileged=True, source="cli", secrets=ps, container=DC,
                                ledger=ledger, revoked=revoked)
check("remove: the directory account and Keycloak's copy are gone, sign-in refused",
      gone == {"uid": "fred", "revoked": []} and kc.call("GET", f"{R}/users?username=fred&exact=true")[1] == []
      and not ntlm_signs_in("fred", fred_pw), gone)
check("each change audited", PEOPLE_AUDIT == ["PERSON_DISABLE", "PERSON_ENABLE", "PERSON_REMOVE"], PEOPLE_AUDIT)

if not os.environ.get("KEYCLOAK_TEST_KEEP"):
    cleanup()
print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
