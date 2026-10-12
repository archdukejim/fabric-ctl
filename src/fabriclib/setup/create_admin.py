import os
import shutil
import subprocess

from fabriclib.common.console import info, ok, warn
from fabriclib.common.sudo_owner import sudo_owner
from fabriclib.directory.ensure_admin import ensure_admin
from fabriclib.federation.common.is_root_site import is_root_site
from fabriclib.keycloak.signin_levels import admin_level
from fabriclib.pki.issue_client_cert import issue_client_cert
from fabriclib.pki.needs_renewal import needs_renewal
from fabriclib.setup.ask_first_admin import ask_first_admin

README = """fabric web UI — first login
===========================

Everything your computer needs to reach https://{mgr}:

  root-ca.crt / root-ca.cer     fabric root CA (Linux, macOS, iOS, Android / Windows)
{cert_line}
1. First, your computer must find fabric's names: set its DNS server to {ip}
   (its network settings, or your router's DHCP), or add this line to its
   hosts file (/etc/hosts; Windows: C:\\Windows\\System32\\drivers\\etc\\hosts):
     {ip} {names}
2. Copy this folder to your computer, e.g.
     scp -r {login}@{host}:{folder} .
   (or download the root CA from http://{ip}/certs/, plain HTTP, no names needed)
3. Trust the root CA: Windows: double-click root-ca.cer and put it in
   "Trusted Root Certification Authorities"; macOS/Linux: root-ca.crt. Every
   system, format and installer: http://{certs}/certs/
{cert_step}{n}. Open https://{mgr}{choose} and sign in as '{user}' with the password
   you chose in setup{factor}.{kerberos}
{p12_delete}More admins: add them to the '{group}' group.{more}
Raise sign-in security (a second factor, the client certificate) in the web
console's Security page.
"""
CERT_LINE = "  {user}.p12                    your client certificate (password: p12-password.txt)\n"
CERT_STEP = """4. Import {user}.p12 into your browser (Firefox: Settings > Certificates >
   Your Certificates > Import; Chrome/Edge/Windows: double-click it).
"""
FACTOR = {"none": "", "totp": "; Keycloak then asks you to set up an authenticator app (TOTP)",
          "passkey": "; Keycloak then asks you to register a passkey (Windows Hello, a phone or a security key)",
          "any": "; Keycloak then asks you to set up an authenticator app (TOTP) unless you add a passkey"}
KERBEROS = """ On a computer
   joined to the domain, signing in to Windows or Linux signs you in here."""


def _write(path, text, owner):
    """Purpose: write a private file for the operator.
    Inputs:  path — destination; text — content; owner — (uid, gid).
    Returns: None; file 0600 (created under umask 077) owned by owner.
    Fails:   OSError on write, chmod or chown.
    Feeds:   run, _client_cert (<user>.crt, p12-password.txt, README.txt)."""
    old = os.umask(0o077)
    try:
        with open(path, "w") as f:
            f.write(text)
    finally:
        os.umask(old)
    os.chmod(path, 0o600)
    os.chown(path, *owner)


def _readme(v, user, login, folder):
    """Purpose: the kit's README.txt for the web console as it is set up: with the client-certificate steps only while
             the console requires one (webui_client_cert), and the second factor Keycloak will ask for.
    Inputs:  v — vars: hostname_mgr, hostname_landing, host_ip, the other names (for the hosts-file line),
             webui_admin_group, webui_client_cert, the sign-in settings (admin_level); user — the admin; login — the
             account the kit is for; folder — the kit's path.
    Returns: str.
    Fails:   ValidationError from admin_level for an unknown level; KeyError for a missing var.
    Feeds:   run; tests/render.py."""
    cert = bool(v.get("webui_client_cert"))
    return README.format(mgr=v["hostname_mgr"], certs=v["hostname_landing"], user=user, login=login, host=v["host_ip"],
                         ip=v["host_ip"], folder=folder, group=v.get("webui_admin_group", "admins"),
                         cert_line=CERT_LINE.format(user=user) if cert else "",
                         cert_step=CERT_STEP.format(user=user) if cert else "", n=5 if cert else 4,
                         names=" ".join(v[k] for k in ("hostname_landing", "hostname_mgr", "hostname_keycloak",
                                                       "hostname_stepca", "hostname_openbao")
                                        if v.get(k)),
                         choose=f', choose the "{user} (fabric)" certificate' if cert else "",
                         factor=FACTOR[admin_level(v)], kerberos=KERBEROS if v.get("signin_kerberos") else "",
                         p12_delete="Delete p12-password.txt once you are in.\n" if cert else "",
                         more=" Their client certificate: sudo fabricctl client-cert <user>." if cert else "")


def run(ctx):
    """Purpose: the first web UI admin, end to end: a person in the directory, in the admin group (Keycloak grants it
             fabric-console-admin), the fabric root CA and, while the web console requires one (webui_client_cert), a
             client certificate (.p12, CN = username), collected with instructions in ~/fabric-admin of the account
             that ran setup.
    Inputs:  ctx — SetupContext: vars install_webui, install_keycloak,
             webui_admin_user, webui_admin_email, webui_admin_group (default admins), webui_client_cert,
             webui_client_cert_days (default 365), the sign-in settings, domain, hostname_mgr, hostname_landing,
             host_ip; secrets (Keycloak admin); the published CA under <deploy_base>/nginx/www/certs. Env SUDO_USER
             via sudo_owner.
    Returns: None. Without web UI or Keycloak: nothing. At a federated site the person is not created here
             (people come from the root, M5): only the client certificate and the kit. Otherwise the kit folder (0700)
             holds root-ca.crt/.cer, README.txt and, with the certificate on and when due, <user>.p12, <user>.crt and
             p12-password.txt. A new admin gets the password chosen in setup (ask_first_admin: asked here when setup
             had not, 2.1.6.33); no password is written to the kit. Idempotent: an existing user keeps their
             password; the certificate is renewed when due or from another CA.
    Fails:   ValidationError from ensure_admin (the directory) or issue_client_cert (propagates,
             not SetupError); CalledProcessError from openssl; OSError on files. Warns when run as root without sudo.
    Feeds:   setup step `admin`, run by run_setup via STEPS."""
    v = ctx.vars
    if not (v.get("install_webui") and v.get("install_keycloak")):
        ok("no web UI: nothing to do")
        return
    user = v.get("webui_admin_user")
    login, home, uid, gid = sudo_owner()
    folder = os.path.join(home, "fabric-admin")
    os.makedirs(folder, mode=0o700, exist_ok=True)
    os.chown(folder, uid, gid)

    if is_root_site(os.path.join(ctx.config_dir, "federation.yaml")):
        state, _ = ensure_admin(v, ctx.secrets, user, v.get("webui_admin_email") or f"{user}@{v['domain']}",
                                lambda: (ask_first_admin(ctx, needed=True), ctx.admin_password)[1])
        if state == "created":
            ok(f"admin '{user}' created in the directory with the password chosen in setup, member of "
               f"'{v.get('webui_admin_group', 'admins')}'")
        else:
            ok(f"admin '{user}' exists" + (" (added to the admin group)" if "+member" in state else ""))
    else:                                     # a federated site: people (the admin too) come from the root (M5)
        info(f"people are created at the root site: '{user}' signs in here once the root's directory has them "
             f"(in '{v.get('webui_admin_group', 'admins')}')")

    if v.get("webui_client_cert"):            # the web console asks for one (2.1.8.2: off by default)
        _client_cert(ctx, v, user, folder, (uid, gid))
    else:
        ok("no client certificate: the web console does not ask for one (raise it in the Security page)")

    www = ctx.path("nginx", "www", "certs")
    for name in ("root-ca.crt", "root-ca.cer"):
        shutil.copy2(os.path.join(www, name), os.path.join(folder, name))
        os.chown(os.path.join(folder, name), uid, gid)
    _write(os.path.join(folder, "README.txt"), _readme(v, user, login, folder), (uid, gid))
    info(f"web UI login kit: {folder} (see README.txt)")
    if login == "root":
        warn("setup was not run with sudo from a user account: the kit is in /root")


def _client_cert(ctx, v, user, folder, owner):
    """Purpose: the first admin's client certificate in the kit (only while the web console requires one): <user>.p12,
             <user>.crt and p12-password.txt, issued when missing, due or from another CA (an earlier install's).
    Inputs:  ctx — SetupContext (the CA under stepca/data/certs); v — vars (webui_client_cert_days); user — the
             admin's name (the certificate's CN); folder — the kit; owner — (uid, gid).
    Returns: None.
    Fails:   ValidationError from issue_client_cert; CalledProcessError from openssl; OSError on files.
    Feeds:   run."""
    crt_pub = os.path.join(folder, f"{user}.crt")
    certs = ctx.path("stepca", "data", "certs")
    ca = (os.path.join(certs, "root_ca.crt"), os.path.join(certs, "intermediate_ca.crt"))
    # A kit left from an earlier install (other CA) is replaced too.
    if needs_renewal(crt_pub, [], ca) or not os.path.exists(os.path.join(folder, f"{user}.p12")):
        p12, p12_password = issue_client_cert(v, user, folder, owner=owner,
                                              days=int(v.get("webui_client_cert_days", 365)))
        pub = subprocess.run(["openssl", "pkcs12", "-in", p12, "-clcerts", "-nokeys", "-passin", "stdin"],
                             input=p12_password, capture_output=True, text=True, check=True).stdout
        _write(crt_pub, pub[pub.index("-----BEGIN CERTIFICATE"):], owner)
        os.chmod(crt_pub, 0o644)
        _write(os.path.join(folder, "p12-password.txt"), p12_password + "\n", owner)
        ok(f"client certificate {p12}")
    else:
        ok(f"client certificate for '{user}' is current")
