import os
import shutil
import subprocess

from fabriclib.breakglass.ensure_enterprise_admin import ensure_enterprise_admin
from fabriclib.breakglass.write_break_glass_file import write_break_glass_file
from fabriclib.common.console import BOLD, NC, info, ok, warn
from fabriclib.common.sudo_owner import sudo_owner
from fabriclib.hostaccounts.record_setup_user import record_setup_user
from fabriclib.directory.constants import DIRECTORY_ADMINS
from fabriclib.directory.ensure_admin import ensure_admin
from fabriclib.federation.common.is_root_site import is_root_site
from fabriclib.keycloak.signin_levels import admin_level
from fabriclib.pki.issue_client_cert import issue_client_cert
from fabriclib.pki.needs_renewal import needs_renewal
from fabriclib.setup.ask_first_admin import ask_first_admin
from fabriclib.setup.errors import SetupError

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
    Inputs:  v — vars: hostname_mgr, hostname_stepca (the CA's files, 1.5.1.6), host_ip, the other names (for the
             hosts-file line),
             webui_client_cert, the sign-in settings (admin_level); user — the admin; login — the
             account the kit is for; folder — the kit's path.
    Returns: str.
    Fails:   ValidationError from admin_level for an unknown level; KeyError for a missing var.
    Feeds:   run; tests/render.py."""
    cert = bool(v.get("webui_client_cert"))
    return README.format(mgr=v["hostname_mgr"], certs=v["hostname_stepca"], user=user, login=login, host=v["host_ip"],
                         ip=v["host_ip"], folder=folder, group=DIRECTORY_ADMINS,
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
    """Purpose: setup's administrators, end to end (manual 1.6.12.2; 2.1.6.68, 2.1.6.69). At the root site: first
             `fabric-admin`, the Enterprise Admin (AD's top tier, not a Directory Administrator), with a generated
             password written once to ~/fabric-admin/fabric-admin-password.txt of the account that ran setup (0600,
             said here, kept nowhere else); then the first Directory Administrator, a person in OU=people and
             `directory-admins` (Keycloak grants it fabric-console-admin) with their full name, e-mail and the password
             they chose in setup. Then the fabric root CA and, while the web console requires one (webui_client_cert),
             the Directory Administrator's client certificate (.p12, CN = username), collected with instructions in
             ~/fabric-admin of the account that ran setup.
    Inputs:  ctx — SetupContext: vars install_webui, install_keycloak, ad_domain, dc_name, webui_admin_user,
             webui_admin_name, webui_admin_email, webui_client_cert, webui_client_cert_days (default 365), the
             sign-in settings, domain, hostname_mgr, hostname_landing, host_ip; secrets (Keycloak admin); config_dir
             (the break-glass record; the setup account, recorded once: record_setup_user); the published CA under
             <deploy_base>/nginx/www/certs. Env SUDO_USER via sudo_owner.
    Returns: None. Without web UI or Keycloak: fabric-admin only. At a federated site no person is created here
             (people come from the root, M5): only the client certificate and the kit. An existing fabric-admin keeps
             its password (nothing written); an existing Directory Administrator keeps theirs; no sign-in password of
             the Directory Administrator is written to the kit. The certificate is renewed when due or from another CA.
    Fails:   SetupError when fabric-admin was made but its file could not be written (the reset is named); a missing
             fact of the first Directory Administrator (ask_first_admin); ValidationError from ensure_enterprise_admin,
             ensure_admin or issue_client_cert (propagates); CalledProcessError from openssl; OSError on files. Warns
             when run as root without sudo.
    Feeds:   setup step `admin`, run by run_setup via STEPS."""
    v = ctx.vars
    if record_setup_user(ctx.config_dir, sudo_owner()[0]):     # the host's root break glass for now (2.1.6.78)
        info(f"{sudo_owner()[0]}, the account that ran setup, is this host's root break glass until local-admin takes "
             "over: it is reminded of until you remove or approve it (sudo fabricctl host accounts list)")
    root = is_root_site(os.path.join(ctx.config_dir, "federation.yaml"))
    if root:                                  # the domain's top tier, with or without the web console
        _enterprise_admin(ctx, v)
    if not (v.get("install_webui") and v.get("install_keycloak")):
        ok("no web UI: no Directory Administrator to make")
        return
    user = v.get("webui_admin_user")
    login, home, uid, gid = sudo_owner()
    folder = os.path.join(home, "fabric-admin")
    os.makedirs(folder, mode=0o700, exist_ok=True)
    os.chown(folder, uid, gid)

    if root:
        if not user:                          # named before any step; asked here only when it was not
            ask_first_admin(ctx, needed=True)
            user = v.get("webui_admin_user")
        state, _ = ensure_admin(v, ctx.secrets, user, v.get("webui_admin_email"),
                                lambda: (ask_first_admin(ctx, needed=True), ctx.admin_password)[1],
                                full_name=v.get("webui_admin_name"))
        if state == "created":
            ok(f"Directory Administrator '{user}' ({v.get('webui_admin_name')}) created in the directory with the "
               f"password chosen in setup, member of '{DIRECTORY_ADMINS}'")
        else:
            ok(f"Directory Administrator '{user}' exists" + (" (added to the admin group)" if "+member" in state
                                                             else ""))
    else:                                     # a federated site: people (the admin too) come from the root (M5)
        info(f"people are created at the root site: '{user}' signs in here once the root's directory has them "
             f"(in '{DIRECTORY_ADMINS}')")

    if not user:                              # a federated site's kit names nobody: the root names its people
        info("no first administrator named here: their sign-in kit is made at the root site")
        return
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


def _enterprise_admin(ctx, v):
    """Purpose: `fabric-admin`, the Enterprise Admin, made once (ensure_enterprise_admin) and, when it was made now,
             its generated password written to its one file (write_break_glass_file), the path said and the person
             asked to put it somewhere safe and delete the file (2.1.6.69).
    Inputs:  ctx — SetupContext (config_dir); v — vars (ad_domain and what ensure_enterprise_admin reads).
    Returns: None.
    Fails:   SetupError when the account was made but the file could not be written (the password is then lost:
             `fabricctl admin reset-break-glass` makes a new one); ValidationError from ensure_enterprise_admin.
    Feeds:   run."""
    made = ensure_enterprise_admin(v)
    if not made["created"]:
        ok("fabric-admin, the Enterprise Admin, exists (its password is kept as it is)")
        return
    try:
        path = write_break_glass_file(made["password"], v.get("ad_domain") or "", ctx.config_dir)
    except OSError as e:
        raise SetupError(f"fabric-admin was made but its password could not be written ({e}): run "
                         "sudo fabricctl admin reset-break-glass for a new one") from None
    ok("fabric-admin, the Enterprise Admin (Enterprise, Schema and Domain Admins), made with a generated password")
    warn(f"its break-glass password is in {BOLD}{path}{NC} (0600, yours alone; fabric keeps it nowhere else): copy "
         "it into your own safekeeping now, then delete the file")


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
