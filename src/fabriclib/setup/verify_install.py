import datetime
import json
import os
import shutil
import stat
import struct
import subprocess

from fabriclib.common.console import err, ok, warn
from fabriclib.common.dns_query import dns_query
from fabriclib.common.doh_query import doh_query
from fabriclib.common.dot_query import dot_query
from fabriclib.common.paths import CERT_RENEWAL_FILE, DB_ROTATION_FILE, ISSUED_CERTS_FILE
from fabriclib.common.sudo_owner import sudo_owner
from fabriclib.consent.allowed_to_change import allowed_to_change
from fabriclib.consent.plan_local_admin import plan_local_admin
from fabriclib.consent.plan_trust import plan_trust
from fabriclib.dns.common.landing_names import landing_names
from fabriclib.federation.common.load_registry import load_registry
from fabriclib.keycloak.user_has_role import user_has_role
from fabriclib.ntp.chrony_settings import chrony_settings
from fabriclib.ntp.query_time import query_time
from fabriclib.ntp.time_status import time_status
from fabriclib.pki.cert_warnings import cert_warnings
from fabriclib.breakglass.break_glass_reminder import break_glass_reminder
from fabriclib.hostaccounts.local_account_reminders import local_account_reminders
from fabriclib.localadmin.local_admin_checks import local_admin_checks
from fabriclib.pki.common.cert_names import cert_names
from fabriclib.setup.errors import SetupError
from fabriclib.system.relaxed_settings import relaxed_settings
from fabriclib.vault.vault_status import vault_status


def _curl(url, host, ip, port, root_ca, client_cert=False):
    """Purpose: one HTTP(S) request pinned to an IP, for the checks.
    Inputs:  url; host, ip, port — `--resolve host:port:ip`; root_ca — CA file to verify with, or None for the
             host's trust store; client_cert — unused.
    Returns: (curl exit code, HTTP status code as str).
    Fails:   never raises for HTTP/TLS errors (they are the exit code); FileNotFoundError without curl.
    Feeds:   checks."""
    ca = ["--cacert", root_ca] if root_ca else []      # None: the host's own trust store
    res = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10",
                          *ca, "--resolve", f"{host}:{port}:{ip}", url],
                         capture_output=True, text=True)
    return res.returncode, res.stdout


def _db_rotation(path=DB_ROTATION_FILE, now=None):
    """Purpose: whether Keycloak's database password was rotated lately (2.1.7.4): the last run worked and is at most
             40 days old (monthly, with a missed night or two to spare).
    Inputs:  path — the record rotate_db_password keeps; now — aware datetime (tests).
    Returns: (ok: bool, detail: str).
    Fails:   never (an unreadable record is a failed check).
    Feeds:   checks."""
    try:
        with open(path) as f:
            last = json.load(f)
        when = datetime.datetime.fromisoformat(last["when"])
    except (OSError, ValueError, KeyError):
        return False, "never rotated: sudo fabricctl setup, or sudo fabricctl vault rotate-db"
    age = ((now or datetime.datetime.now().astimezone()) - when).days
    if not last.get("ok"):
        return False, f"the last rotation failed ({last.get('detail', '')}): sudo fabricctl vault rotate-db"
    return age <= 40, f"last rotated {age} day(s) ago" + ("" if age <= 40 else ": is the fabric-db-rotate timer on?")


def _records(archive):
    """Purpose: the certificate records of this install, in its own archive: setup runs from the package's copy, where
             the default paths would point (found by the 0.6.3 sandbox).
    Inputs:  archive — <install>/archive.
    Returns: {"record", "ledger"} for cert_warnings.
    Fails:   never.
    Feeds:   checks, run."""
    return {"record": os.path.join(archive, os.path.basename(CERT_RENEWAL_FILE)),
            "ledger": os.path.join(archive, os.path.basename(ISSUED_CERTS_FILE))}


def checks(ctx):
    """Purpose: the end-to-end checks of a running install: DNS (and DNS-over-HTTPS), HTTP/HTTPS chains, CA
             publishing (the landing page at http://<host_ip>/info/ and over HTTPS at each of its names, aliases
             included, 2.1.4.8; the CRL point at ca.<domain>), ACME, host trust
             (unless the `trust` host change was declined), web UI gates, fabric-agent socket, first admin
             (Keycloak role, the client certificate while one is required), OpenBao state, the federation endpoint and
             the DNS filter (the BIND resolver answers on 53) when on, time (chrony synchronised and
             under 1 s off — or this host's own clock when no source is set —, and at a site within 1 s of its
             upstream site), the certificates (renewal working, none about to expire), and every installed service.
    Inputs:  ctx — SetupContext: vars (hostnames, host_ip, ip_nginx, bind_dns_port, install_webui/keycloak,
             federation_endpoint, install_resolver, webui_admin_user/role), secrets (Keycloak),
             Step-CA root, the
             agent socket, ~/fabric-admin of the sudo user.
    Returns: list of (name, passed: bool, detail: str).
    Fails:   ValidationError from ctx.secrets when OpenBao is locked; KeyError for missing vars; OSError reading
             root_ca.crt; struct.error/IndexError from
             dns_query on a malformed reply. Check failures are results, not exceptions.
    Feeds:   run."""
    archive = os.path.join(ctx.target_dir, "archive")      # the install's, not the package copy's
    v, s = ctx.vars, ctx.secrets
    root_ca = ctx.path("stepca", "data", "certs", "root_ca.crt")
    port = int(v.get("bind_dns_port", 53))
    results = []

    def add(name, passed, detail=""):
        results.append((name, bool(passed), detail))

    # fabric's own names (the landing page's info alias is the admin's since 0.7.1: 2.1.4.6)
    host_fqdn = f"{v['hostname']}.{v['domain']}".lower()
    for name in (host_fqdn, f"ns.{v['domain']}", v["hostname_stepca"]):
        try:
            got = dns_query(name, v["host_ip"], port)
            add(f"DNS {name}", v["host_ip"] in got, ", ".join(got) or "no answer")
        except OSError as e:
            add(f"DNS {name}", False, str(e))

    try:                                     # DNS-over-HTTPS through nginx to BIND (2.1.12.2)
        got = doh_query(f"ns.{v['domain']}", v["hostname_bind9"], v["ip_nginx"], root_ca)
        add(f"DNS-over-HTTPS https://{v['hostname_bind9']}/dns-query answers", v["host_ip"] in got,
            ", ".join(got) or "no answer")
    except (subprocess.CalledProcessError, struct.error, IndexError) as e:
        add(f"DNS-over-HTTPS https://{v['hostname_bind9']}/dns-query answers", False, str(e)[-200:])

    if v.get("install_resolver"):          # the BIND resolver (1.12.2) answers clients on 53, fabric's names via BIND
        try:
            got = dns_query(v["hostname_stepca"], v["host_ip"], 53)
            add(f"DNS filter (BIND resolver, port 53) resolves {v['hostname_stepca']}", v["host_ip"] in got,
                ", ".join(got) or "no answer")
        except OSError as e:
            add(f"DNS filter (BIND resolver, port 53) resolves {v['hostname_stepca']}", False, str(e))
        what = f"DNS-over-TLS {v['host_ip']}:853 ({v['hostname_bind9']}) answers"      # 1.12.2.16
        try:
            got = dot_query(f"ns.{v['domain']}", v["hostname_bind9"], v["host_ip"], root_ca)
            add(what, v["host_ip"] in got, ", ".join(got) or "no answer")
        except (OSError, struct.error, IndexError) as e:
            add(what, False, str(e)[-200:])

    if shutil.which("chronyc"):             # time (manual 1.13.1): certificates, TOTP and TSIG depend on it
        t = time_status()
        own_only = not chrony_settings(v, os.path.join(ctx.config_dir, "federation.yaml"))["sources"]
        if t.get("error"):
            add("time: chrony answers", False, t["error"])
        else:
            add("time synchronised (under 1 s off)" if not own_only else "time: this host's own clock (no sources)",
                (t["synced"] and t["offset"] < 1.0) or (own_only and t["local"]),
                f"{t['source']}, stratum {t['stratum']}, {t['offset']:.3f} s off" if not t["local"]
                else "no time source reachable: this host's own clock")
        up = (load_registry(os.path.join(ctx.config_dir, "federation.yaml")).get("upstream") or {}).get("address")
        if up:
            off = query_time(up)
            add(f"time agrees with the upstream site ({up})", off is not None and abs(off) < 1.0,
                f"{off:+.3f} s" if off is not None else "no answer on UDP 123")

    rc, code = _curl(f"http://{v['host_ip']}/", v["host_ip"], v["host_ip"], 80, root_ca)
    add("nginx HTTP", code in ("200", "301", "302"), f"HTTP {code}")
    res = subprocess.run(["curl", "-s", "--max-time", "10", f"http://{v['host_ip']}/info/"], capture_output=True,
                         text=True)                       # the landing page by address (2.1.4.6, 1.4.2.5)
    add(f"the landing page at http://{v['host_ip']}/info/",
        res.returncode == 0 and "/certs/ca-certs.json" in res.stdout, f"curl exit {res.returncode}")
    # the landing page's names, its aliases included: its certificate holds exactly them once applied (2.1.4.8)
    names = landing_names(v)
    have = cert_names(ctx.path("nginx", "certs", v["hostname_landing"], "fullchain.pem")) or set()
    missing, extra = sorted(set(names) - have), sorted(have - set(names))
    add("the landing page's certificate holds its names (the host's, <domain>, its aliases)", not missing and not extra,
        "; ".join(([f"not yet: {', '.join(missing)}"] if missing else [])
                  + ([f"no longer: {', '.join(extra)}"] if extra else [])) + " (an apply issues it again)")
    for host in (*[n for n in names if n in have or n in names[:2]], v["hostname_stepca"], v["hostname_bind9"]):
        rc, code = _curl(f"https://{host}/", host, v["ip_nginx"], 443, root_ca)
        add(f"HTTPS {host} (cert verified)", rc == 0, f"HTTP {code}" if rc == 0 else f"curl exit {rc}")
    # the CA certificates at the host's own name (1.5.1.5, 2.1.4.6); ca.<domain>: Step-CA's API, browsers sent there
    certs_url = f"https://{host_fqdn}/certs/"
    res = subprocess.run(["curl", "-s", "--max-time", "10", "--cacert", root_ca, "--resolve",
                          f"{host_fqdn}:443:{v['ip_nginx']}", f"{certs_url}root-ca.pem"],
                         capture_output=True, text=True)
    with open(root_ca) as f:
        served_ok = res.returncode == 0 and res.stdout.strip() and res.stdout.strip() in f.read()
    add(f"{certs_url} serves this CA's root certificate", served_ok, f"curl exit {res.returncode}")
    crl_url = f"http://{v['hostname_stepca']}/certs/crl/intermediate.crl"      # the point certificates name (1.5.1.6)
    if os.path.exists(ctx.path("nginx", "www", "certs", "crl", "intermediate.crl")):    # where the key is here
        res = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10", "--resolve",
                              f"{v['hostname_stepca']}:80:{v['host_ip']}", crl_url], capture_output=True, text=True)
        add(f"{crl_url} answers (the CRL point certificates name)", res.stdout == "200", f"HTTP {res.stdout}")
    res = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{redirect_url}", "--max-time", "10",
                          "--cacert", root_ca, "--resolve", f"{v['hostname_stepca']}:443:{v['ip_nginx']}",
                          f"https://{v['hostname_stepca']}/"], capture_output=True, text=True)
    add(f"https://{v['hostname_stepca']}/ sends browsers to {certs_url}",
        res.stdout.startswith("302 ") and res.stdout.split(" ", 1)[-1] == certs_url, res.stdout)
    rc, code = _curl(f"https://{v['hostname_stepca']}/acme/acme/directory", v["hostname_stepca"], v["ip_nginx"], 443,
                     root_ca)
    add("Step-CA ACME directory reachable (API unaffected)", rc == 0 and code == "200", f"HTTP {code}")
    if allowed_to_change(ctx.config_dir, "trust", plan_trust(v), unasked_install=True):    # not when declined
        rc, code = _curl(f"https://{host_fqdn}/", host_fqdn, v["ip_nginx"], 443, None)   # a name fabric keeps
        add("this host trusts the fabric CA (system store)", rc == 0, f"HTTP {code}" if rc == 0 else f"curl exit {rc}")

    if v.get("install_webui"):
        rc, code = _curl(f"https://{v['hostname_mgr']}/", v["hostname_mgr"], v["ip_nginx"], 443, root_ca)
        if v.get("webui_client_cert"):          # the web console asks for a client certificate (2.1.8.2)
            add("web UI refuses requests without a client certificate", code == "400", f"HTTP {code}")
        else:                                   # no certificate asked: the web app sends a newcomer to sign in
            add("web UI answers and sends a newcomer to sign in", code == "303", f"HTTP {code}")
        sock = ctx.path("webui", "agent", "agent.sock")
        st = os.stat(sock) if os.path.exists(sock) else None
        add("fabric-agent socket 0660, webui group only",
            st and stat.S_IMODE(st.st_mode) == 0o660 and st.st_gid == ctx.uid("webui")[1])

        # The first admin, end to end: LDAP user -> admin group -> Keycloak role,
        # and a client certificate from this CA whose CN is that user.
        admin, role = v.get("webui_admin_user"), v.get("webui_admin_role", "fabric-admin")
        if admin and v.get("install_keycloak"):
            try:
                add(f"Keycloak grants {admin} {role}", user_has_role(v, s, admin, role))
            except (SystemExit, OSError) as e:
                add(f"Keycloak grants {admin} {role}", False, str(e))
            crt = os.path.join(sudo_owner()[1], "fabric-admin", f"{admin}.crt")
            if v.get("webui_client_cert") and os.path.exists(crt):
                certs = ctx.path("stepca", "data", "certs")
                chain = os.path.join(certs, "intermediate_chain.crt")     # byoc: the intermediate + parent CAs
                res = subprocess.run(["openssl", "verify", "-CAfile", os.path.join(certs, "root_ca.crt"),
                                      "-untrusted", chain if os.path.exists(chain)
                                      else os.path.join(certs, "intermediate_ca.crt"), crt],
                                     capture_output=True, text=True)
                subj = subprocess.run(["openssl", "x509", "-in", crt, "-noout", "-subject", "-nameopt", "RFC2253"],
                                      capture_output=True, text=True).stdout
                add(f"client certificate for {admin} (CN, chain)", res.returncode == 0 and f"CN={admin}" in subj,
                    (res.stdout + res.stderr).strip()[-200:])

    bao = vault_status(v)
    add("OpenBao unsealed (static seal, raft)", bao.get("initialized") and bao.get("sealed") is False
        and bao.get("seal_type") == "static", bao.get("error", ""))
    add("OpenBao unlock methods: store root-only, no vault key left in RAM", bao["key"]["ok"], bao["key"]["detail"])
    add("OpenBao KV v2 fabric/ and apps/ (read as fabric-agent)",
        {"fabric/", "apps/"} <= {m["path"] for m in bao.get("mounts", [])}, bao.get("error", ""))
    code = _curl(f"https://{v['hostname_openbao']}/v1/sys/health", v["hostname_openbao"], v["ip_nginx"], 443, root_ca)
    add(f"https://{v['hostname_openbao']} (OpenBao via nginx, TLS verified)", code == (0, "200"), code)
    if v.get("federation_endpoint"):
        code = _curl(f"https://{v['hostname_federation']}/v1/health", v["hostname_federation"], v["ip_nginx"], 443,
                     root_ca)
        add(f"https://{v['hostname_federation']} (federation endpoint, TLS verified)", code == (0, "200"), code)

    if v.get("install_keycloak"):           # Keycloak's database password, rotated monthly by OpenBao (2.1.7.4)
        add("Keycloak's database password: rotated by OpenBao in the last 40 days",
            *_db_rotation(os.path.join(archive, "db-rotation.json")))
    # the host's local-admin while its host change is approved (2.1.7.16, manual 1.7.1.4.7)
    approved = allowed_to_change(ctx.config_dir, "local_admin", plan_local_admin(v))
    for row in local_admin_checks(v, ctx.config_dir, approved)["checks"]:
        add(*row)
    failing = [w["what"] for w in cert_warnings(v, **_records(archive)) if w["level"] == "fail"]
    add("certificates: renewal working, none about to expire (2.1.5.4)", not failing, "; ".join(failing))
    for unit in ("bind9", "stepca", "nginx", "samba", "postgres", "keycloak", "openbao", "kea", "freeradius",
                 "samba", "fluentbit",
                 "bind9-resolver", "adguard-filter", "fabric-agent", "fabric-federation", "fabric-web",
                 "fabric-firewall"):
        if os.path.exists(f"/etc/systemd/system/{unit}.service"):
            active = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True).stdout.strip()
            add(f"service {unit}", active == "active", active)
    return results


def run(ctx):
    """Purpose: check the running install end to end and fail setup if anything is wrong (same checks as
             `fabricctl doctor`).
    Inputs:  ctx — SetupContext with state loaded (see checks).
    Returns: None; each check printed as ok or error, then a warning for each sign-in layer lowered below a level
             it had, for what is coming with the certificates (cert_warnings) and, while it is on the host, for the
             break-glass password's file (break_glass_reminder, 2.1.6.69) and for each local administrator account
             neither managed nor approved (local_account_reminders, 2.1.6.78).
    Fails:   SetupError("<n> check(s) failed"); exceptions from checks propagate.
    Feeds:   setup step `verify`, run by run_setup via STEPS; run_setup main for `fabricctl doctor`."""
    failed = 0
    for name, passed, detail in checks(ctx):
        (ok if passed else err)(f"{name}" + (f" — {detail}" if detail else ""))
        failed += not passed
    # sign-in layers lowered with `fabricctl security lower` stay in view until raised again (2.1.6.24), and the
    # grants' open fallback while it is on (2.1.6.88): warnings, which do not fail the checks
    for row in relaxed_settings(ctx.vars, ctx.config_dir):
        if " lowered: " in row["setting"] or row["setting"].startswith("grants_fallback_open"):
            warn(("sign-in " if " lowered: " in row["setting"] else "") + f"{row['setting']} — {row['effect']}")
    for row in cert_warnings(ctx.vars, **_records(os.path.join(ctx.target_dir, "archive"))):    # what is coming
        if row["level"] == "warn":
            warn(f"certificates: {row['what']}")
    reminder = break_glass_reminder(ctx.config_dir)     # until the break-glass password's file is gone (2.1.6.69)
    if reminder:
        warn(reminder["text"])
    for row in local_account_reminders(ctx.config_dir):     # until removed or approved (2.1.6.78)
        warn(row["text"])
    # a rotation waiting (2.1.7.20); SSH on until its alert is acknowledged (2.1.7.21)
    for text in local_admin_checks(ctx.vars, ctx.config_dir, False)["warnings"]:
        warn(text)
    if failed:
        raise SetupError(f"{failed} check(s) failed")
