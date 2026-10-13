import os
import shutil
import subprocess

from fabriclib.common.console import err, ok
from fabriclib.common.errors import ValidationError
from fabriclib.dns.common.landing_names import landing_names
from fabriclib.pki.common.cert_names import cert_names
from fabriclib.pki.common.crl_points import crl_points
from fabriclib.pki.common.describe_cert import describe_cert
from fabriclib.pki.install_cert import install_cert
from fabriclib.pki.mint_cert import mint_cert
from fabriclib.pki.needs_renewal import needs_renewal
from fabriclib.pki.publish_crl import publish_crl
from fabriclib.pki.revoke_cert import revoke_cert
from fabriclib.setup.mint_extra_certs import mint_extra_certs


def _targets(ctx):
    """Purpose: the service certificates this install needs and where each one goes.
    Inputs:  ctx — SetupContext: vars hostname_* (bind9, stepca, landing, openbao, keycloak, mgr,
             radius, federation, dc), domain, install_keycloak, install_webui,
             install_freeradius, install_resolver, federation_endpoint, ad_domain.
    Returns: list of (cn, extra SANs, [(destination dir, service user or "freeradius:eap")],
             services to restart when it changes, exact: True when the certificate must hold exactly these names, so
             a name dropped is a reason to issue it again). bind9 (and the DNS filter's resolver when on), stepca,
             landing and openbao always (no certs.<domain> since 0.7.0: the CA is served at /certs/, 1.5.1.5, 1.5.1.6);
             the landing page's certificate holds landing_names (decision 2.1.4.8, 1.4.2.6): the host's own name
             (its CN), <domain> and the admin's aliases of the host, kept in its folder named after hostname_landing;
             LDAP, Keycloak + Postgres, web UI, FreeRADIUS (EAP-TLS server cert), the federation endpoint when on,
             the DNS filter's AdGuard Home (*.filter.<domain>) when on, and the domain controller.
    Fails:   KeyError for a missing hostname_* var.
    Feeds:   run."""
    v, p = ctx.vars, ctx.path
    nginx = lambda host: (p("nginx", "certs", host), "nginx")   # noqa: E731
    # the DNS name's certificate: DoH through nginx, and the DNS filter's own DoT and DoH listeners (1.12.2.16)
    dns_dests, dns_services = [nginx(v["hostname_bind9"]), (p("bind9", "ssl"), "bind")], ["nginx", "bind9"]
    if v.get("install_resolver"):
        dns_dests.append((p("resolver", "tls"), "resolver"))
        dns_services.append("bind9-resolver")
    # the landing page's names, computed from the zone at each run: exactly these, so a renamed alias moves (2.1.4.8)
    landing = landing_names(v)
    t = [
        (v["hostname_bind9"], [f"ns.{v['domain']}", "127.0.0.1"], dns_dests, dns_services),
        (v["hostname_stepca"], [], [nginx(v["hostname_stepca"])], ["nginx"]),
        (landing[0], landing[1:], [nginx(v["hostname_landing"])], ["nginx"], True),
        (v["hostname_openbao"], ["openbao"], [nginx(v["hostname_openbao"]), (p("openbao", "certs"), "openbao")],
         ["nginx", "openbao"]),
    ]
    if v.get("install_keycloak"):
        t.append((v["hostname_keycloak"], [], [nginx(v["hostname_keycloak"]), (p("keycloak", "certs"), "keycloak")],
                  ["nginx", "keycloak"]))
        # only ever reached on fabric_net by its alias (Keycloak, and OpenBao's database engine: 2.1.7.4); 5432 is
        # not published
        t.append(("postgres", [], [(p("postgres", "certs"), "postgres")], ["postgres"]))
    if v.get("install_webui"):
        t.append((v["hostname_mgr"], [], [nginx(v["hostname_mgr"])], ["nginx"]))
    if v.get("federation_endpoint"):
        t.append((v["hostname_federation"], [], [nginx(v["hostname_federation"])], ["nginx"]))
    # the DC's LDAPS/TLS certificate (manual 1.6.5.7): Keycloak, FreeRADIUS and members verify it; Keycloak and
    # FreeRADIUS reach it at the host's address, so it names that too
    # fabric_net's gateway too: containers reach the DC there (2.1.2.15)
    t.append((v["hostname_dc"], [v["ad_domain"], v["host_ip"], v.get("ip_fabric_gateway", "10.255.0.1")],
              [(p("samba", "tls"), "root")], ["samba"]))
    if v.get("install_resolver"):
        # AdGuard Home's DoT for the groups: each group's view names <group>.filter.<domain>, its ClientID (1.12.3.6);
        # a new certificate restarts it (about 30 s of SERVFAIL for internet names: renewed at night by the timer)
        t.append((f"filter.{v['domain']}", [f"*.filter.{v['domain']}"], [(p("dnsfilter", "tls"), "adguard")],
                  ["adguard-filter"]))
    if v.get("install_freeradius"):
        # the EAP-TLS server certificate supplicants check (server.pem, server.key)
        t.append((v["hostname_radius"], [], [(p("freeradius", "certs"), "freeradius:eap")], ["freeradius"]))
    return [(*x, False) if len(x) == 4 else x for x in t]


def _replaced_serial(cert_path, ca_certs):
    """Purpose: the serial of a certificate about to be replaced because its names changed, so it can be revoked
             once the new one is in place (decision 2.1.4.8).
    Inputs:  cert_path — the certificate on disk; ca_certs — (root, intermediate) of this CA.
    Returns: the serial (hex) when the certificate is there and was issued by this CA; None otherwise (one from a
             replaced CA is not this CA's to revoke).
    Fails:   never for a bad certificate (None); FileNotFoundError only if openssl is not installed.
    Feeds:   run."""
    root, intermediate = ca_certs
    if subprocess.run(["openssl", "verify", "-CAfile", root, "-untrusted", intermediate, cert_path],
                      capture_output=True).returncode != 0:
        return None
    try:
        with open(cert_path) as f:
            return describe_cert(f.read())["serial"] or None
    except (OSError, ValidationError):
        return None


def _revoke_replaced(ctx, serial, cn):
    """Purpose: revoke the certificate a name change replaced (decision 2.1.4.8, reason superseded), so the old
             alias's certificate is not left valid; run publishes the CRL right after. A refusal is said loudly and
             kept for the renewal record (status, doctor), and the new certificate stays: the new names are what the
             page needs, the revocation is the clean-up.
    Inputs:  ctx — SetupContext (vars: deploy_base_dir; cert_problems collects the failure); serial — the replaced
             certificate's; cn — its CN, for the messages.
    Returns: None.
    Fails:   never: ValidationError, OSError and CalledProcessError from revoke_cert are reported, not raised.
    Feeds:   run."""
    try:
        revoke_cert(ctx.vars, "fabric", serial, reason="superseded", source="cli", publish=False)
        ok(f"{cn}: the certificate it replaced ({serial}) is revoked (superseded)")
    except (ValidationError, OSError, subprocess.CalledProcessError) as e:
        msg = (f"{cn}: the certificate it replaced ({serial}) could not be revoked: {e}. The new one is in use; "
               f"revoke the old one with `sudo fabricctl certs revoke {serial} --reason superseded`")
        err(msg)
        if isinstance(getattr(ctx, "cert_problems", None), list):
            ctx.cert_problems.append(msg)


def _crl_moved(ctx, cert_path):
    """Purpose: whether a service certificate names a CRL point other than the one fabric's certificates name now
             (http://<hostname_stepca>/certs/crl/intermediate.crl, 1.5.1.6): one issued by 0.7.0 names info.<domain>,
             which the admin may now rename, repoint or delete (2.1.4.6), so it is issued again at once.
    Inputs:  ctx — SetupContext: vars hostname_stepca; cert_path — the certificate on disk.
    Returns: True when the certificate names CRL points and the current one is not exactly the one; False when it
             names none (issued before 0.7.0: left to its renewal, 1.5.1.5), names the current one, or is missing
             (needs_renewal decides that).
    Fails:   FileNotFoundError only if openssl is not installed.
    Feeds:   run."""
    if not os.path.exists(cert_path):
        return False
    points = crl_points(cert_path)
    return bool(points) and points != [f"http://{ctx.vars['hostname_stepca']}/certs/crl/intermediate.crl"]


def _old_certs_host(ctx, targets):
    """Purpose: the certificate folder of certs.<domain>, which fabric no longer serves or issues (0.7.0, 1.5.1.5),
             when it is still there (an install from before 0.7.0): run deletes it.
    Inputs:  ctx — SetupContext: vars domain, path(); targets — _targets(ctx), so a folder still in use is kept (a
             landing_page_cname of "certs": the landing certificate's folder is named after hostname_landing).
    Returns: the folder <deploy_base>/nginx/certs/certs.<domain> (str), or None when it is gone or still in use.
    Fails:   never.
    Feeds:   run."""
    name = f"certs.{ctx.vars.get('domain', '')}".lower()
    old = ctx.path("nginx", "certs", name)
    if old in {d for _, _, dests, *_ in targets for d, _ in dests} or not os.path.isdir(old):
        return None
    return old


def run(ctx):
    """Purpose: issue (or renew) every service certificate from Step-CA and the CA bundles that verify client
             certificates, then the extra_certs.
    Inputs:  ctx — SetupContext: vars (see _targets; cert_renew_after_days, cert_service_days; install_webui,
             install_freeradius for the bundles),
             force_certs (re-issue even when current), Step-CA certs under <deploy_base>/stepca/data/certs.
    Returns: None. Certificates that exist, cover their names, chain to this CA, are younger than
             cert_renew_after_days and live no longer than cert_service_days (manual 2.1.5.4, 2.1.5.7) are left
             alone unless force_certs, unless one of their destinations has no copy yet, or unless they name another
             CRL point than fabric's current one (_crl_moved, 1.5.1.6). The landing page's certificate is also
             issued again at once when its names differ from landing_names in any way, and the one it replaces is
             revoked (superseded; a refusal reported loudly, the new one kept: _revoke_replaced, 2.1.4.8). The old
             certs.<domain> certificate, still there after an upgrade to 0.7.0, is deleted (_old_certs_host,
             1.5.1.5). The web UI client-CA bundle is rewritten on every run; the CRLs are published every run
             (publish_crl: FreeRADIUS's ca.pem with them). Services whose certificates changed are added to
             ctx.restart_services.
    Fails:   SetupError from mint_cert (step-ca refused); OSError/CalledProcessError installing files (a failed
             revocation of a replaced certificate is reported, never raised);
             ValidationError from mint_extra_certs; KeyError for missing hostname vars.
    Feeds:   setup step `certs`, run by run_setup via STEPS; renew_service_certs (`fabricctl certs`)."""
    certs_dir = ctx.path("stepca", "data", "certs")
    root_ca = os.path.join(certs_dir, "root_ca.crt")
    intermediate = os.path.join(certs_dir, "intermediate_ca.crt")
    parents = os.path.join(certs_dir, "ca_parents.crt")           # a nested site's parent CAs (else empty/absent)
    chain_cas = [intermediate] + ([parents] if os.path.exists(parents) else [])
    restart = set()
    renew_after = int(ctx.vars.get("cert_renew_after_days", 30))
    lifetime = int(ctx.vars.get("cert_service_days", 47))
    targets = _targets(ctx)
    old_certs = _old_certs_host(ctx, targets)          # the upgrade to 0.7.0

    for cn, sans, dests, services, exact in targets:
        first = dests[0][0]
        check = os.path.join(first, "server.pem" if dests[0][1] == "freeradius:eap" else "fullchain.pem")
        # a destination added since the certificate was issued (the DNS filter's, on an upgrade) needs its copy now
        missing = any(not os.path.exists(os.path.join(d, "server.pem" if u == "freeradius:eap" else "fullchain.pem"))
                      for d, u in dests)
        moved = not missing and _crl_moved(ctx, check)
        have = cert_names(check) if exact and not missing else None
        renamed = have is not None and have != {n.lower() for n in (cn, *sans)}
        if not ctx.force_certs and not missing and not moved and not renamed and not needs_renewal(
                check, [cn, *sans], (root_ca, intermediate), renew_after_days=renew_after, max_days=lifetime):
            ok(f"{cn}: current")
            continue
        replaced = _replaced_serial(check, (root_ca, intermediate)) if renamed else None
        crt, key = mint_cert(ctx, cn, sans, cn.replace(".", "-"))
        for dest, user in dests:
            if user == "freeradius:eap":
                install_cert(crt, key, root_ca, dest, *ctx.uid("freeradius"), names=("server.pem", "server.key", None))
            else:
                install_cert(crt, key, root_ca, dest, *ctx.uid(user))
        os.remove(key)
        os.remove(crt)
        restart.update(services)
        ok(f"{cn}: issued" + (" (its CRL point moved to the CA's own name, 1.5.1.6)" if moved else "")
           + (f" (its names changed: {', '.join([cn, *sans])}; 2.1.4.8)" if renamed else ""))
        if replaced:
            _revoke_replaced(ctx, replaced, cn)
    if old_certs:
        shutil.rmtree(old_certs)
        ok(f"{os.path.basename(old_certs)}: old certificate deleted (the CA is at /certs/, 1.5.1.5)")

    if ctx.vars.get("install_webui"):
        uid, gid = ctx.uid("nginx")
        bundle = ctx.path("nginx", "certs", "client-ca", "ca-bundle.pem")
        os.makedirs(os.path.dirname(bundle), mode=0o750, exist_ok=True)
        os.chown(os.path.dirname(bundle), uid, gid)
        with open(bundle, "w") as out:
            for src in (*chain_cas, root_ca):
                out.write(open(src).read())
        os.chown(bundle, uid, gid)
        os.chmod(bundle, 0o644)
        ok("web UI client-certificate CA bundle")
    if ctx.vars.get("install_freeradius"):
        os.makedirs(ctx.path("freeradius", "certs"), mode=0o750, exist_ok=True)
        os.chown(ctx.path("freeradius", "certs"), *ctx.uid("freeradius"))
    crl = publish_crl(ctx.vars)              # the CRLs, and FreeRADIUS's CA bundle with them (2.1.5.10)
    if crl["changed"]:
        restart.add("nginx")
    if crl["radius_changed"]:
        restart.add("freeradius")
        ok("FreeRADIUS CA bundle and CRLs")
    ctx.restart_services.update(restart)
    mint_extra_certs(ctx)
