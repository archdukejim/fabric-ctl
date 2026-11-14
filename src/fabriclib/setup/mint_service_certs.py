import os

from fabriclib.common.console import ok
from fabriclib.pki.common.cert_names import cert_names
from fabriclib.pki.common.crl_points import crl_points
from fabriclib.pki.needs_renewal import needs_renewal
from fabriclib.pki.publish_crl import publish_crl
from fabriclib.setup.issue_service_cert import issue_service_cert
from fabriclib.setup.mint_extra_certs import mint_extra_certs
from fabriclib.setup.service_cert_targets import cert_file, service_cert_targets


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


def run(ctx):
    """Purpose: issue (or renew) every service certificate from Step-CA and the CA bundles that verify client
             certificates, then the extra_certs.
    Inputs:  ctx — SetupContext: vars (see service_cert_targets; cert_renew_after_days, cert_service_days;
             install_webui, install_freeradius for the bundles),
             force_certs (re-issue even when current), Step-CA certs under <deploy_base>/stepca/data/certs.
    Returns: None. Certificates that exist, cover their names, chain to this CA, are younger than
             cert_renew_after_days and live no longer than cert_service_days (manual 2.1.5.4, 2.1.5.7) are left
             alone unless force_certs, unless one of their destinations has no copy yet, or unless they name another
             CRL point than fabric's current one (_crl_moved, 1.5.1.6). The landing page's certificate is also
             issued again at once when its names differ from landing_names in any way; the one it replaces is not
             revoked, it expires (2.1.4.8, revised 2026-10-12). The web UI client-CA bundle is rewritten on every
             run; the CRLs are published every run
             (publish_crl: FreeRADIUS's ca.pem with them). Services whose certificates changed are added to
             ctx.restart_services.
    Fails:   SetupError from mint_cert (step-ca refused); OSError/CalledProcessError installing files;
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
    targets = service_cert_targets(ctx)

    for cn, sans, dests, services, exact in targets:
        check = cert_file(*dests[0])
        # a destination added since the certificate was issued (the DNS filter's, on an upgrade) needs its copy now
        missing = any(not os.path.exists(cert_file(d, u)) for d, u in dests)
        moved = not missing and _crl_moved(ctx, check)
        have = cert_names(check) if exact and not missing else None
        renamed = have is not None and have != {n.lower() for n in (cn, *sans)}
        if not ctx.force_certs and not missing and not moved and not renamed and not needs_renewal(
                check, [cn, *sans], (root_ca, intermediate), renew_after_days=renew_after, max_days=lifetime):
            ok(f"{cn}: current")
            continue
        issue_service_cert(ctx, cn, sans, dests)
        restart.update(services)
        ok(f"{cn}: issued" + (" (its CRL point moved to the CA's own name, 1.5.1.6)" if moved else "")
           + (f" (its names changed: {', '.join([cn, *sans])}; 2.1.4.8)" if renamed else ""))

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
