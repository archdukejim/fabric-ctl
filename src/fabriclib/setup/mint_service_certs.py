import os

from fabriclib.common.console import ok
from fabriclib.pki.install_cert import install_cert
from fabriclib.pki.mint_cert import mint_cert
from fabriclib.pki.needs_renewal import needs_renewal
from fabriclib.pki.publish_crl import publish_crl
from fabriclib.setup.mint_extra_certs import mint_extra_certs


def _targets(ctx):
    """Purpose: the service certificates this install needs and where each one goes.
    Inputs:  ctx — SetupContext: vars hostname_* (bind9, stepca, landing, certs, openbao, keycloak, mgr,
             radius, federation, dc), domain, install_keycloak, install_webui,
             install_freeradius, install_resolver, federation_endpoint, ad_domain.
    Returns: list of (cn, extra SANs, [(destination dir, service user or "freeradius:eap")],
             services to restart when it changes). bind9 (and the DNS filter's resolver when on), stepca, landing,
             certs and openbao always; LDAP,
             Keycloak + Postgres, web UI, FreeRADIUS (EAP-TLS server cert), the federation endpoint when on, the
             DNS filter's AdGuard Home (*.filter.<domain>) when on, and the domain controller.
    Fails:   KeyError for a missing hostname_* var.
    Feeds:   run."""
    v, p = ctx.vars, ctx.path
    nginx = lambda host: (p("nginx", "certs", host), "nginx")   # noqa: E731
    # the DNS name's certificate: DoH through nginx, and the DNS filter's own DoT and DoH listeners (1.12.2.16)
    dns_dests, dns_services = [nginx(v["hostname_bind9"]), (p("bind9", "ssl"), "bind")], ["nginx", "bind9"]
    if v.get("install_resolver"):
        dns_dests.append((p("resolver", "tls"), "resolver"))
        dns_services.append("bind9-resolver")
    t = [
        (v["hostname_bind9"], [f"ns.{v['domain']}", "127.0.0.1"], dns_dests, dns_services),
        (v["hostname_stepca"], [], [nginx(v["hostname_stepca"])], ["nginx"]),
        # the host's own name and <domain> too: they redirect to the info page over HTTPS (2.1.4.3)
        (v["hostname_landing"], [f"{v['hostname']}.{v['domain']}".lower(), v["domain"]], [nginx(v["hostname_landing"])],
         ["nginx"]),
        (v["hostname_certs"], [], [nginx(v["hostname_certs"])], ["nginx"]),
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
    return t


def run(ctx):
    """Purpose: issue (or renew) every service certificate from Step-CA and the CA bundles that verify client
             certificates, then the extra_certs.
    Inputs:  ctx — SetupContext: vars (see _targets; cert_renew_after_days, cert_service_days; install_webui,
             install_freeradius for the bundles),
             force_certs (re-issue even when current), Step-CA certs under <deploy_base>/stepca/data/certs.
    Returns: None. Certificates that exist, cover their names, chain to this CA, are younger than
             cert_renew_after_days and live no longer than cert_service_days (manual 2.1.5.4, 2.1.5.7) are left
             alone unless force_certs, or unless one of their destinations has no copy yet. The web UI client-CA
             bundle is rewritten on every run; the CRLs are published every run (publish_crl: FreeRADIUS's ca.pem
             with them). Services whose certificates changed are added to ctx.restart_services.
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

    for cn, sans, dests, services in _targets(ctx):
        first = dests[0][0]
        check = os.path.join(first, "server.pem" if dests[0][1] == "freeradius:eap" else "fullchain.pem")
        # a destination added since the certificate was issued (the DNS filter's, on an upgrade) needs its copy now
        missing = any(not os.path.exists(os.path.join(d, "server.pem" if u == "freeradius:eap" else "fullchain.pem"))
                      for d, u in dests)
        if not ctx.force_certs and not missing and not needs_renewal(check, [cn, *sans], (root_ca, intermediate),
                                                                     renew_after_days=renew_after,
                                                                     max_days=lifetime):
            ok(f"{cn}: current")
            continue
        crt, key = mint_cert(ctx, cn, sans, cn.replace(".", "-"))
        for dest, user in dests:
            if user == "freeradius:eap":
                install_cert(crt, key, root_ca, dest, *ctx.uid("freeradius"), names=("server.pem", "server.key", None))
            else:
                install_cert(crt, key, root_ca, dest, *ctx.uid(user))
        os.remove(key)
        os.remove(crt)
        restart.update(services)
        ok(f"{cn}: issued")

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
