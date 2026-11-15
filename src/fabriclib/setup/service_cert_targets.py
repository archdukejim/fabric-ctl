import os

from fabriclib.dns.common.landing_names import landing_names


def cert_file(dest, user):
    """Purpose: the file a service certificate is read back from in one of its destinations.
    Inputs:  dest — the destination folder; user — its service user, "freeradius:eap" for FreeRADIUS' EAP-TLS one.
    Returns: <dest>/server.pem for FreeRADIUS' EAP-TLS certificate, <dest>/fullchain.pem for every other (the
             certificate first, then its chain).
    Fails:   never.
    Feeds:   setup/mint_service_certs.run, pki/list_service_certs."""
    return os.path.join(dest, "server.pem" if user == "freeradius:eap" else "fullchain.pem")


def service_cert_targets(ctx):
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
    Feeds:   setup/mint_service_certs.run, pki/list_service_certs."""
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
