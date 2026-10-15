import re

from fabriclib.dns.common.fabric_record import fabric_record

LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def _fqdn(name, domain):
    """Purpose: the full name of a record name of the site's zone, as BIND reads it.
    Inputs:  name — a record's name ("@", a relative label, or an absolute name ending in "."); domain — the zone.
    Returns: the lower-case name without a trailing dot ("@" is the domain itself; a relative name gets ".<domain>").
    Fails:   never.
    Feeds:   landing_names."""
    name = str(name).strip().lower()
    if name.endswith("."):
        return name[:-1]
    return domain if name in ("@", "") else f"{name}.{domain}"


def _service_names(v, domain):
    """Purpose: the names fabric's other HTTPS services and certificates answer at: never landing names (nginx would
             see the name twice, and two certificates would name it).
    Inputs:  v — the settings (hostname_* and filter.<domain>); domain — the site's domain, lower case.
    Returns: set of lower-case full names.
    Fails:   never.
    Feeds:   landing_names."""
    keys = ("hostname_bind9", "hostname_stepca", "hostname_openbao", "hostname_keycloak", "hostname_mgr",
            "hostname_federation", "hostname_radius", "hostname_dc")
    names = {str(v.get(k) or "").strip().lower().rstrip(".") for k in keys}
    return (names | {f"ns.{domain}", f"filter.{domain}"}) - {""}


def landing_names(v):
    """Purpose: the names the landing page answers at over HTTPS, and so the names its certificate holds (decision
             2.1.4.8, manual 1.4.2.6): fabric's own (the host's own name and <domain>) and every record of the site's
             zone that points at this host and is the admin's (an A record to host_ip, or a CNAME to one of the
             host's names, through other CNAMEs too). A renamed alias is on it after the next apply; the old name is
             not, nor is a record pointing at another machine.
    Inputs:  v — the settings or a template's context (anything with .get): hostname, domain, host_ip, the
             hostname_* of fabric's services, dns.dynamic_zone_var (A and CNAME records, as vars.yaml holds them).
    Returns: list of lower-case names: the host's own name, <domain>, then the aliases sorted. Left out: wildcards,
             fabric's own records (dns/common/fabric_record: ca, dns, sso, vault, ntp, ...), the names of fabric's
             other services (each has its own certificate and nginx server), and names that are not host names.
    Fails:   never (a malformed record is skipped).
    Feeds:   common/jinja_env (the global nginx.conf.j2 renders the landing server names with),
             setup/mint_service_certs (the landing certificate's names), deploy/renew_landing_cert (the apply issues
             it again when they changed), setup/verify_install (doctor checks HTTPS on each)."""
    domain = str(v.get("domain") or "").strip().lower().rstrip(".")
    host = f"{str(v.get('hostname') or '').strip().lower()}.{domain}"
    host_ip = str(v.get("host_ip") or "").strip()
    zone = ((v.get("dns") or {}).get("dynamic_zone_var") or {}) if isinstance(v.get("dns"), dict) else {}
    records = []
    for rtype in ("A", "CNAME"):
        for r in zone.get(rtype) or []:
            if isinstance(r, dict) and str(r.get("name") or "") not in ("", "None"):
                records.append((rtype, r))
    at_host = {host} | {_fqdn(r["name"], domain) for t, r in records if t == "A" and str(r.get("ip")) == host_ip}
    changed = True
    while changed:                                      # CNAMEs to CNAMEs to the host, however deep
        changed = False
        for t, r in records:
            name = _fqdn(r["name"], domain)
            if t == "CNAME" and name not in at_host and _fqdn(r.get("canonical") or "", domain) in at_host:
                at_host.add(name)
                changed = True
    skip = _service_names(v, domain) | {host, domain}
    for t, r in records:
        if fabric_record(v, "dynamic_zone_var", t, r):
            skip.add(_fqdn(r["name"], domain))
    aliases = sorted(n for n in at_host - skip
                     if all(LABEL.match(label) for label in n.split(".")))
    return [host, domain] + aliases
