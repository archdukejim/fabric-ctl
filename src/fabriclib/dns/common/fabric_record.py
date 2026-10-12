def _names(v):
    """Purpose: the names fabric adds to the site's zone on every render (templates/vars.yaml.j2: default_cnames,
             default_a), each with the service it is for and the setting it follows.
    Inputs:  v — the settings (vars.yaml as installed: rendered, so every key below is there on a host): domain,
             hostname, host_ip, cname_ca, cname_dns, cname_sso, cname_openbao, hostname_mgr, install_webui,
             install_keycloak, landing_page_cname, federation_endpoint, cname_federation, ntp_serve, cname_ntp.
    Returns: dict {(record type, name): (value it points to, service, setting)}.
    Fails:   never.
    Feeds:   fabric_record."""
    host, domain = str(v.get("hostname") or ""), str(v.get("domain") or "")
    cnames = [(v.get("cname_ca") or "ca", "the CA (step-ca)", "cname_ca"),
              (v.get("cname_dns") or "dns", "DNS (BIND)", "cname_dns"),
              (v.get("cname_sso") or "sso", "sign-in (Keycloak)", "cname_sso"),
              (v.get("cname_openbao") or "vault", "OpenBao", "cname_openbao"),
              (v.get("landing_page_cname") or "info", "the landing page", "landing_page_cname")]
    mgr = str(v.get("hostname_mgr") or "")
    label = mgr[:-len(domain) - 1] if domain and mgr.endswith("." + domain) else ""
    if v.get("install_webui", True) and v.get("install_keycloak") and label and label != host:
        cnames.append((label, "the web console", "webui_hostname"))
    if v.get("federation_endpoint"):
        cnames.append((v.get("cname_federation") or "federation", "the federation endpoint", "cname_federation"))
    if v.get("ntp_serve", True):
        cnames.append((v.get("cname_ntp") or "ntp", "time (NTP)", "cname_ntp"))
    out = {("CNAME", str(name)): (host, service, setting) for name, service, setting in cnames}
    out[("A", host)] = (str(v.get("host_ip") or ""), "this host", "hostname")
    out[("A", "@")] = (str(v.get("host_ip") or ""), "the domain itself, which redirects to the landing page", "host_ip")
    return out


def fabric_record(v, key, rtype, record):
    """Purpose: whether a record is one of fabric's own names (2.1.2.22 item 6): the site's zone gets them back from
             their settings on every render, so the DNS tab marks them "provided by fabric" and a delete is refused.
    Inputs:  v — the settings (as _names reads them); key — the zone key (only dynamic_zone_var, the site's zone,
             holds fabric's names); rtype — the record's type; record — the record dict (name, canonical or ip).
    Returns: {"service", "setting"} when the record is fabric's (its name and what it points to both match), else None.
    Fails:   never.
    Feeds:   dns/zone_detail (the pill), dns/remove_record (the refusal)."""
    if key != "dynamic_zone_var" or not isinstance(record, dict):
        return None
    hit = _names(v).get((rtype, str(record.get("name") or "")))
    value = str((record.get("canonical") if rtype == "CNAME" else record.get("ip")) or "")
    if not hit or value.rstrip(".") != hit[0]:
        return None
    return {"service": hit[1], "setting": hit[2]}
