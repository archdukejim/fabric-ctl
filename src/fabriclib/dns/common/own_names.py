def own_names(v):
    """Purpose: the names fabric adds to the site's zone on every render (templates/vars.yaml.j2: default_cnames,
             default_a), each with the service it is for and the setting it follows.
    Inputs:  v — the settings (vars.yaml as installed: rendered, so every key below is there on a host): domain,
             hostname, host_ip, cname_ca, cname_dns, cname_sso, cname_openbao, hostname_mgr, install_webui,
             install_keycloak, federation_endpoint, cname_federation, ntp_serve, cname_ntp. The landing page's `info`
             is not one of them since 0.7.1: added once at install, it is the admin's record (2.1.4.6).
    Returns: dict {(record type, name): (value it points to, service, setting)}.
    Fails:   never.
    Feeds:   fabric_record, drop_previous_own (an install from before 0.9.1, which kept no list of them)."""
    host, domain = str(v.get("hostname") or ""), str(v.get("domain") or "")
    cnames = [(v.get("cname_ca") or "ca", "the CA (step-ca)", "cname_ca"),
              (v.get("cname_dns") or "dns", "DNS (BIND)", "cname_dns"),
              (v.get("cname_sso") or "sso", "sign-in (Keycloak)", "cname_sso"),
              (v.get("cname_openbao") or "vault", "OpenBao", "cname_openbao")]
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
    out[("A", "@")] = (str(v.get("host_ip") or ""), "the domain itself, which serves the landing page", "host_ip")
    return out
