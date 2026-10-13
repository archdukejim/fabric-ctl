def fabric_options(v, gateway=""):
    """Purpose: the options fabric provides itself at a subnet (manual 1.10.4.6.2), as the Kea template renders them:
             DNS (the settings' dhcp.dns, else fabric's address), NTP (dhcp.ntp, else fabric's address while it serves
             time), the domain, its search list (DHCP's zone first while DHCP registers names), and the subnet's
             gateway as its router.
    Inputs:  v — fabric vars (dhcp, host_ip, domain, ntp_serve); gateway — the subnet's gateway ("" none).
    Returns: list of {"name", "data"}.
    Fails:   never.
    Feeds:   networks_view (the options a subnet shows), networks_overview."""
    d = v.get("dhcp") or {}
    host = v.get("host_ip") or ""
    out = [{"name": "routers", "data": gateway}] if gateway else []
    out.append({"name": "domain-name-servers", "data": ", ".join(d.get("dns") or [host])})
    if d.get("ntp") or v.get("ntp_serve", True):
        out.append({"name": "ntp-servers", "data": ", ".join(d.get("ntp") or [host])})
    domain = d.get("domain") or v.get("domain") or ""
    out.append({"name": "domain-name", "data": domain})
    zone = f"{d.get('ddns_subdomain', 'dhcp')}.{v.get('domain', '')}" if d.get("ddns", True) else ""
    out.append({"name": "domain-search", "data": ", ".join(x for x in (zone, v.get("domain") or "") if x)})
    return out
