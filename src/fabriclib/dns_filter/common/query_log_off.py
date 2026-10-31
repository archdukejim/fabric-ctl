def query_log_off(v):
    """Purpose: why the DNS query log is off (manual 1.12.2.13), or None when it is on.
    Inputs:  v — rendered vars (install_resolver, install_keycloak).
    Returns: str (e.g. "the BIND resolver is off") or None.
    Fails:   never.
    Feeds:   dns_filter/ingest_dns_log, dns_filter/common/read_dnslog."""
    if not v.get("install_resolver"):
        return "the BIND resolver is off"
    if not v.get("install_keycloak"):
        return "Postgres is not installed (install_keycloak: false)"
    return None
