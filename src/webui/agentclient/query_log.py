from webui.agentclient.connection import call_agent


def query_log(client="", name="", blocked=False, limit=200, own=False):
    """Purpose: Search the DNS query log (who looked up what; admins only, 2.1.12.4).
             Agent route: POST /v1/dns-filter/querylog (dns:querylog).
    Inputs:  client — "" or an address or network; name — "" or a DNS name (it and every name below it); blocked —
             bool, blocked queries only; limit — 1..500; own — bool, fabric's own queries too (2.1.12.9).
    Returns: {"entries": [{at, client, view, name, qtype, action, zone, list, blocked}], "own", "own_networks"} or
             {"off": reason}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: a search term refused), AuthError (401),
             PermissionDenied (403: no dns:querylog).
    Feeds:   src/webui/routes/dns_filter_page."""
    return call_agent("POST", "/v1/dns-filter/querylog",
                      {"client": client, "name": name, "blocked": bool(blocked), "limit": limit,
                       "own": bool(own)}, timeout=120)
