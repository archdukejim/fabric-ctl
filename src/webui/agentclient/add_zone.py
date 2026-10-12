from webui.agentclient.connection import call_agent


def add_zone(actor, name, hide_public):
    """Purpose: Add a forward zone; BIND and the DNS filter serve it within seconds (no apply).
             Agent route: POST /v1/zones (dns:write), timeout 300 s.
    Inputs:  actor — str user name (the agent uses the token's user instead for the web UI); name — the zone's name;
             hide_public — bool, the owner ticked that a public name is hidden on purpose.
    Returns: {"key", "name", "public", "resolver"} (fabriclib.dns.add_zone).
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400: the name is
             refused, or BIND or the resolver did not take it, saying why), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/zones_post for /bind9/zones/new.
    """
    return call_agent("POST", "/v1/zones", {"actor": actor, "name": name, "hide_public": bool(hide_public)},
                      timeout=300)
