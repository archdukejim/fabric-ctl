from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def remove_zone(actor, key, confirm):
    """Purpose: Remove a forward zone with its records; BIND and the DNS filter stop answering within seconds.
             Agent route: POST /v1/zones/<key>/delete (dns:write), timeout 960 s
             (an apply may run for minutes, 2.1.2.23).
    Inputs:  actor — str user name (ignored by the agent for token callers); key — the zone's key; confirm — the
             zone's name as the person typed it again.
    Returns: {"key", "name", "records"} (fabriclib.dns.remove_zone).
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400: the site's own
             zone, a name typed wrong, a key or policy naming it, or BIND or the resolver refusing, saying why),
             AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/zones_post for /bind9/zones/<key>/remove.
    """
    return call_agent("POST", f"/v1/zones/{quote_segment(key)}/delete", {"actor": actor, "confirm": confirm},
                      timeout=960)
