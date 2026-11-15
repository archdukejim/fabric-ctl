from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def tsig_choices(zone):
    """Purpose: A zone's records a TSIG key's names are picked from (ACME (DNS-01) mode and Edit names, decisions
             2.1.4.12 to 2.1.4.14). Agent route: GET /v1/tsig-choices/<zone> (dns:read).
    Inputs:  zone — str, the zone's name.
    Returns: list of {"name", "types", "address", "aliases"} (key_record_choices).
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400: not one of
             fabric's zones), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/bind9_page (views "newkey" and "key").
    """
    return call_agent("GET", f"/v1/tsig-choices/{quote_segment(zone)}")
