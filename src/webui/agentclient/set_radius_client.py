from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def set_radius_client(name, vendor="", transport=""):
    """Purpose: Change a RADIUS client's vendor or transport (RADIUS/UDP or RadSec); saved and applied at once.
             Agent route: POST /v1/radius/clients/<name>/set (radius:admin), timeout 960 s (an apply may run for
             minutes, 2.1.2.23).
    Inputs:  name — client name; vendor — "unifi", "cisco", "generic" or "" to keep it; transport — "udp", "radsec"
             or "" to keep it.
    Returns: {"client": {"name", "address", "message_authenticator", "vendor", "transport"}, "applied": bool,
             "output": str}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400: unknown client
             or vendor, RadSec for a vendor without it), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/radius_post (set).
    """
    return call_agent("POST", f"/v1/radius/clients/{quote_segment(name)}/set",
                      {"vendor": vendor, "transport": transport}, timeout=960)
