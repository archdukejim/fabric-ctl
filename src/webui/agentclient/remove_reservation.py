from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def remove_reservation(mac):
    """Purpose: Remove a DHCP reservation and apply at once.
             Agent route: POST /v1/dhcp/reservations/<mac>/delete (dhcp:write), timeout 960 s
             (an apply may run for minutes, 2.1.2.23).
    Inputs:  mac — str MAC of the reservation (quoted).
    Returns: {"applied": bool, "output": str last 2000 chars of apply}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403);
             ValidationError for an unknown MAC.
    Feeds:   src/webui/routes/post_action for /kea/reservations/<mac>/delete.
    """
    return call_agent("POST", f"/v1/dhcp/reservations/{quote_segment(mac)}/delete", {}, timeout=960)
