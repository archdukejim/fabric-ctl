from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def remove_radius_client(name):
    """Purpose: Remove a RADIUS client; saved and applied at once.
             Agent route: POST /v1/radius/clients/<name>/delete (radius:admin), timeout 960 s
             (an apply may run for minutes, 2.1.2.23).
    Inputs:  name — client name (quoted).
    Returns: {"secret": None, "applied": bool, "output": str}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403);
             ValidationError for an unknown client.
    Feeds:   src/webui/routes/radius_post (delete).
    """
    return call_agent("POST", f"/v1/radius/clients/{quote_segment(name)}/delete", {}, timeout=960)
